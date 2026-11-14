import os, re, secrets, hashlib, smtplib, ssl, urllib.request, json
from datetime import datetime, timedelta, timezone
from functools import wraps
from io import BytesIO
from pathlib import Path
from email.message import EmailMessage
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, flash, abort, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from PIL import Image, ImageOps
import boto3

load_dotenv()
app=Flask(__name__)
IS_PRODUCTION = os.getenv('RENDER', '').lower() == 'true' or os.getenv('APP_ENV', '').lower() == 'production'
_secret = os.getenv('SECRET_KEY', '').strip()
if IS_PRODUCTION and len(_secret) < 32:
 raise RuntimeError('Production requires SECRET_KEY with at least 32 characters.')
app.config['SECRET_KEY']=_secret or secrets.token_hex(32)
db_url=os.getenv('DATABASE_URL','sqlite:///swapcouple.db')
if db_url.startswith('postgres://'):
 db_url='postgresql+psycopg://' + db_url[len('postgres://'):]
elif db_url.startswith('postgresql://'):
 db_url='postgresql+psycopg://' + db_url[len('postgresql://'):]
app.config['SQLALCHEMY_DATABASE_URI']=db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS']=False
app.config['SQLALCHEMY_ENGINE_OPTIONS']={'pool_pre_ping': True} if db_url.startswith('postgresql') else {}
app.config['MAX_CONTENT_LENGTH']=5*1024*1024
app.config['PREFERRED_URL_SCHEME']='https' if os.getenv('PUBLIC_BASE_URL','').startswith('https://') else 'http'
app.config['SESSION_COOKIE_HTTPONLY']=True
app.config['SESSION_COOKIE_SAMESITE']='Lax'
app.config['PERMANENT_SESSION_LIFETIME']=timedelta(hours=8)
app.config['SESSION_REFRESH_EACH_REQUEST']=True
app.config['SESSION_COOKIE_SECURE']=os.getenv('PUBLIC_BASE_URL','').startswith('https://')
app.config['REMEMBER_COOKIE_SECURE']=app.config['SESSION_COOKIE_SECURE']
app.config['WTF_CSRF_TIME_LIMIT']=3600
app.config['UPLOAD_DIR']=str(Path(app.instance_path)/'private_uploads')
Path(app.config['UPLOAD_DIR']).mkdir(parents=True,exist_ok=True)
if IS_PRODUCTION:
 required_prod = ['DATABASE_URL','ADMIN_EMAIL','ADMIN_PASSWORD','SMTP_HOST','SMTP_USERNAME','SMTP_PASSWORD','SMTP_FROM','SMS_WEBHOOK_URL','SMS_WEBHOOK_TOKEN','S3_BUCKET','S3_ENDPOINT_URL','S3_ACCESS_KEY_ID','S3_SECRET_ACCESS_KEY']
 missing_prod = [key for key in required_prod if not os.getenv(key)]
 if missing_prod or len(os.getenv('ADMIN_PASSWORD','')) < 12 or not os.getenv('PUBLIC_BASE_URL','').startswith('https://') or not os.getenv('SMS_WEBHOOK_URL','').startswith('https://'):
  raise RuntimeError('Production configuration incomplete. Set all required private environment variables, use HTTPS URLs, and use an admin password of at least 12 characters. Missing: '+', '.join(missing_prod))
# Trust Render's client IP and HTTPS scheme, but never trust forwarded Host headers.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=0)

def object_store_enabled(): return bool(os.getenv('S3_BUCKET') and os.getenv('S3_ENDPOINT_URL') and os.getenv('S3_ACCESS_KEY_ID') and os.getenv('S3_SECRET_ACCESS_KEY'))
def s3_client():
 return boto3.client('s3', endpoint_url=os.getenv('S3_ENDPOINT_URL'), aws_access_key_id=os.getenv('S3_ACCESS_KEY_ID'), aws_secret_access_key=os.getenv('S3_SECRET_ACCESS_KEY'), region_name=os.getenv('S3_REGION','auto'))
def save_private_image(filename, data):
 if object_store_enabled():
  s3_client().put_object(Bucket=os.getenv('S3_BUCKET'), Key='private/'+filename, Body=data, ContentType='image/jpeg', ServerSideEncryption='AES256')
 elif IS_PRODUCTION:
  raise RuntimeError('Private object storage is mandatory in production.')
 else:
  (Path(app.config['UPLOAD_DIR'])/filename).write_bytes(data)
def read_private_image(filename):
 if object_store_enabled(): return s3_client().get_object(Bucket=os.getenv('S3_BUCKET'), Key='private/'+filename)['Body'].read()
 if IS_PRODUCTION: raise RuntimeError('Private object storage is mandatory in production.')
 return (Path(app.config['UPLOAD_DIR'])/filename).read_bytes()
def delete_private_image(filename):
 if not filename: return
 if object_store_enabled(): s3_client().delete_object(Bucket=os.getenv('S3_BUCKET'), Key='private/'+filename)
 elif not IS_PRODUCTION: (Path(app.config['UPLOAD_DIR'])/filename).unlink(missing_ok=True)

db=SQLAlchemy(app); login_manager=LoginManager(app); login_manager.login_view='login'; CSRFProtect(app)

def now(): return datetime.now(timezone.utc).replace(tzinfo=None)
class User(UserMixin,db.Model):
 id=db.Column(db.Integer,primary_key=True); name=db.Column(db.String(80),nullable=False); email=db.Column(db.String(200),unique=True,nullable=False); phone=db.Column(db.String(30),unique=True); city=db.Column(db.String(100)); birthdate=db.Column(db.Date); password_hash=db.Column(db.String(255),nullable=False); is_admin=db.Column(db.Boolean,default=False); email_ok=db.Column(db.Boolean,default=False); phone_ok=db.Column(db.Boolean,default=False); approved=db.Column(db.Boolean,default=False); blocked=db.Column(db.Boolean,default=False); selfie=db.Column(db.String(120)); photo_access=db.Column(db.Boolean,default=False); created=db.Column(db.DateTime,default=now)
class Code(db.Model):
 id=db.Column(db.Integer,primary_key=True); user_id=db.Column(db.Integer,db.ForeignKey('user.id'),nullable=False); kind=db.Column(db.String(10)); digest=db.Column(db.String(64)); expires=db.Column(db.DateTime); attempts=db.Column(db.Integer,default=0); issued=db.Column(db.DateTime,default=now)
class MessageRequest(db.Model):
 id=db.Column(db.Integer,primary_key=True); user_id=db.Column(db.Integer,db.ForeignKey('user.id'),unique=True); note=db.Column(db.String(500)); status=db.Column(db.String(20),default='pending'); created=db.Column(db.DateTime,default=now)
class Message(db.Model):
 id=db.Column(db.Integer,primary_key=True); user_id=db.Column(db.Integer,db.ForeignKey('user.id')); from_admin=db.Column(db.Boolean,default=False); body=db.Column(db.String(2000)); created=db.Column(db.DateTime,default=now)
class Meeting(db.Model):
 id=db.Column(db.Integer,primary_key=True); user_id=db.Column(db.Integer,db.ForeignKey('user.id')); when=db.Column(db.String(80)); location=db.Column(db.String(200)); note=db.Column(db.String(500)); status=db.Column(db.String(20),default='pending'); created=db.Column(db.DateTime,default=now)
class Photo(db.Model):
 id=db.Column(db.Integer,primary_key=True); filename=db.Column(db.String(120)); public=db.Column(db.Boolean,default=False)
@login_manager.user_loader
def load_user(uid): return db.session.get(User,int(uid))
@app.context_processor
def context(): return {'year':datetime.now().year}
def owner_only(fn):
 @wraps(fn)
 @login_required
 def inner(*args,**kwargs):
  if not current_user.is_admin: abort(403)
  return fn(*args,**kwargs)
 return inner
def verified(): return current_user.is_authenticated and not current_user.is_admin and not current_user.blocked and current_user.email_ok and current_user.phone_ok and current_user.approved
def require_verified(fn):
 @wraps(fn)
 @login_required
 def inner(*a,**kw):
  if not verified(): flash('पहले सत्यापन और Admin approval पूरा करें।'); return redirect(url_for('status'))
  return fn(*a,**kw)
 return inner
def mail(to,subject,body):
 host=os.getenv('SMTP_HOST'); sender=os.getenv('SMTP_FROM')
 if not host or not sender: return False
 msg=EmailMessage(); msg['From']=sender; msg['To']=to; msg['Subject']=subject; msg.set_content(body)
 try:
  with smtplib.SMTP(host,int(os.getenv('SMTP_PORT','587')),timeout=12) as s:
   s.starttls(context=ssl.create_default_context()); s.login(os.getenv('SMTP_USERNAME',''),os.getenv('SMTP_PASSWORD','')); s.send_message(msg)
  return True
 except Exception: app.logger.exception('SMTP delivery failed'); return False
def sms(phone,body):
 endpoint=os.getenv('SMS_WEBHOOK_URL'); token=os.getenv('SMS_WEBHOOK_TOKEN')
 if not endpoint or not endpoint.startswith('https://') or (IS_PRODUCTION and not token): return False
 try:
  payload=json.dumps({'to':phone,'message':body}).encode()
  req=urllib.request.Request(endpoint,data=payload,headers={'Content-Type':'application/json','Authorization':'Bearer '+(token or '')})
  with urllib.request.urlopen(req,timeout=12) as res: return 200<=res.status<300
 except Exception: app.logger.exception('SMS delivery failed'); return False
def code_digest(code):
 return hashlib.sha256((app.config['SECRET_KEY'] + ':' + code).encode()).hexdigest()

def issue_code(user,kind):
 issued_after=now()-timedelta(hours=1)
 recent_count=Code.query.filter(Code.user_id==user.id, Code.kind==kind, Code.issued>=issued_after).count()
 if recent_count>=5: return False,'एक घंटे में अधिकतम 5 verification codes भेजे जा सकते हैं।'
 latest=Code.query.filter_by(user_id=user.id,kind=kind).order_by(Code.issued.desc()).first()
 if latest and latest.issued>now()-timedelta(seconds=60): return False,'60 सेकंड बाद दोबारा कोशिश करें।'
 # Invalidate earlier codes so only the newest code can be used.
 Code.query.filter_by(user_id=user.id,kind=kind).delete(); db.session.flush()
 code=f'{secrets.randbelow(1000000):06d}'
 sent=mail(user.email,'Swap Couple verification',f'Your verification code is {code}. It expires in 10 minutes.') if kind=='email' else sms(user.phone,f'Swap Couple verification code: {code} (10 minutes).')
 if not sent: return False,'Delivery service configured नहीं है या संदेश भेजना असफल रहा।'
 db.session.add(Code(user_id=user.id,kind=kind,digest=code_digest(code),expires=now()+timedelta(minutes=10))); db.session.commit()
 return True,'Verification code भेज दिया गया है।'
@app.get('/healthz')
def healthz():
 try: db.session.execute(db.text('SELECT 1'))
 except Exception: return {'status':'unhealthy'},503
 return {'status':'ok'}

@app.route('/')
def home(): return render_template('home.html')
@app.route('/register',methods=['GET','POST'])
def register():
 if request.method=='POST':
  name=request.form.get('name','').strip()[:80]; email=request.form.get('email','').strip().lower()[:200]; phone=request.form.get('phone','').strip()[:30]; city=request.form.get('city','').strip()[:100]; password=request.form.get('password','')
  try:
   birth=datetime.strptime(request.form.get('birthdate',''),'%Y-%m-%d').date()
   today=datetime.now(timezone.utc).date()
   age=today.year-birth.year-((today.month,today.day)<(birth.month,birth.day))
  except (ValueError, TypeError): age=0; birth=None
  if not name or not city or not re.fullmatch(r'[^@\s]+@[^@\s]+\.[^@\s]+',email) or not re.fullmatch(r'\+?[0-9]{10,15}',phone) or len(password)<12 or not 18<=age<=110:
   flash('सही विवरण, 18+ उम्र और कम-से-कम 12 अक्षरों का Password दर्ज करें।')
  elif User.query.filter((User.email==email)|(User.phone==phone)).first(): flash('Email या मोबाइल पहले से पंजीकृत है।')
  else:
   u=User(name=name,email=email,phone=phone,city=city,birthdate=birth,password_hash=generate_password_hash(password)); db.session.add(u); db.session.commit(); login_user(u); flash('Account बन गया। अब Email और Mobile verify करें।'); return redirect(url_for('status'))
 return render_template('register.html')
@app.route('/login',methods=['GET','POST'])
def login():
 if request.method=='POST':
  u=User.query.filter_by(email=request.form.get('email','').strip().lower()).first()
  if u and not u.blocked and check_password_hash(u.password_hash,request.form.get('password','')):
   login_user(u); return redirect(url_for('dashboard' if u.is_admin else 'status'))
  flash('Login असफल। विवरण जाँचें।')
 return render_template('login.html')
@app.post('/logout')
@login_required
def logout(): logout_user(); return redirect(url_for('home'))
@app.route('/status')
@login_required
def status():
 if current_user.is_admin: return redirect(url_for('dashboard'))
 return render_template('status.html')
@app.post('/send-code/<kind>')
@login_required
def send_code(kind):
 if current_user.is_admin or kind not in ('email','phone'): abort(403)
 if (kind=='email' and current_user.email_ok) or (kind=='phone' and current_user.phone_ok): return redirect(url_for('status'))
 ok,msg=issue_code(current_user,kind); flash(msg); return redirect(url_for('status'))
@app.post('/verify/<kind>')
@login_required
def verify(kind):
 if current_user.is_admin or kind not in ('email','phone'): abort(403)
 code=request.form.get('code','').strip(); entry=Code.query.filter_by(user_id=current_user.id,kind=kind).order_by(Code.issued.desc()).first()
 if not re.fullmatch(r'[0-9]{6}',code) or not entry or not entry.expires or entry.expires<now() or entry.attempts>=5: flash('Code समाप्त हो गया है। नया Code मँगाएँ।')
 else:
  entry.attempts+=1
  if secrets.compare_digest(entry.digest,code_digest(code)):
   if kind=='email': current_user.email_ok=True
   else: current_user.phone_ok=True
   Code.query.filter_by(user_id=current_user.id,kind=kind).delete(); flash('Verification सफल।')
  else: flash('गलत Code।')
  db.session.commit()
 return redirect(url_for('status'))
def store_image(upload):
 if not upload or not upload.filename: raise ValueError('फोटो चुनें।')
 try:
  im=Image.open(upload.stream); im.verify(); upload.stream.seek(0); im=Image.open(upload.stream); im=ImageOps.exif_transpose(im).convert('RGB'); im.thumbnail((1400,1400)); filename=secrets.token_hex(20)+'.jpg'; out=BytesIO(); im.save(out,'JPEG',quality=85); save_private_image(filename,out.getvalue()); return filename
 except Exception: raise ValueError('सही JPG/PNG फोटो अपलोड करें (अधिकतम 5 MB)।')
@app.post('/selfie')
@login_required
def selfie():
 if current_user.is_admin or not (current_user.email_ok and current_user.phone_ok): abort(403)
 try: filename=store_image(request.files.get('selfie'))
 except ValueError as e: flash(str(e)); return redirect(url_for('status'))
 if current_user.selfie: delete_private_image(current_user.selfie)
 current_user.selfie=filename; current_user.approved=False; db.session.commit(); flash('Selfie समीक्षा के लिए भेज दी गई है।'); return redirect(url_for('status'))
@app.route('/profile')
@require_verified
def profile(): return render_template('profile.html',photos=Photo.query.order_by(Photo.id).all())
@app.route('/photo/<int:photo_id>')
@require_verified
def photo(photo_id):
 p=db.get_or_404(Photo,photo_id)
 if not (p.public or current_user.photo_access): abort(403)
 return send_file(BytesIO(read_private_image(p.filename)),mimetype='image/jpeg',download_name='photo.jpg')
@app.post('/request-message')
@require_verified
def request_message():
 r=MessageRequest.query.filter_by(user_id=current_user.id).first()
 if not r: db.session.add(MessageRequest(user_id=current_user.id,note=request.form.get('note','').strip()[:500])); db.session.commit(); flash('Message Request भेज दी गई है।')
 else: flash('आपकी Request पहले से मौजूद है।')
 return redirect(url_for('profile'))
def chat_allowed(uid):
 r=MessageRequest.query.filter_by(user_id=uid).first(); return r and r.status=='accepted'
@app.route('/chat',methods=['GET','POST'])
@require_verified
def chat():
 if not chat_allowed(current_user.id): flash('पहले Message Request स्वीकार होना जरूरी है।'); return redirect(url_for('profile'))
 if request.method=='POST':
  body=request.form.get('body','').strip()[:2000]
  if body: db.session.add(Message(user_id=current_user.id,body=body)); db.session.commit()
  return redirect(url_for('chat'))
 return render_template('chat.html',messages=Message.query.filter_by(user_id=current_user.id).order_by(Message.created).all(),meetings=Meeting.query.filter_by(user_id=current_user.id).order_by(Meeting.created.desc()).all())
@app.post('/meeting')
@require_verified
def meeting():
 if not chat_allowed(current_user.id): abort(403)
 when=request.form.get('when','').strip()[:80]; location=request.form.get('location','').strip()[:200]
 if not when or not location: flash('तारीख और सार्वजनिक स्थान जरूरी हैं।')
 else: db.session.add(Meeting(user_id=current_user.id,when=when,location=location,note=request.form.get('note','').strip()[:500])); db.session.commit(); flash('Meeting Request भेज दी गई है।')
 return redirect(url_for('chat'))
@app.route('/admin')
@owner_only
def dashboard(): return render_template('admin.html',users=User.query.filter_by(is_admin=False).order_by(User.created.desc()).all(),requests=MessageRequest.query.order_by(MessageRequest.created.desc()).all(),meetings=Meeting.query.order_by(Meeting.created.desc()).all(),photos=Photo.query.all())
@app.route('/admin/selfie/<int:uid>')
@owner_only
def admin_selfie(uid):
 u=db.get_or_404(User,uid)
 if not u.selfie: abort(404)
 return send_file(BytesIO(read_private_image(u.selfie)),mimetype='image/jpeg',download_name='selfie.jpg')
@app.post('/admin/user/<int:uid>/<action>')
@owner_only
def admin_user(uid,action):
 u=db.get_or_404(User,uid)
 if u.is_admin: abort(403)
 if action=='approve' and u.email_ok and u.phone_ok and u.selfie and not u.blocked: u.approved=True
 elif action=='reject': u.approved=False
 elif action=='block': u.blocked=True; u.approved=False
 elif action=='unblock': u.blocked=False
 elif action=='photos': u.photo_access=not u.photo_access
 elif action=='delete-selfie' and u.selfie: delete_private_image(u.selfie); u.selfie=None
 else: abort(400)
 db.session.commit(); return redirect(url_for('dashboard'))
@app.post('/admin/request/<int:rid>/<action>')
@owner_only
def admin_request(rid,action):
 r=db.get_or_404(MessageRequest,rid)
 if action not in ('accepted','rejected'): abort(400)
 u=db.session.get(User,r.user_id)
 if action=='accepted' and (not u or u.blocked or not (u.email_ok and u.phone_ok and u.approved)): abort(403)
 r.status=action; db.session.commit(); return redirect(url_for('dashboard'))
@app.route('/admin/chat/<int:uid>',methods=['GET','POST'])
@owner_only
def admin_chat(uid):
 u=db.get_or_404(User,uid)
 if u.is_admin or u.blocked or not u.approved or not chat_allowed(uid): abort(403)
 if request.method=='POST':
  body=request.form.get('body','').strip()[:2000]
  if body: db.session.add(Message(user_id=uid,from_admin=True,body=body)); db.session.commit()
  return redirect(url_for('admin_chat',uid=uid))
 return render_template('chat.html',messages=Message.query.filter_by(user_id=uid).order_by(Message.created).all(),admin_chat=True,other=u)
@app.post('/admin/meeting/<int:mid>/<action>')
@owner_only
def admin_meeting(mid,action):
 m=db.get_or_404(Meeting,mid)
 if action not in ('accepted','rejected','reschedule'): abort(400)
 m.status=action
 if action=='reschedule': m.when=request.form.get('when','').strip()[:80] or m.when
 db.session.commit(); return redirect(url_for('dashboard'))
@app.post('/admin/photo')
@owner_only
def admin_photo():
 try: filename=store_image(request.files.get('photo'))
 except ValueError as e: flash(str(e)); return redirect(url_for('dashboard'))
 db.session.add(Photo(filename=filename,public=request.form.get('public')=='yes')); db.session.commit(); return redirect(url_for('dashboard'))
@app.post('/admin/photo/<int:pid>/delete')
@owner_only
def delete_photo(pid):
 p=db.get_or_404(Photo,pid); delete_private_image(p.filename); db.session.delete(p); db.session.commit(); return redirect(url_for('dashboard'))
@app.route('/privacy')
def privacy(): return render_template('privacy.html')
@app.after_request
def headers(response):
 response.headers['X-Content-Type-Options']='nosniff'; response.headers['Permissions-Policy']='camera=(), microphone=(), geolocation=()'; response.headers['X-Frame-Options']='DENY'; response.headers['Referrer-Policy']='strict-origin-when-cross-origin'; response.headers['Cache-Control']='no-store' if current_user.is_authenticated else 'no-cache'; response.headers['Content-Security-Policy']="default-src 'self'; img-src 'self' data:; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'self'"
 return response
with app.app_context():
 db.create_all()
 admin_email=os.getenv('ADMIN_EMAIL','').strip().lower(); admin_pass=os.getenv('ADMIN_PASSWORD','')
 if admin_email and len(admin_pass)>=12 and not User.query.filter_by(email=admin_email).first():
  db.session.add(User(name='Swap Couple',email=admin_email,password_hash=generate_password_hash(admin_pass),is_admin=True,approved=True,email_ok=True,phone_ok=True)); db.session.commit()
if __name__=='__main__': app.run(host='127.0.0.1', port=int(os.getenv('PORT','5000')), debug=False)
