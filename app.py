import os, re, secrets, hashlib, smtplib, ssl, urllib.request, json, logging
from datetime import datetime, timedelta, timezone
from functools import wraps
from io import BytesIO
from pathlib import Path
from email.message import EmailMessage

import boto3
from dotenv import load_dotenv
from PIL import Image, ImageOps, UnidentifiedImageError
from flask import Flask, render_template, request, redirect, url_for, flash, abort, send_file, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from sqlalchemy import or_, Index

load_dotenv()
app = Flask(__name__)
IS_PRODUCTION = os.getenv("RENDER", "").lower() == "true" or os.getenv("APP_ENV", "").lower() == "production"
_secret = os.getenv("SECRET_KEY", "").strip()
if IS_PRODUCTION and len(_secret) < 32:
    raise RuntimeError("Production requires SECRET_KEY with at least 32 characters.")

public_url = os.getenv("PUBLIC_BASE_URL", "").strip()
db_url = os.getenv("DATABASE_URL", "sqlite:///swapcouple.db").strip()
if db_url.startswith("postgres://"):
    db_url = "postgresql+psycopg://" + db_url[len("postgres://"):]
elif db_url.startswith("postgresql://"):
    db_url = "postgresql+psycopg://" + db_url[len("postgresql://"):]

app.config.update(
    SECRET_KEY=_secret or secrets.token_hex(32),
    SQLALCHEMY_DATABASE_URI=db_url,
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    SQLALCHEMY_ENGINE_OPTIONS={"pool_pre_ping": True} if db_url.startswith("postgresql") else {},
    MAX_CONTENT_LENGTH=5 * 1024 * 1024,
    PREFERRED_URL_SCHEME="https" if public_url.startswith("https://") else "http",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=public_url.startswith("https://"),
    REMEMBER_COOKIE_SECURE=public_url.startswith("https://"),
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
    SESSION_REFRESH_EACH_REQUEST=True,
    WTF_CSRF_TIME_LIMIT=3600,
    UPLOAD_DIR=str(Path(app.instance_path) / "private_uploads"),
)
Path(app.config["UPLOAD_DIR"]).mkdir(parents=True, exist_ok=True)

if IS_PRODUCTION:
    required = ["DATABASE_URL", "ADMIN_EMAIL", "ADMIN_PASSWORD", "SMTP_HOST", "SMTP_USERNAME",
                "SMTP_PASSWORD", "SMTP_FROM", "SMS_WEBHOOK_URL", "SMS_WEBHOOK_TOKEN",
                "S3_BUCKET", "S3_ENDPOINT_URL", "S3_ACCESS_KEY_ID", "S3_SECRET_ACCESS_KEY"]
    missing = [k for k in required if not os.getenv(k)]
    if (missing or len(os.getenv("ADMIN_PASSWORD", "")) < 12 or
        not public_url.startswith("https://") or
        not os.getenv("SMS_WEBHOOK_URL", "").startswith("https://")):
        raise RuntimeError("Production configuration incomplete. Missing: " + ", ".join(missing))

# Trust one Render proxy hop only; do not trust forwarded Host headers.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=0)
db = SQLAlchemy(app)
migrate = Migrate(app, db, compare_type=True)
login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message = "कृपया पहले Login करें।"
CSRFProtect(app)
logging.basicConfig(level=logging.INFO)


def now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def client_ip():
    return (request.remote_addr or "unknown")[:64]


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(200), unique=True, nullable=False, index=True)
    phone = db.Column(db.String(30), unique=True, index=True)
    city = db.Column(db.String(100))
    birthdate = db.Column(db.Date)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    email_ok = db.Column(db.Boolean, default=False, nullable=False)
    phone_ok = db.Column(db.Boolean, default=False, nullable=False)
    approved = db.Column(db.Boolean, default=False, nullable=False)
    blocked = db.Column(db.Boolean, default=False, nullable=False)
    selfie = db.Column(db.String(120))
    photo_access = db.Column(db.Boolean, default=False, nullable=False)
    created = db.Column(db.DateTime, default=now, nullable=False)


class Code(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    kind = db.Column(db.String(10), nullable=False)
    digest = db.Column(db.String(64), nullable=False)
    expires = db.Column(db.DateTime, nullable=False)
    attempts = db.Column(db.Integer, default=0, nullable=False)
    issued = db.Column(db.DateTime, default=now, nullable=False)


class RateEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    subject = db.Column(db.String(220), nullable=False, index=True)
    action = db.Column(db.String(40), nullable=False, index=True)
    created = db.Column(db.DateTime, default=now, nullable=False, index=True)


class LoginAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    identity = db.Column(db.String(220), nullable=False, index=True)
    ip = db.Column(db.String(64), nullable=False, index=True)
    succeeded = db.Column(db.Boolean, nullable=False, default=False)
    created = db.Column(db.DateTime, nullable=False, default=now, index=True)


class AdminAudit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    admin_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    target_user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    action = db.Column(db.String(60), nullable=False)
    details = db.Column(db.String(500))
    ip = db.Column(db.String(64))
    created = db.Column(db.DateTime, default=now, nullable=False, index=True)


class MessageRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), unique=True, nullable=False)
    note = db.Column(db.String(500))
    status = db.Column(db.String(20), default="pending", nullable=False)
    created = db.Column(db.DateTime, default=now, nullable=False)


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    from_admin = db.Column(db.Boolean, default=False, nullable=False)
    body = db.Column(db.String(2000), nullable=False)
    created = db.Column(db.DateTime, default=now, nullable=False)


class Meeting(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    when = db.Column(db.String(80), nullable=False)
    location = db.Column(db.String(200), nullable=False)
    note = db.Column(db.String(500))
    status = db.Column(db.String(20), default="pending", nullable=False)
    created = db.Column(db.DateTime, default=now, nullable=False)


class Photo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(120), nullable=False, unique=True)
    public = db.Column(db.Boolean, default=False, nullable=False)


Index("ix_rate_subject_action_created", RateEvent.subject, RateEvent.action, RateEvent.created)
Index("ix_login_identity_ip_created", LoginAttempt.identity, LoginAttempt.ip, LoginAttempt.created)


@login_manager.user_loader
def load_user(uid):
    try:
        return db.session.get(User, int(uid))
    except (TypeError, ValueError):
        return None


@app.context_processor
def context():
    return {"year": datetime.now().year}


def owner_only(fn):
    @wraps(fn)
    @login_required
    def inner(*args, **kwargs):
        if not current_user.is_admin or current_user.blocked:
            abort(403)
        return fn(*args, **kwargs)
    return inner


def verified():
    return (current_user.is_authenticated and not current_user.is_admin and not current_user.blocked
            and current_user.email_ok and current_user.phone_ok and current_user.approved)


def require_verified(fn):
    @wraps(fn)
    @login_required
    def inner(*args, **kwargs):
        if not verified():
            flash("पहले Email, Mobile verification और Admin approval पूरा करें।", "warning")
            return redirect(url_for("status"))
        return fn(*args, **kwargs)
    return inner


def audit(action, target_user_id=None, details=""):
    if current_user.is_authenticated and current_user.is_admin:
        db.session.add(AdminAudit(admin_id=current_user.id, target_user_id=target_user_id,
                                  action=action[:60], details=details[:500], ip=client_ip()))


def object_store_enabled():
    return all(os.getenv(k) for k in ("S3_BUCKET", "S3_ENDPOINT_URL", "S3_ACCESS_KEY_ID", "S3_SECRET_ACCESS_KEY"))


def s3_client():
    return boto3.client("s3", endpoint_url=os.getenv("S3_ENDPOINT_URL"),
        aws_access_key_id=os.getenv("S3_ACCESS_KEY_ID"),
        aws_secret_access_key=os.getenv("S3_SECRET_ACCESS_KEY"),
        region_name=os.getenv("S3_REGION", "auto"))


def save_private_image(filename, data):
    if object_store_enabled():
        s3_client().put_object(Bucket=os.getenv("S3_BUCKET"), Key="private/" + filename,
            Body=data, ContentType="image/jpeg", ServerSideEncryption="AES256")
    elif IS_PRODUCTION:
        raise RuntimeError("Private object storage is mandatory in production.")
    else:
        (Path(app.config["UPLOAD_DIR"]) / filename).write_bytes(data)


def read_private_image(filename):
    if object_store_enabled():
        return s3_client().get_object(Bucket=os.getenv("S3_BUCKET"), Key="private/" + filename)["Body"].read()
    if IS_PRODUCTION:
        raise RuntimeError("Private object storage is mandatory in production.")
    path = Path(app.config["UPLOAD_DIR"]) / filename
    if not path.is_file():
        abort(404)
    return path.read_bytes()


def delete_private_image(filename):
    if not filename:
        return
    if object_store_enabled():
        s3_client().delete_object(Bucket=os.getenv("S3_BUCKET"), Key="private/" + filename)
    elif not IS_PRODUCTION:
        (Path(app.config["UPLOAD_DIR"]) / filename).unlink(missing_ok=True)


def rate_limited(subject, action, limit, seconds):
    cutoff = now() - timedelta(seconds=seconds)
    return RateEvent.query.filter(RateEvent.subject == subject,
        RateEvent.action == action, RateEvent.created >= cutoff).count() >= limit


def record_event(subject, action):
    db.session.add(RateEvent(subject=subject[:220], action=action[:40]))
    db.session.commit()


def mail(to, subject, body):
    if not os.getenv("SMTP_HOST") or not os.getenv("SMTP_FROM"):
        return False
    message = EmailMessage()
    message["From"], message["To"], message["Subject"] = os.getenv("SMTP_FROM"), to, subject
    message.set_content(body)
    try:
        with smtplib.SMTP(os.getenv("SMTP_HOST"), int(os.getenv("SMTP_PORT", "587")), timeout=12) as smtp:
            smtp.starttls(context=ssl.create_default_context())
            smtp.login(os.getenv("SMTP_USERNAME", ""), os.getenv("SMTP_PASSWORD", ""))
            smtp.send_message(message)
        return True
    except Exception:
        app.logger.exception("SMTP delivery failed")
        return False


def sms(phone, body):
    endpoint, token = os.getenv("SMS_WEBHOOK_URL", ""), os.getenv("SMS_WEBHOOK_TOKEN", "")
    if not endpoint.startswith("https://") or (IS_PRODUCTION and not token):
        return False
    try:
        payload = json.dumps({"to": phone, "message": body}).encode()
        req = urllib.request.Request(endpoint, data=payload,
            headers={"Content-Type": "application/json", "Authorization": "Bearer " + token},
            method="POST")
        with urllib.request.urlopen(req, timeout=12) as response:
            return 200 <= response.status < 300
    except Exception:
        app.logger.exception("SMS delivery failed")
        return False


def code_digest(code):
    return hashlib.sha256((app.config["SECRET_KEY"] + ":" + code).encode()).hexdigest()


def issue_code(user, kind):
    subject = f"user:{user.id}"
    if rate_limited(subject, f"otp:{kind}", 5, 3600):
        return False, "एक घंटे में अधिकतम 5 verification codes भेजे जा सकते हैं।"
    if rate_limited(subject, f"otp-wait:{kind}", 1, 60):
        return False, "60 सेकंड बाद दोबारा कोशिश करें।"
    # Persist rate-limit events independently from the OTP record.
    record_event(subject, f"otp:{kind}")
    record_event(subject, f"otp-wait:{kind}")
    Code.query.filter_by(user_id=user.id, kind=kind).delete(synchronize_session=False)
    code = f"{secrets.randbelow(1000000):06d}"
    delivered = (mail(user.email, "Swap Couple verification",
        f"Your verification code is {code}. It expires in 10 minutes.")
        if kind == "email" else sms(user.phone, f"Swap Couple verification code: {code} (10 minutes)."))
    if not delivered:
        return False, "Verification message भेजना असफल रहा। कुछ देर बाद कोशिश करें।"
    db.session.add(Code(user_id=user.id, kind=kind, digest=code_digest(code),
                        expires=now() + timedelta(minutes=10)))
    db.session.commit()
    return True, "Verification code भेज दिया गया है।"


def store_image(upload):
    if not upload or not upload.filename:
        raise ValueError("फोटो चुनें।")
    try:
        upload.stream.seek(0)
        image = Image.open(upload.stream)
        if image.format not in ("JPEG", "PNG", "WEBP"):
            raise ValueError("केवल JPG, PNG या WEBP फोटो स्वीकार हैं।")
        if not (100 <= image.width <= 8000 and 100 <= image.height <= 8000):
            raise ValueError("फोटो के dimensions मान्य सीमा में नहीं हैं।")
        image.verify()
        upload.stream.seek(0)
        image = ImageOps.exif_transpose(Image.open(upload.stream)).convert("RGB")
        image.thumbnail((1400, 1400))
        filename, output = secrets.token_hex(20) + ".jpg", BytesIO()
        image.save(output, "JPEG", quality=85, optimize=True)
        save_private_image(filename, output.getvalue())
        return filename
    except (UnidentifiedImageError, OSError) as exc:
        raise ValueError("सही JPG/PNG/WEBP फोटो अपलोड करें (अधिकतम 5 MB)।") from exc


@app.get("/healthz")
def healthz():
    try:
        db.session.execute(db.text("SELECT 1"))
        return jsonify(status="ok"), 200
    except Exception:
        db.session.rollback()
        app.logger.exception("Health check failed")
        return jsonify(status="unhealthy"), 503


@app.route("/")
def home():
    return render_template("home.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        ip = client_ip()
        if rate_limited(ip, "register", 5, 3600):
            flash("बहुत अधिक registration प्रयास हुए हैं। बाद में कोशिश करें।", "warning")
            return render_template("register.html"), 429
        name = request.form.get("name", "").strip()[:80]
        email = request.form.get("email", "").strip().lower()[:200]
        phone = request.form.get("phone", "").strip()[:30]
        city = request.form.get("city", "").strip()[:100]
        password = request.form.get("password", "")
        try:
            birth = datetime.strptime(request.form.get("birthdate", ""), "%Y-%m-%d").date()
            today = datetime.now(timezone.utc).date()
            age = today.year - birth.year - ((today.month, today.day) < (birth.month, birth.day))
        except (ValueError, TypeError):
            age, birth = 0, None
        if (not name or not city or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email)
            or not re.fullmatch(r"\+?[0-9]{10,15}", phone) or len(password) < 12 or not 18 <= age <= 110):
            flash("सही विवरण, 18+ उम्र और कम-से-कम 12 अक्षरों का Password दर्ज करें।", "warning")
        elif User.query.filter(or_(User.email == email, User.phone == phone)).first():
            flash("Email या मोबाइल पहले से पंजीकृत है।", "warning")
        else:
            record_event(ip, "register")
            user = User(name=name, email=email, phone=phone, city=city, birthdate=birth,
                        password_hash=generate_password_hash(password))
            db.session.add(user)
            db.session.commit()
            login_user(user)
            session.permanent = True
            flash("Account बन गया। अब Email और Mobile verify करें।", "success")
            return redirect(url_for("status"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()[:200]
        password, ip = request.form.get("password", ""), client_ip()
        cutoff = now() - timedelta(minutes=15)
        failures = LoginAttempt.query.filter(LoginAttempt.identity == email,
            LoginAttempt.ip == ip, LoginAttempt.succeeded.is_(False),
            LoginAttempt.created >= cutoff).count()
        if failures >= 5 or rate_limited(ip, "login", 20, 900):
            flash("बहुत अधिक Login प्रयास हुए हैं। 15 मिनट बाद कोशिश करें।", "warning")
            return render_template("login.html"), 429
        user = User.query.filter_by(email=email).first()
        success = bool(user and not user.blocked and check_password_hash(user.password_hash, password))
        db.session.add(LoginAttempt(identity=email or "unknown", ip=ip, succeeded=success))
        db.session.add(RateEvent(subject=ip, action="login"))
        db.session.commit()
        if success:
            login_user(user)
            session.permanent = True
            return redirect(url_for("dashboard" if user.is_admin else "status"))
        flash("Login असफल। विवरण जाँचें।", "warning")
    return render_template("login.html")


@app.post("/logout")
@login_required
def logout():
    logout_user()
    session.clear()
    return redirect(url_for("home"))


@app.route("/status")
@login_required
def status():
    if current_user.is_admin:
        return redirect(url_for("dashboard"))
    return render_template("status.html")


@app.post("/send-code/<kind>")
@login_required
def send_code(kind):
    if current_user.is_admin or current_user.blocked or kind not in ("email", "phone"):
        abort(403)
    if (kind == "email" and current_user.email_ok) or (kind == "phone" and current_user.phone_ok):
        return redirect(url_for("status"))
    ok, message = issue_code(current_user, kind)
    flash(message, "success" if ok else "warning")
    return redirect(url_for("status"))


@app.post("/verify/<kind>")
@login_required
def verify(kind):
    if current_user.is_admin or current_user.blocked or kind not in ("email", "phone"):
        abort(403)
    code = request.form.get("code", "").strip()
    entry = Code.query.filter_by(user_id=current_user.id, kind=kind).order_by(Code.issued.desc()).first()
    if (not re.fullmatch(r"[0-9]{6}", code) or not entry or entry.expires < now()
        or entry.attempts >= 5):
        flash("Code समाप्त या अमान्य है। नया Code मँगाएँ।", "warning")
    else:
        entry.attempts += 1
        if secrets.compare_digest(entry.digest, code_digest(code)):
            if kind == "email":
                current_user.email_ok = True
            else:
                current_user.phone_ok = True
            Code.query.filter_by(user_id=current_user.id, kind=kind).delete(synchronize_session=False)
            flash("Verification सफल।", "success")
        else:
            flash("गलत Code।", "warning")
        db.session.commit()
    return redirect(url_for("status"))


@app.post("/selfie")
@login_required
def selfie():
    if current_user.is_admin or current_user.blocked or not (current_user.email_ok and current_user.phone_ok):
        abort(403)
    try:
        filename = store_image(request.files.get("selfie"))
    except ValueError as exc:
        flash(str(exc), "warning")
        return redirect(url_for("status"))
    old = current_user.selfie
    current_user.selfie, current_user.approved = filename, False
    db.session.commit()
    if old:
        try:
            delete_private_image(old)
        except Exception:
            app.logger.exception("Old selfie cleanup failed")
    flash("Selfie समीक्षा के लिए भेज दी गई है।", "success")
    return redirect(url_for("status"))


@app.route("/profile")
@require_verified
def profile():
    return render_template("profile.html", photos=Photo.query.order_by(Photo.id).all())


@app.route("/photo/<int:photo_id>")
@require_verified
def photo(photo_id):
    item = db.get_or_404(Photo, photo_id)
    if not (item.public or current_user.photo_access):
        abort(403)
    return send_file(BytesIO(read_private_image(item.filename)), mimetype="image/jpeg",
                     download_name="photo.jpg", max_age=0)


@app.post("/request-message")
@require_verified
def request_message():
    if not MessageRequest.query.filter_by(user_id=current_user.id).first():
        db.session.add(MessageRequest(user_id=current_user.id,
            note=request.form.get("note", "").strip()[:500]))
        db.session.commit()
        flash("Message Request भेज दी गई है।", "success")
    else:
        flash("आपकी Request पहले से मौजूद है।", "info")
    return redirect(url_for("profile"))


def chat_allowed(uid):
    item = MessageRequest.query.filter_by(user_id=uid).first()
    return bool(item and item.status == "accepted")


@app.route("/chat", methods=["GET", "POST"])
@require_verified
def chat():
    if not chat_allowed(current_user.id):
        flash("पहले Message Request स्वीकार होना जरूरी है।", "warning")
        return redirect(url_for("profile"))
    if request.method == "POST":
        body = request.form.get("body", "").strip()
        if body and len(body) <= 2000:
            db.session.add(Message(user_id=current_user.id, from_admin=False, body=body))
            db.session.commit()
        else:
            flash("Message 1 से 2000 अक्षरों के बीच होना चाहिए।", "warning")
        return redirect(url_for("chat"))
    return render_template("chat.html",
        messages=Message.query.filter_by(user_id=current_user.id).order_by(Message.created).all(),
        meetings=Meeting.query.filter_by(user_id=current_user.id).order_by(Meeting.created.desc()).all())


@app.post("/meeting")
@require_verified
def meeting():
    if not chat_allowed(current_user.id):
        abort(403)
    when = request.form.get("when", "").strip()[:80]
    location = request.form.get("location", "").strip()[:200]
    if not when or not location:
        flash("तारीख और सार्वजनिक स्थान जरूरी हैं।", "warning")
    else:
        db.session.add(Meeting(user_id=current_user.id, when=when, location=location,
            note=request.form.get("note", "").strip()[:500]))
        db.session.commit()
        flash("Meeting Request भेज दी गई है।", "success")
    return redirect(url_for("chat"))


@app.route("/admin")
@owner_only
def dashboard():
    return render_template("admin.html",
        users=User.query.filter_by(is_admin=False).order_by(User.created.desc()).all(),
        requests=MessageRequest.query.order_by(MessageRequest.created.desc()).all(),
        meetings=Meeting.query.order_by(Meeting.created.desc()).all(),
        photos=Photo.query.order_by(Photo.id).all())


@app.route("/admin/selfie/<int:uid>")
@owner_only
def admin_selfie(uid):
    user = db.get_or_404(User, uid)
    if not user.selfie:
        abort(404)
    return send_file(BytesIO(read_private_image(user.selfie)), mimetype="image/jpeg",
                     download_name="selfie.jpg", max_age=0)


@app.post("/admin/user/<int:uid>/<action>")
@owner_only
def admin_user(uid, action):
    user = db.get_or_404(User, uid)
    if user.is_admin:
        abort(403)
    details = ""
    if action == "approve" and user.email_ok and user.phone_ok and user.selfie and not user.blocked:
        user.approved, details = True, "Visitor approved"
    elif action == "reject":
        user.approved, details = False, "Visitor approval rejected"
    elif action == "block":
        user.blocked, user.approved, details = True, False, "Visitor blocked"
    elif action == "unblock":
        user.blocked, details = False, "Visitor unblocked; approval unchanged"
    elif action == "photos":
        user.photo_access = not user.photo_access
        details = f"Photo access set to {user.photo_access}"
    elif action == "delete-selfie" and user.selfie:
        old = user.selfie
        user.selfie, details = None, "Selfie deleted"
        audit(action, user.id, details)
        db.session.commit()
        try:
            delete_private_image(old)
        except Exception:
            app.logger.exception("Selfie cleanup failed")
        return redirect(url_for("dashboard"))
    else:
        abort(400)
    audit(action, user.id, details)
    db.session.commit()
    return redirect(url_for("dashboard"))


@app.post("/admin/request/<int:rid>/<action>")
@owner_only
def admin_request(rid, action):
    item = db.get_or_404(MessageRequest, rid)
    if action not in ("accepted", "rejected"):
        abort(400)
    user = db.session.get(User, item.user_id)
    if action == "accepted" and (not user or user.blocked or not user.approved
        or not user.email_ok or not user.phone_ok):
        abort(403)
    item.status = action
    audit("message_request_" + action, user.id if user else None, f"Request ID {rid}")
    db.session.commit()
    return redirect(url_for("dashboard"))


@app.route("/admin/chat/<int:uid>", methods=["GET", "POST"])
@owner_only
def admin_chat(uid):
    user = db.get_or_404(User, uid)
    if user.is_admin or user.blocked or not user.approved or not chat_allowed(uid):
        abort(403)
    if request.method == "POST":
        body = request.form.get("body", "").strip()
        if body and len(body) <= 2000:
            db.session.add(Message(user_id=uid, from_admin=True, body=body))
            db.session.commit()
        else:
            flash("Message 1 से 2000 अक्षरों के बीच होना चाहिए।", "warning")
        return redirect(url_for("admin_chat", uid=uid))
    return render_template("chat.html",
        messages=Message.query.filter_by(user_id=uid).order_by(Message.created).all(),
        admin_chat=True, other=user)


@app.post("/admin/meeting/<int:mid>/<action>")
@owner_only
def admin_meeting(mid, action):
    item = db.get_or_404(Meeting, mid)
    if action not in ("accepted", "rejected", "reschedule"):
        abort(400)
    if action == "reschedule":
        when = request.form.get("when", "").strip()
        if not when:
            flash("नई तारीख और समय दर्ज करें।", "warning")
            return redirect(url_for("dashboard"))
        item.when = when[:80]
    item.status = action
    audit("meeting_" + action, item.user_id, f"Meeting ID {mid}")
    db.session.commit()
    return redirect(url_for("dashboard"))


@app.post("/admin/photo")
@owner_only
def admin_photo():
    try:
        filename = store_image(request.files.get("photo"))
    except ValueError as exc:
        flash(str(exc), "warning")
        return redirect(url_for("dashboard"))
    item = Photo(filename=filename, public=request.form.get("public") == "yes")
    db.session.add(item)
    audit("photo_uploaded", None, f"public={item.public}")
    db.session.commit()
    return redirect(url_for("dashboard"))


@app.post("/admin/photo/<int:pid>/delete")
@owner_only
def delete_photo(pid):
    item = db.get_or_404(Photo, pid)
    filename = item.filename
    db.session.delete(item)
    audit("photo_deleted", None, f"Photo ID {pid}")
    db.session.commit()
    try:
        delete_private_image(filename)
    except Exception:
        app.logger.exception("Photo storage cleanup failed")
    return redirect(url_for("dashboard"))


@app.route("/admin/audit")
@owner_only
def admin_audit():
    entries = AdminAudit.query.order_by(AdminAudit.created.desc()).limit(500).all()
    return render_template("audit.html", entries=entries)


@app.route("/privacy")
def privacy():
    return render_template("privacy.html")


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Cache-Control"] = "no-store" if current_user.is_authenticated else "no-cache"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' data:; style-src 'self'; "
        "form-action 'self'; frame-ancestors 'none'; base-uri 'self'"
    )
    return response


def bootstrap_admin():
    """Create first admin once; never silently reset an existing admin password."""
    email = os.getenv("ADMIN_EMAIL", "").strip().lower()
    password = os.getenv("ADMIN_PASSWORD", "")
    if not email or len(password) < 12:
        if IS_PRODUCTION:
            raise RuntimeError("ADMIN_EMAIL and ADMIN_PASSWORD (12+ chars) are required.")
        return
    existing = User.query.filter_by(email=email).first()
    if existing:
        if not existing.is_admin:
            raise RuntimeError("ADMIN_EMAIL is already registered as a visitor. Resolve manually.")
        return
    db.session.add(User(name="Swap Couple", email=email,
        password_hash=generate_password_hash(password), is_admin=True,
        approved=True, email_ok=True, phone_ok=True))
    db.session.commit()


with app.app_context():
    # Development convenience only. Production schema must be migrated before app startup.
    if not IS_PRODUCTION and os.getenv("AUTO_CREATE_DB", "true").lower() == "true":
        db.create_all()
    # In production, the Render start command must run `flask db upgrade` first.
    # This creates the first admin once and never resets an existing admin password.
    bootstrap_admin()


if __name__ == "__main__":
    app.run(host="127.0.0.1" if not IS_PRODUCTION else "0.0.0.0",
            port=int(os.getenv("PORT", "5000")), debug=False)
