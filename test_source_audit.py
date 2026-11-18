from pathlib import Path
import ast

ROOT = Path(__file__).resolve().parents[1]

def test_app_parses():
    ast.parse((ROOT / "app.py").read_text(encoding="utf-8"))

def test_production_requires_msg91_credentials():
    text = (ROOT / "app.py").read_text(encoding="utf-8")
    assert "'MSG91_AUTHKEY'" in text
    assert "'MSG91_WIDGET_TOKEN'" in text
    assert "verifyAccessToken" in text

def test_otp_hourly_limit_exists():
    text = (ROOT / "app.py").read_text(encoding="utf-8")
    assert "recent_count>=5" in text

def test_no_python_cache_in_release():
    assert not list(ROOT.rglob("__pycache__"))

def test_login_throttle_is_database_backed():
    text = (ROOT / "app.py").read_text(encoding="utf-8")
    assert "class LoginAttempt(db.Model)" in text
    assert "recent>=10" in text
    assert "timedelta(minutes=15)" in text

def test_no_s3_dependency_and_database_media_storage():
    text = (ROOT / "app.py").read_text(encoding="utf-8")
    assert "S3_BUCKET" not in text
    assert "class UserMedia(db.Model)" in text
    assert "db.LargeBinary" in text
    assert "image.verify()" in text

def test_admin_approval_requires_verified_contact_and_selfie():
    text = (ROOT / "app.py").read_text(encoding="utf-8")
    assert "action=='approve' and u.email_ok and u.phone_ok and UserMedia.query.filter_by(user_id=u.id,kind='selfie').first()" in text

def test_chat_requires_current_approval():
    text = (ROOT / "app.py").read_text(encoding="utf-8")
    assert "def chat_allowed(uid):" in text
    assert "u.email_ok and u.phone_ok and u.approved" in text


def test_private_selfie_is_admin_only():
    text = (ROOT / "app.py").read_text(encoding="utf-8")
    assert "@app.get('/admin/selfie/<int:uid>')" in text
    assert "@owner_only" in text


def test_media_upload_limits_and_formats():
    text = (ROOT / "app.py").read_text(encoding="utf-8")
    assert "5*1024*1024" in text
    assert "'JPEG':'image/jpeg'" in text
    assert "'PNG':'image/png'" in text
    assert "'WEBP':'image/webp'" in text
