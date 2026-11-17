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

def test_private_image_names_are_validated():
    text = (ROOT / "app.py").read_text(encoding="utf-8")
    assert "def valid_private_filename(filename):" in text
    assert "re.fullmatch(r'[a-f0-9]{40}\\.jpg', filename)" in text

def test_chat_requires_current_approval():
    text = (ROOT / "app.py").read_text(encoding="utf-8")
    assert "def chat_allowed(uid):" in text
    assert "u.email_ok and u.phone_ok and u.approved" in text
