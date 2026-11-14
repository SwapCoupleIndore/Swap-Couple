from pathlib import Path
import ast

ROOT = Path(__file__).resolve().parents[1]

def test_app_parses():
    ast.parse((ROOT / "app.py").read_text(encoding="utf-8"))

def test_production_requires_sms_token():
    text = (ROOT / "app.py").read_text(encoding="utf-8")
    assert "'SMS_WEBHOOK_TOKEN'" in text

def test_otp_hourly_limit_exists():
    text = (ROOT / "app.py").read_text(encoding="utf-8")
    assert "recent_count>=5" in text

def test_no_python_cache_in_release():
    assert not list(ROOT.rglob("__pycache__"))
