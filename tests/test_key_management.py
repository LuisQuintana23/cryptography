import io
import json
import shutil
import sys
import tempfile
from pathlib import Path

import pytest


ROOT_DIR = Path(__file__).resolve().parents[1]
APP_DIR = ROOT_DIR / "app"
if str(APP_DIR) not in sys.path:
    sys.path.insert(0, str(APP_DIR))

import app as app_module  # noqa: E402
import config as app_config  # noqa: E402
from crypto_d6 import SecureVaultD6Crypto  # noqa: E402
from extensions import db  # noqa: E402
from models import User  # noqa: E402


@pytest.fixture(scope="module")
def app_ctx():
    temp_dir = tempfile.TemporaryDirectory()
    db_path = Path(temp_dir.name) / "km_secure_vault.db"
    upload_dir = Path(temp_dir.name) / "vault_storage"
    upload_dir.mkdir(parents=True, exist_ok=True)

    app_config.Config.SQLALCHEMY_DATABASE_URI = f"sqlite:///{db_path}"
    app_config.Config.UPLOAD_FOLDER = str(upload_dir)
    app_config.Config.TESTING = True

    app = app_module.create_app()
    client = app.test_client()
    runner = app.test_cli_runner()
    yield {"app": app, "client": client, "runner": runner, "upload_dir": upload_dir}

    with app.app_context():
        db.session.remove()
        db.engine.dispose()
    temp_dir.cleanup()


@pytest.fixture(autouse=True)
def reset_state(app_ctx):
    result = app_ctx["runner"].invoke(args=["init-db"])
    if result.exit_code != 0:
        raise RuntimeError(f"init-db failed: {result.output}")

    upload_dir = app_ctx["upload_dir"]
    if upload_dir.exists():
        shutil.rmtree(upload_dir)
    upload_dir.mkdir(parents=True, exist_ok=True)


def _login(client, username: str, password: str):
    return client.post("/login", data={"username": username, "password": password}, follow_redirects=False)


def test_keystore_correct_password_succeeds():
    crypto = SecureVaultD6Crypto()
    private_material = "abc123:fed456"
    wrapped = crypto.wrap_private_key(private_material, "passw0rd!")
    recovered = crypto.unwrap_private_key(json.dumps(wrapped), password="passw0rd!")
    assert recovered == private_material
    assert wrapped["kdf"]["algorithm"] == "PBKDF2-HMAC-SHA256"
    assert wrapped["wrap"]["algorithm"] == "AES-GCM-256"
    assert wrapped["key_id"]


def test_keystore_wrong_password_fails():
    crypto = SecureVaultD6Crypto()
    wrapped = crypto.wrap_private_key("owner-priv:sign-priv", "correct-password")
    with pytest.raises(ValueError):
        crypto.unwrap_private_key(json.dumps(wrapped), password="wrong-password")


def test_modified_keystore_fails():
    crypto = SecureVaultD6Crypto()
    wrapped = crypto.wrap_private_key("owner-priv:sign-priv", "correct-password")
    tampered = dict(wrapped)
    tampered["encrypted_key"] = wrapped["encrypted_key"][:-1] + ("0" if wrapped["encrypted_key"][-1] != "0" else "1")
    with pytest.raises(ValueError):
        crypto.unwrap_private_key(json.dumps(tampered), password="correct-password")


def test_backup_restore_identity_succeeds(app_ctx):
    client = app_ctx["client"]
    app = app_ctx["app"]

    login = _login(client, "admin", "secreto123")
    assert login.status_code == 302

    backup_response = client.get("/download_identity")
    assert backup_response.status_code == 200
    backup_bytes = backup_response.data
    backup_payload = json.loads(backup_bytes.decode("utf-8"))

    with app.app_context():
        admin = User.query.filter_by(username="admin").first()
        assert admin is not None
        admin.encrypted_private_key = json.dumps({"broken": True})
        admin.key_salt = "00"
        admin.key_nonce = "00"
        db.session.commit()

    restore_response = client.post(
        "/restore_identity",
        data={
            "password": "secreto123",
            "identity_file": (io.BytesIO(backup_bytes), "identity_admin.json"),
        },
        content_type="multipart/form-data",
    )
    assert restore_response.status_code == 200
    assert restore_response.get_json()["status"] == "success"

    with app.app_context():
        admin = User.query.filter_by(username="admin").first()
        assert admin is not None
        assert admin.encrypted_private_key == backup_payload["encrypted_private_key"]


def test_stolen_keystore_alone_cannot_decrypt(app_ctx):
    client = app_ctx["client"]
    login = _login(client, "admin", "secreto123")
    assert login.status_code == 302

    backup_response = client.get("/download_identity")
    payload = json.loads(backup_response.data.decode("utf-8"))

    crypto = SecureVaultD6Crypto()
    with pytest.raises(ValueError):
        crypto.unwrap_private_key(payload["encrypted_private_key"], password="not-the-password")
