"""
Integración D6 con la app Flask (BD, rutas, `app.services`).

Cripto pura: `tests/test_crypto_d6_unit.py` (sin cargar `app`).
"""

import io
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration

ROOT_DIR = Path(__file__).resolve().parents[1]
APP_DIR = ROOT_DIR / "app"
for path in (APP_DIR, ROOT_DIR):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import app as app_module  # noqa: E402
from crypto.crypto_d6 import SecureVaultD6Crypto  # noqa: E402
from db.extensions import db  # noqa: E402
from db.models import User  # noqa: E402
from repositories.user_repository import UserRepository  # noqa: E402
from services.auth_service import rotate_user_vault_credentials  # noqa: E402


@pytest.fixture(scope="module")
def app_ctx():
    temp_dir = tempfile.TemporaryDirectory()
    db_path = Path(temp_dir.name) / "km_secure_vault.db"
    upload_dir = Path(temp_dir.name) / "vault_storage"
    upload_dir.mkdir(parents=True, exist_ok=True)

    os.environ["DATABASE_URL"] = f"sqlite:///{db_path}"
    os.environ["UPLOAD_FOLDER"] = str(upload_dir)
    os.environ["TESTING"] = "true"

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


def test_restore_rejects_foreign_identity_username(app_ctx):
    client = app_ctx["client"]
    assert _login(client, "trustee1", "clave1").status_code == 302
    foreign_backup = client.get("/download_identity").data
    client.get("/logout")
    assert _login(client, "admin", "secreto123").status_code == 302

    restore_response = client.post(
        "/restore_identity",
        data={
            "password": "clave1",
            "identity_file": (io.BytesIO(foreign_backup), "identity_trustee1.json"),
        },
        content_type="multipart/form-data",
    )
    assert restore_response.status_code == 400


def test_restore_rejects_mismatched_public_keys(app_ctx):
    client = app_ctx["client"]
    app = app_ctx["app"]
    assert _login(client, "admin", "secreto123").status_code == 302
    backup = json.loads(client.get("/download_identity").data.decode("utf-8"))

    with app.app_context():
        trustee1 = User.query.filter_by(username="trustee1").first()
        assert trustee1 is not None
        backup["public_key"] = trustee1.public_key

    restore_response = client.post(
        "/restore_identity",
        data={
            "password": "secreto123",
            "identity_file": (io.BytesIO(json.dumps(backup).encode("utf-8")), "identity_admin.json"),
        },
        content_type="multipart/form-data",
    )
    assert restore_response.status_code == 400


def test_rotate_vault_credentials_updates_login_and_keystore(app_ctx):
    client = app_ctx["client"]
    app = app_ctx["app"]

    with app.app_context():
        admin = UserRepository().find_by_username("admin")
        assert admin is not None
        rotate_user_vault_credentials(db, admin, "secreto123", "nuevoPass9", commit=True)

    client.get("/logout")
    assert _login(client, "admin", "secreto123").status_code != 302
    assert _login(client, "admin", "nuevoPass9").status_code == 302

    backup = json.loads(client.get("/download_identity").data.decode("utf-8"))
    crypto = SecureVaultD6Crypto()
    with pytest.raises(ValueError):
        crypto.unwrap_private_key(backup["encrypted_private_key"], password="secreto123")
    material = crypto.unwrap_private_key(backup["encrypted_private_key"], password="nuevoPass9")
    assert ":" in material
