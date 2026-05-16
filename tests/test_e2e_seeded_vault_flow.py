"""
E2E con usuarios de `seed_users.py` (init-db): cifrado, umbral 2-of-2 y control de acceso.

Ejecutar: `pytest tests/test_e2e_seeded_vault_flow.py` (requiere integración / app).
"""

from __future__ import annotations

import io
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
from db.extensions import db  # noqa: E402
from db.models import Document, Share, User  # noqa: E402
from db.seeders.seed_users import DEFAULT_USERS  # noqa: E402


def _seed_password(username: str) -> str:
    for row in DEFAULT_USERS:
        if row["u"] == username:
            return row["p"]
    raise KeyError(f"Usuario no definido en seed_users: {username}")


@pytest.fixture(scope="module")
def e2e_ctx():
    temp_dir = tempfile.TemporaryDirectory()
    db_path = Path(temp_dir.name) / "e2e_secure_vault.db"
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
def _reset_e2e_db(e2e_ctx):
    result = e2e_ctx["runner"].invoke(args=["init-db"])
    if result.exit_code != 0:
        raise RuntimeError(f"init-db failed: {result.output}")

    upload_dir = e2e_ctx["upload_dir"]
    if upload_dir.exists():
        shutil.rmtree(upload_dir)
    upload_dir.mkdir(parents=True, exist_ok=True)


def _login(client, username: str, password: str):
    return client.post("/login", data={"username": username, "password": password}, follow_redirects=False)


def _logout(client):
    client.get("/logout", follow_redirects=False)


def _upload_as_admin_with_trustees(client, app, *, filename: str, data: bytes):
    assert _login(client, "admin", _seed_password("admin")).status_code == 302

    with app.app_context():
        trustee_ids = [
            str(user.id)
            for user in User.query.filter(User.username.in_(["trustee1", "trustee2"])).all()
        ]
        assert len(trustee_ids) == 2

    response = client.post(
        "/upload",
        data={
            "password": _seed_password("admin"),
            "selected_trustees": trustee_ids,
            "file": (io.BytesIO(data), filename),
        },
        content_type="multipart/form-data",
    )
    assert response.status_code == 200, response.get_json()
    assert response.get_json()["status"] == "success"

    with app.app_context():
        document = Document.query.order_by(Document.id.desc()).first()
        assert document is not None
        return document.id


def test_e2e_seeded_admin_encrypts_pdf_two_trustees_release_download_original(e2e_ctx):
    """Admin (seed) cifra un PDF ficticio para trustee1 y trustee2; ambos liberan; el archivo coincide."""
    client = e2e_ctx["client"]
    app = e2e_ctx["app"]

    original = (
        b"%PDF-1.4\n"
        b"1 0 obj<<>>endobj\n"
        b"trailer<<>>\n"
        b"%%EOF\n"
        b"---contenido-binario-simulado---\n" + os.urandom(64)
    )
    doc_id = _upload_as_admin_with_trustees(
        client, app, filename="informe-e2e.pdf", data=original
    )

    with app.app_context():
        t1 = User.query.filter_by(username="trustee1").first()
        t2 = User.query.filter_by(username="trustee2").first()
        s1 = Share.query.filter_by(document_id=doc_id, trustee_user_id=t1.id).first()
        s2 = Share.query.filter_by(document_id=doc_id, trustee_user_id=t2.id).first()
        assert s1 and s2
        sid1, sid2 = s1.id, s2.id

    _logout(client)
    assert _login(client, "trustee1", _seed_password("trustee1")).status_code == 302
    r1 = client.post(f"/release/{sid1}", data={"password": _seed_password("trustee1")})
    assert r1.status_code == 200
    assert r1.is_json
    assert "tokens necesarios" in r1.get_json()["message"]

    _logout(client)
    assert _login(client, "trustee2", _seed_password("trustee2")).status_code == 302
    r2 = client.post(f"/release/{sid2}", data={"password": _seed_password("trustee2")})
    assert r2.status_code == 200
    assert not r2.is_json
    assert "attachment" in (r2.headers.get("Content-Disposition") or "")
    assert r2.data == original


def test_e2e_notrustee_cannot_release_trustee_share(e2e_ctx):
    """notrustee (seed) no es fiduciario del vault: no puede liberar el token de trustee1."""
    client = e2e_ctx["client"]
    app = e2e_ctx["app"]

    payload = b"secreto-solo-para-t1-y-t2"
    doc_id = _upload_as_admin_with_trustees(
        client, app, filename="privado.bin", data=payload
    )

    with app.app_context():
        t1 = User.query.filter_by(username="trustee1").first()
        share = Share.query.filter_by(document_id=doc_id, trustee_user_id=t1.id).first()
        assert share is not None
        share_id = share.id

    _logout(client)
    assert _login(client, "notrustee", _seed_password("notrustee")).status_code == 302
    denied = client.post(f"/release/{share_id}", data={"password": _seed_password("notrustee")})
    assert denied.status_code == 403
    assert b"Acceso denegado" in denied.data
