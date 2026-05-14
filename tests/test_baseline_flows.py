import io
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
from extensions import db  # noqa: E402
from models import Document, Share, User, Vault, VaultTrustee  # noqa: E402


@pytest.fixture(scope="module")
def test_context():
    temp_dir = tempfile.TemporaryDirectory()
    db_path = Path(temp_dir.name) / "baseline_secure_vault.db"
    upload_dir = Path(temp_dir.name) / "vault_storage"
    upload_dir.mkdir(parents=True, exist_ok=True)

    app_config.Config.SQLALCHEMY_DATABASE_URI = f"sqlite:///{db_path}"
    app_config.Config.UPLOAD_FOLDER = str(upload_dir)
    app_config.Config.TESTING = True

    app = app_module.create_app()
    client = app.test_client()
    runner = app.test_cli_runner()

    context = {"app": app, "client": client, "runner": runner, "upload_dir": upload_dir}
    yield context

    with app.app_context():
        db.session.remove()
        db.engine.dispose()
    temp_dir.cleanup()


@pytest.fixture(autouse=True)
def reset_db(test_context):
    result = test_context["runner"].invoke(args=["init-db"])
    if result.exit_code != 0:
        raise RuntimeError(f"init-db failed: {result.output}")

    upload_dir = test_context["upload_dir"]
    if upload_dir.exists():
        shutil.rmtree(upload_dir)
    upload_dir.mkdir(parents=True, exist_ok=True)


def _login(client, username: str, password: str):
    return client.post(
        "/login",
        data={"username": username, "password": password},
        follow_redirects=False,
    )


def _logout(client):
    client.get("/logout", follow_redirects=False)


def _upload_sample_vault(test_context, filename: str = "baseline.txt", data: bytes = b"baseline-content"):
    client = test_context["client"]
    app = test_context["app"]
    login_response = _login(client, "admin", "secreto123")
    assert login_response.status_code == 302

    with app.app_context():
        trustee_ids = [
            str(user.id)
            for user in User.query.filter(User.username.in_(["trustee1", "trustee2"])).all()
        ]
        assert len(trustee_ids) == 2

    response = client.post(
        "/upload",
        data={
            "password": "secreto123",
            "selected_trustees": trustee_ids,
            "file": (io.BytesIO(data), filename),
        },
        content_type="multipart/form-data",
    )
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["status"] == "success"

    with app.app_context():
        document = Document.query.order_by(Document.id.desc()).first()
        assert document is not None
        return document.id


def test_seeded_login_owner_and_trustee(test_context):
    client = test_context["client"]
    owner_response = _login(client, "admin", "secreto123")
    assert owner_response.status_code == 302
    assert "/dashboard" in owner_response.location

    _logout(client)

    trustee_response = _login(client, "trustee1", "clave1")
    assert trustee_response.status_code == 302
    assert "/dashboard" in trustee_response.location


def test_upload_and_seal_vault_container(test_context):
    app = test_context["app"]
    _upload_sample_vault(test_context)

    with app.app_context():
        document = Document.query.order_by(Document.id.desc()).first()
        assert document is not None
        assert Path(document.storage_path).exists()
        assert Share.query.filter_by(document_id=document.id).count() > 0
        assert document.vault_id is not None
        assert document.vault.threshold >= 2


def test_trustee_release_threshold_reconstruction_flow(test_context):
    client = test_context["client"]
    app = test_context["app"]
    document_id = _upload_sample_vault(test_context, filename="threshold.txt", data=b"threshold-case")
    _logout(client)

    with app.app_context():
        trustee1 = User.query.filter_by(username="trustee1").first()
        trustee2 = User.query.filter_by(username="trustee2").first()
        assert trustee1 is not None
        assert trustee2 is not None

        share1 = Share.query.filter_by(document_id=document_id, trustee_user_id=trustee1.id).first()
        share2 = Share.query.filter_by(document_id=document_id, trustee_user_id=trustee2.id).first()
        assert share1 is not None
        assert share2 is not None
        share1_id = share1.id
        share2_id = share2.id

    login_trustee1 = _login(client, "trustee1", "clave1")
    assert login_trustee1.status_code == 302
    response_1 = client.post(f"/release/{share1_id}", data={"password": "clave1"})
    assert response_1.status_code == 200
    payload_1 = response_1.get_json()
    assert payload_1["status"] == "success"
    assert "tokens necesarios" in payload_1["message"]
    _logout(client)

    login_trustee2 = _login(client, "trustee2", "clave2")
    assert login_trustee2.status_code == 302
    response_2 = client.post(f"/release/{share2_id}", data={"password": "clave2"})
    assert response_2.status_code == 200
    assert "attachment" in response_2.headers.get("Content-Disposition", "")


def test_upload_requires_at_least_two_selected_trustees(test_context):
    client = test_context["client"]
    app = test_context["app"]
    login_response = _login(client, "admin", "secreto123")
    assert login_response.status_code == 302

    with app.app_context():
        one_trustee = User.query.filter_by(username="trustee1").first()
        assert one_trustee is not None

    response = client.post(
        "/upload",
        data={
            "password": "secreto123",
            "selected_trustees": [str(one_trustee.id)],
            "file": (io.BytesIO(b"sample"), "one-trustee.txt"),
        },
        content_type="multipart/form-data",
    )
    assert response.status_code == 400
    payload = response.get_json()
    assert "Se requieren al menos 2 fiduciarios" in payload["error"]


def test_recovery_blocked_when_trustee_policy_becomes_invalid(test_context):
    client = test_context["client"]
    app = test_context["app"]
    document_id = _upload_sample_vault(test_context, filename="policy.txt", data=b"policy-case")
    _logout(client)

    with app.app_context():
        trustee1 = User.query.filter_by(username="trustee1").first()
        trustee2 = User.query.filter_by(username="trustee2").first()
        assert trustee1 and trustee2

        share1 = Share.query.filter_by(document_id=document_id, trustee_user_id=trustee1.id).first()
        share2 = Share.query.filter_by(document_id=document_id, trustee_user_id=trustee2.id).first()
        assert share1 and share2
        share1_id = share1.id
        share2_id = share2.id

    # Primer token válido
    assert _login(client, "trustee1", "clave1").status_code == 302
    response_1 = client.post(f"/release/{share1_id}", data={"password": "clave1"})
    assert response_1.status_code == 200
    _logout(client)

    # Inactivar membresía del segundo trustee y forzar política inválida
    with app.app_context():
        share2 = db.session.get(Share, share2_id)
        membership = db.session.get(VaultTrustee, share2.vault_trustee_id)
        membership.status = "revoked"
        doc = db.session.get(Document, document_id)
        vault = db.session.get(Vault, doc.vault_id)
        vault.threshold = 2
        db.session.commit()

    # Debe bloquear recuperación por política inconsistente (<2 activos)
    assert _login(client, "trustee2", "clave2").status_code == 302
    response_2 = client.post(f"/release/{share2_id}", data={"password": "clave2"})
    assert response_2.status_code == 403 or response_2.status_code == 400
