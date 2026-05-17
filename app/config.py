import os
from pathlib import Path


def _as_bool(value: str, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _debug_from_env() -> bool:
    """DEBUG explícito; si falta, FLASK_DEBUG (convención Flask CLI)."""
    for key in ("DEBUG", "FLASK_DEBUG"):
        raw = os.getenv(key)
        if raw is not None and raw.strip() != "":
            return _as_bool(raw, False)
    return False


def get_settings() -> dict:
    base_dir = Path(__file__).resolve().parent
    default_db_path = base_dir / "db" / "secure_vault.db"
    default_upload_folder = base_dir.parent / "storage" / "vault"
    upload_folder_env = os.getenv("UPLOAD_FOLDER")

    # Compatibilidad con configuración legacy:
    # versiones anteriores usaban app/vault_storage.
    # Si detectamos ese valor, forzamos la nueva ruta canónica storage/vault.
    if upload_folder_env:
        normalized = upload_folder_env.replace("\\", "/").rstrip("/")
        if normalized.endswith("vault_storage"):
            upload_folder = str(default_upload_folder)
        else:
            upload_folder = upload_folder_env
    else:
        upload_folder = str(default_upload_folder)

    return {
        "SECRET_KEY": os.getenv("SECRET_KEY", "change-me-in-production"),
        "SQLALCHEMY_DATABASE_URI": os.getenv("DATABASE_URL", f"sqlite:///{default_db_path}"),
        "SQLALCHEMY_TRACK_MODIFICATIONS": _as_bool(os.getenv("SQLALCHEMY_TRACK_MODIFICATIONS"), False),
        "UPLOAD_FOLDER": upload_folder,
        "DEBUG": _debug_from_env(),
        "TESTING": _as_bool(os.getenv("TESTING"), False),
    }