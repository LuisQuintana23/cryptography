import json

from werkzeug.security import check_password_hash, generate_password_hash

from crypto.crypto_d6 import SecureVaultD6Crypto
from db.models import User
from db.seeders.seed_users import seed_default_users
from repositories.user_repository import UserRepository
from services.keystore_service import unwrap_user_private_keys


user_repository = UserRepository()


def create_user(username: str, password: str) -> User:
    crypto_d6 = SecureVaultD6Crypto()
    enc_priv, enc_pub = crypto_d6.generate_encryption_keypair()
    sign_priv, sign_pub = crypto_d6.generate_signing_keypair()
    combined_privates = f"{enc_priv}:{sign_priv}"
    wrapped = crypto_d6.wrap_private_key(combined_privates, password)

    return User(
        username=username,
        password_hash=generate_password_hash(password),
        public_key=enc_pub,
        signing_public_key=sign_pub,
        encrypted_private_key=json.dumps(wrapped),
        encrypted_signing_private_key=None,
        key_salt=wrapped["salt"],
        key_nonce=wrapped["nonce"],
        keystore_lifecycle_state="active",
    )


def register_user(db, username: str, password: str, *, commit: bool = True) -> User:
    user = create_user(username, password)
    user_repository.add(db, user)
    if commit:
        db.session.commit()
    return user


def rotate_user_vault_credentials(db, user: User, old_password: str, new_password: str, *, commit: bool = True) -> None:
    """
    Rotación mínima D6: mismo par de llaves, nuevo wrap PBKDF2/AES-GCM y nuevo hash de login.
    La contraseña de sesión y la del keystore permanecen alineadas (un solo secreto usuario).
    """
    if not new_password or len(new_password) < 8:
        raise ValueError("La nueva contraseña debe tener al menos 8 caracteres.")
    if not check_password_hash(user.password_hash, old_password):
        raise ValueError("La contraseña actual no es válida.")

    crypto_d6 = SecureVaultD6Crypto()
    enc_priv, sign_priv = unwrap_user_private_keys(user, old_password, crypto=crypto_d6)
    combined = f"{enc_priv}:{sign_priv}"
    wrapped = crypto_d6.wrap_private_key(combined, new_password)

    user.encrypted_private_key = json.dumps(wrapped)
    user.key_salt = wrapped["salt"]
    user.key_nonce = wrapped["nonce"]
    user.password_hash = generate_password_hash(new_password)
    user.keystore_lifecycle_state = "rotated"

    if commit:
        db.session.commit()


def resolve_trustee_by_username(username: str, current_user_id: int):
    return user_repository.find_by_username_case_insensitive_excluding_user(username, current_user_id)
