from datetime import datetime, timezone
from db.extensions import db


def utcnow():
    return datetime.now(timezone.utc)

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    # Llaves para Confidencialidad (ECIES - secp256k1)
    public_key = db.Column(db.String(255), nullable=True) 
    encrypted_private_key = db.Column(db.Text, nullable=True)
    # Llaves para Autenticidad (Firmas - Ed25519)
    signing_public_key = db.Column(db.String(255), nullable=True)
    # Reservado: el material de firma viaja junto al de cifrado en encrypted_private_key (un solo wrap AES-GCM).
    encrypted_signing_private_key = db.Column(db.Text, nullable=True)
    # Componentes de la KDF compartidos para desbloquear ambas llaves
    key_salt = db.Column(db.String(64), nullable=True)
    key_nonce = db.Column(db.String(64), nullable=True)
    # Ciclo de vida D6: active | rotated | retired (uso principalmente documental / exportación)
    keystore_lifecycle_state = db.Column(db.String(32), nullable=False, default="active")


class Vault(db.Model):
    __tablename__ = 'vaults'
    id = db.Column(db.Integer, primary_key=True)
    owner_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    threshold = db.Column(db.Integer, nullable=False, default=2)
    status = db.Column(db.String(32), nullable=False, default='active')
    created_at = db.Column(db.DateTime, default=utcnow)
    owner = db.relationship('User', backref=db.backref('owned_vaults', lazy=True))


class VaultTrustee(db.Model):
    __tablename__ = 'vault_trustees'
    id = db.Column(db.Integer, primary_key=True)
    vault_id = db.Column(db.Integer, db.ForeignKey('vaults.id'), nullable=False)
    trustee_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    status = db.Column(db.String(32), nullable=False, default='active')
    created_at = db.Column(db.DateTime, default=utcnow)

    vault = db.relationship('Vault', backref=db.backref('trusteeships', lazy=True))
    trustee = db.relationship('User', backref=db.backref('vault_memberships', lazy=True))

    __table_args__ = (
        db.UniqueConstraint('vault_id', 'trustee_user_id', name='uq_vault_trustee'),
    )

class Document(db.Model):
    __tablename__ = 'documents'
    id = db.Column(db.Integer, primary_key=True)
    vault_id = db.Column(db.Integer, db.ForeignKey('vaults.id'), nullable=False)
    owner_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    storage_path = db.Column(db.String(255), nullable=False)
    nonce = db.Column(db.String(64), nullable=True)
    aad = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=utcnow)
    owner = db.relationship('User', backref=db.backref('owned_documents', lazy=True))
    vault = db.relationship('Vault', backref=db.backref('documents', lazy=True))

class Share(db.Model):
    __tablename__ = 'shares'
    id = db.Column(db.Integer, primary_key=True)
    document_id = db.Column(db.Integer, db.ForeignKey('documents.id'), nullable=False)
    trustee_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    vault_trustee_id = db.Column(db.Integer, db.ForeignKey('vault_trustees.id'), nullable=False)
    encrypted_fragment = db.Column(db.Text, nullable=False) 
    plain_fragment = db.Column(db.String(255), nullable=True)
    document = db.relationship('Document', backref=db.backref('shares', lazy=True))
    trustee = db.relationship('User', backref=db.backref('received_shares', lazy=True))
    vault_trustee = db.relationship('VaultTrustee', backref=db.backref('shares', lazy=True))