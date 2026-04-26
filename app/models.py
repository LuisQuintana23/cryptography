from extensions import db
from datetime import datetime

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    public_key = db.Column(db.String(255), nullable=True) 
    encrypted_private_key = db.Column(db.Text, nullable=True)
    key_salt = db.Column(db.String(64), nullable=True)
    key_nonce = db.Column(db.String(64), nullable=True)

class Document(db.Model):
    __tablename__ = 'documents'
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    storage_path = db.Column(db.String(255), nullable=False)
    nonce = db.Column(db.String(64), nullable=True)
    aad = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    owner = db.relationship('User', backref=db.backref('owned_documents', lazy=True))

class Share(db.Model):
    __tablename__ = 'shares'
    id = db.Column(db.Integer, primary_key=True)
    document_id = db.Column(db.Integer, db.ForeignKey('documents.id'), nullable=False)
    trustee_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    encrypted_fragment = db.Column(db.Text, nullable=False) 
    plain_fragment = db.Column(db.String(255), nullable=True)
    document = db.relationship('Document', backref=db.backref('shares', lazy=True))
    trustee = db.relationship('User', backref=db.backref('received_shares', lazy=True))