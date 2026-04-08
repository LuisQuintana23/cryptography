import os

class Config:
    SECRET_KEY = 'una_clave_secreta_muy_dificil_de_adivinar'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///secure_vault.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    UPLOAD_FOLDER = 'vault_storage'