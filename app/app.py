from flask import Flask
import os
import click 

# Importar configuraciones locales
from extensions import db
from config import Config
from routes import bp

# Importaciones necesarias para inicializar la BD
from models import User
from werkzeug.security import generate_password_hash

# Importaciones del Motor Simétrico (D2) y el Nuevo Motor Híbrido con Firmas (D5)
from crypto_d2 import SecureVaultCrypto
from crypto_d5_signatures import SecureVaultSignedCrypto

def create_app():
    """Patrón de Fábrica de Aplicaciones (Application Factory)"""
    app = Flask(__name__)
    app.config.from_object(Config)

    # Inicializar las extensiones
    db.init_app(app)

    # Asegurarnos de que la carpeta exista al arrancar
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

    # Registrar el Blueprint (las rutas)
    app.register_blueprint(bp)

    # ==========================================
    # COMANDO CLI PARA INICIALIZAR LA BD
    # usar flask --app app init-db en consola 
    # ==========================================
    @app.cli.command("init-db")
    def init_db_command():
        """Comando para limpiar y poblar la base de datos."""
        db.drop_all() 
        db.create_all()
        
        usuarios_test = [
            {"u": "admin", "p": "secreto123"},
            {"u": "trustee1", "p": "clave1"},
            {"u": "trustee2", "p": "clave2"},
            {"u": "notrustee", "p": "clave3"},
        ]
        
        # Instanciamos los motores criptográficos
        crypto_sym = SecureVaultCrypto()           # Para envolver las llaves privadas (Keystore)
        vault_signed = SecureVaultSignedCrypto()   # Para generar las llaves D5

        for user_data in usuarios_test:
            if not User.query.filter_by(username=user_data["u"]).first():
                click.echo(f"Creando usuario: {user_data['u']}...")
                
                # Generar ambas identidades criptográficas
                enc_priv, enc_pub = vault_signed.generate_encryption_keypair()
                sign_priv, sign_pub = vault_signed.generate_signing_keypair()
                
                # Keystore: Unimos ambas llaves privadas separadas por ":"
                # Esto evita reutilizar Nonces de AES-GCM y ahorra espacio en la base de datos
                combined_privates = f"{enc_priv}:{sign_priv}"
                
                # Cifrar el llavero completo con la contraseña del usuario
                wrapped = crypto_sym.wrap_private_key(combined_privates, user_data["p"])
                
                # Guardar en Base de Datos
                new_user = User(
                    username=user_data["u"],
                    password_hash=generate_password_hash(user_data["p"]),
                    
                    # Llaves Públicas (Visibles para todos)
                    public_key=enc_pub,
                    signing_public_key=sign_pub,
                    # Llavero Privado Cifrado
                    encrypted_private_key=wrapped["encrypted_key"],
                    key_salt=wrapped["salt"],
                    key_nonce=wrapped["nonce"]
                )
                db.session.add(new_user)
        
        db.session.commit()
        click.echo("Base de datos inicializada y llenada con éxito (Llaves Ed25519 integradas).")

    return app

# Crear la instancia de la aplicación
app = create_app()

if __name__ == '__main__':
    app.run(debug=True)