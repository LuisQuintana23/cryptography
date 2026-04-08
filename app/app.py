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
from crypto_d3 import SecureVaultHybridCrypto 
from crypto_d2 import SecureVaultCrypto

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
    # usar flask --app app init-db en consola dentro del env para poder crear la BD y limpiarla de ser necesario.
    # ==========================================
    @app.cli.command("init-db")
    def init_db_command():
        """Comando para limpiar y poblar la base de datos."""
        db.drop_all() 
        db.create_all()
        
        usuarios_test = [
            {"u": "admin", "p": "secreto123"},
            {"u": "trustee1", "p": "clave1"},
            {"u": "trustee2", "p": "clave2"}
        ]
        
        crypto_asym = SecureVaultHybridCrypto()
        crypto_sym = SecureVaultCrypto()

        for user_data in usuarios_test:
            if not User.query.filter_by(username=user_data["u"]).first():
                click.echo(f"Creando usuario: {user_data['u']}...")
                
                priv_hex, pub_hex = crypto_asym.generate_keypair()
                wrapped = crypto_sym.wrap_private_key(priv_hex, user_data["p"])
                
                new_user = User(
                    username=user_data["u"],
                    password_hash=generate_password_hash(user_data["p"]),
                    public_key=pub_hex,
                    encrypted_private_key=wrapped["encrypted_key"],
                    key_salt=wrapped["salt"],
                    key_nonce=wrapped["nonce"]
                )
                db.session.add(new_user)
        
        db.session.commit()
        click.echo("Base de datos inicializada y llenada con éxito.")

    return app

# Crear la instancia de la aplicación
app = create_app()

if __name__ == '__main__':
    app.run(debug=True)