from flask import Flask
import os
import click
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from dotenv import load_dotenv

from db.extensions import db
from config import get_settings
from routes import bp
from services.auth_service import register_user, rotate_user_vault_credentials, seed_default_users
from repositories.user_repository import UserRepository

user_repository = UserRepository()

def create_app():
    """Patrón de Fábrica de Aplicaciones (Application Factory)"""
    load_dotenv(ROOT_DIR / ".env")
    app = Flask(__name__)
    app.config.from_mapping(get_settings())
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
        
        usuarios_test = seed_default_users()
        
        for user_data in usuarios_test:
            if not user_repository.find_by_username(user_data["u"]):
                click.echo(f"Creando usuario: {user_data['u']}...")
                
                register_user(db, user_data["u"], user_data["p"], commit=False)
        
        db.session.commit()
        click.echo("Base de datos inicializada y llenada con éxito (Llaves Ed25519 integradas).")

    @app.cli.command("rotate-user-credentials")
    @click.argument("username")
    @click.argument("old_password")
    @click.argument("new_password")
    def rotate_user_credentials_cmd(username, old_password, new_password):
        """Re-envuelve el keystore y actualiza el hash de login (rotación mínima D6)."""
        user = user_repository.find_by_username(username)
        if not user:
            raise click.ClickException("Usuario no encontrado.")
        rotate_user_vault_credentials(db, user, old_password, new_password, commit=True)
        click.echo(f"Credenciales rotadas para {username}.")

    return app

# Crear la instancia de la aplicación
app = create_app()

if __name__ == '__main__':
    app.run(debug=app.config["DEBUG"])