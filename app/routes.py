from flask import Blueprint, render_template, request, redirect, url_for, session, send_file, current_app, jsonify
import io, json, os
from werkzeug.security import check_password_hash
from werkzeug.utils import secure_filename
# Importaciones locales 
from db.extensions import db
from repositories.document_repository import DocumentRepository
from repositories.share_repository import ShareRepository
from repositories.user_repository import UserRepository
from repositories.vault_repository import VaultRepository
from services.auth_service import register_user, resolve_trustee_by_username
from services.recovery_service import (
    decrypt_and_store_share_fragment,
    release_share_and_maybe_decrypt,
    validate_identity_payload,
)
from services.vault_service import create_vault_document

# Blueprint
bp = Blueprint('main', __name__)
user_repository = UserRepository()
share_repository = ShareRepository()
vault_repository = VaultRepository()
document_repository = DocumentRepository()

# Rutas
@bp.route('/')
def index():
    return render_template('index.html')

@bp.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = user_repository.find_by_username(username)

        if user and check_password_hash(user.password_hash, password):
            session['usuario'] = user.username
            return redirect(url_for('main.dashboard'))
        else:
            error = "Credenciales inválidas. Inténtalo de nuevo."

    return render_template('login.html', error=error)


@bp.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        password = request.form.get('password') or ''
        password_confirm = request.form.get('password_confirm') or ''

        if not username or len(username) < 3 or len(username) > 50:
            error = "El usuario debe tener entre 3 y 50 caracteres."
        elif not password or len(password) < 8:
            error = "La contraseña debe tener al menos 8 caracteres."
        elif password != password_confirm:
            error = "Las contraseñas no coinciden."
        elif user_repository.find_by_username(username):
            error = "Ese nombre de usuario ya existe."
        else:
            new_user = register_user(db, username, password, commit=True)
            session['usuario'] = new_user.username
            return redirect(url_for('main.dashboard'))

    return render_template('register.html', error=error)

@bp.route('/dashboard')
def dashboard():
    if 'usuario' not in session:
        return redirect(url_for('main.login'))
    
    user = user_repository.find_by_username(session['usuario'])
    
    # Pasamos user.owned_documents a la plantilla
    return render_template(
        'dashboard.html', 
        usuario=user.username, 
        public_key=user.public_key,
        owned_documents=user.owned_documents
    )

@bp.route('/logout')
def logout():
    session.pop('usuario', None)
    return redirect(url_for('main.index'))

@bp.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if 'usuario' not in session:
        return redirect(url_for('main.login'))
        
    owner = user_repository.find_by_username(session['usuario'])
    available_trustees = user_repository.list_other_users(owner.id)

    if request.method == 'POST':
        # Fix de validaciones para los archivos subidos.
        
        if 'file' not in request.files:
            return jsonify({"error": "Petición inválida: No se detectó ningún archivo"}), 400
            
        file = request.files['file']
        
        # Validar nombre de archivo (Evitar inyecciones largas o archivos sin nombre)
        if file.filename == '':
            return jsonify({"error": "No se seleccionó ningún archivo"}), 400
            
        filename = secure_filename(file.filename)
        if not filename or len(filename) > 100:
            return jsonify({"error": "Nombre de archivo inválido o demasiado largo (máximo 100 caracteres)."}), 400

        # Validar tamaño del archivo (Prevenir DoS por agotamiento de RAM)
        # Límite en 10 MB
        MAX_FILE_SIZE = 10 * 1024 * 1024 
        
        # Revisamos la cabecera HTTP primero
        if request.content_length is not None and request.content_length > MAX_FILE_SIZE:
            return jsonify({"error": "El archivo excede el tamaño máximo permitido (10 MB)."}), 413
            
        plaintext = file.read()
        
        # Verificamos los bytes reales cargados en memoria
        if len(plaintext) == 0:
            return jsonify({"error": "El archivo está vacío."}), 400
            
        if len(plaintext) > MAX_FILE_SIZE:
            return jsonify({"error": "El archivo excede el tamaño máximo permitido (15 MB)."}), 413

        # Validar la contraseña
        password = request.form.get('password')
        if not password or len(password) > 128:
            return jsonify({"error": "La contraseña es requerida y no debe exceder los 128 caracteres."}), 400

        
        try:
            selected_trustee_ids_raw = request.form.getlist("selected_trustees")
            if not selected_trustee_ids_raw:
                return jsonify({"error": "Debes seleccionar al menos 2 fiduciarios."}), 400

            try:
                selected_trustee_ids = [int(trustee_id) for trustee_id in selected_trustee_ids_raw]
            except ValueError:
                return jsonify({"error": "Selección de fiduciarios inválida."}), 400

            selected_trustee_ids = list(dict.fromkeys(selected_trustee_ids))
            if owner.id in selected_trustee_ids:
                return jsonify({"error": "El propietario no puede ser fiduciario de su propia bóveda."}), 400

            create_vault_document(
                owner=owner,
                plaintext=plaintext,
                source_filename=filename,
                password=password,
                selected_trustee_ids=selected_trustee_ids,
                upload_folder=current_app.config["UPLOAD_FOLDER"],
                db=db,
            )
            db.session.commit()
            return jsonify({
                "status": "success", 
                "message": "El documento ha sido cifrado, firmado digitalmente y sellado correctamente."
            }), 200

        except ValueError as e:
            db.session.rollback()
            if "Contraseña incorrecta" in str(e):
                return jsonify({"error": "Contraseña incorrecta. No se pudo autorizar la firma."}), 401
            return jsonify({"error": str(e)}), 400
        except Exception as e:
            db.session.rollback()
            return jsonify({"error": f"Error criptográfico: {str(e)}"}), 500
    return render_template(
        'upload_file.html',
        trustees_count=len(available_trustees)
    )


@bp.route('/api/trustees/resolve', methods=['POST'])
def resolve_trustee():
    if 'usuario' not in session:
        return jsonify({"error": "No autenticado"}), 401

    current_user = user_repository.find_by_username(session['usuario'])
    username = (request.json or {}).get("username", "").strip()
    if not username:
        return jsonify({"error": "Debes escribir un username."}), 400

    trustee = resolve_trustee_by_username(username, current_user.id)
    if not trustee:
        return jsonify({"error": "No existe un fiduciario con ese username."}), 404

    return jsonify({"id": trustee.id, "username": trustee.username})

# Lógica de liberación y decifrado para los usuarios trusted
@bp.route('/trustee_dashboard')
def trustee_dashboard():
    if 'usuario' not in session:
        return redirect(url_for('main.login'))
        
    user = user_repository.find_by_username(session['usuario'])
    mis_shares = share_repository.list_active_for_trustee(user.id)
    
    return render_template('trustee_dashboard.html', shares=mis_shares)

# Release para desbloquear documento
@bp.route('/release/<int:share_id>', methods=['GET', 'POST'])
def release_share(share_id):
    if 'usuario' not in session:
        return redirect(url_for('main.login'))

    user = user_repository.find_by_username(session['usuario'])
    share = share_repository.get_or_404(db, share_id)
    doc = share.document

    membership = vault_repository.find_active_membership(share.vault_trustee_id, user.id)

    if share.trustee_user_id != user.id or membership is None:
        return "Acceso denegado", 403

    if request.method == 'POST':
        password = request.form['password']
        try:
            decrypt_and_store_share_fragment(db, user, share, password)
            result = release_share_and_maybe_decrypt(db, user, share)

            if result["type"] == "file":
                return send_file(
                    io.BytesIO(result["content"]),
                    as_attachment=True,
                    download_name=result["filename"],
                    mimetype='application/octet-stream'
                )
            return jsonify(result["payload"]), result["status_code"]
                
        except ValueError as e:
            return jsonify({"error": f"Error criptográfico o contraseña incorrecta: {str(e)}"}), 400
        except Exception as e:
            return jsonify({"error": f"Error interno: {str(e)}"}), 500

    return render_template('release.html', document=doc)

# --- Ruta para descargar el archivo .vault (Para el Dueño) ---
@bp.route('/download_vault/<int:doc_id>')
def download_vault(doc_id):
    if 'usuario' not in session:
        return redirect(url_for('main.login'))
        
    user = user_repository.find_by_username(session['usuario'])
    doc = document_repository.get_or_404(db, doc_id)
    
    if doc.owner_user_id != user.id:
        return "No tienes permiso para descargar este archivo", 403

    storage_path = doc.storage_path or ""
    if not os.path.isabs(storage_path):
        storage_path = os.path.abspath(os.path.join(current_app.config["UPLOAD_FOLDER"], os.path.basename(storage_path)))

    if not os.path.exists(storage_path):
        return jsonify({"error": "El archivo .vault no existe en almacenamiento."}), 404

    return send_file(storage_path, as_attachment=True)

# --- Ruta para descargar la Identidad Digital (Para todos los usuarios) ---
@bp.route('/download_identity')
def download_identity():
    if 'usuario' not in session:
        return redirect(url_for('main.login'))
        
    user = user_repository.find_by_username(session['usuario'])
    
    try:
        keystore = json.loads(user.encrypted_private_key) if user.encrypted_private_key else {}
    except (json.JSONDecodeError, TypeError):
        keystore = {}

    # Creamos un archivo de identidad portable
    identity_data = {
        "username": user.username,
        "public_key": user.public_key,
        "signing_public_key": user.signing_public_key,
        "encrypted_private_key": user.encrypted_private_key,
        "keystore_metadata": {
            "key_id": keystore.get("key_id"),
            "kdf_algorithm": (keystore.get("kdf") or {}).get("algorithm", "PBKDF2-HMAC-SHA256"),
            "kdf_iterations": (keystore.get("kdf") or {}).get("iterations", 480000),
            "salt": (keystore.get("kdf") or {}).get("salt", user.key_salt),
            "wrap_algorithm": (keystore.get("wrap") or {}).get("algorithm", "AES-GCM-256"),
            "nonce": (keystore.get("wrap") or {}).get("nonce", user.key_nonce),
            "wrap_version": keystore.get("wrap_version", 1),
            "lifecycle_state": getattr(user, "keystore_lifecycle_state", None) or "active",
        },
        "description": "Este archivo contiene tu llave privada cifrada. No la compartas y recuerda tu contraseña."
    }
    
    # Convertimos a bytes para enviarlo sin guardarlo en el disco del servidor
    identity_json = json.dumps(identity_data, indent=4)
    return send_file(
        io.BytesIO(identity_json.encode('utf-8')),
        as_attachment=True,
        download_name=f"identity_{user.username}.json",
        mimetype='application/json'
    )


@bp.route('/restore_identity', methods=['POST'])
def restore_identity():
    if 'usuario' not in session:
        return jsonify({"error": "No autenticado"}), 401

    if 'identity_file' not in request.files:
        return jsonify({"error": "No se encontró archivo de identidad."}), 400

    password = request.form.get("password")
    if not password:
        return jsonify({"error": "La contraseña es requerida para validar la identidad."}), 400

    file = request.files['identity_file']
    raw = file.read()
    if not raw:
        return jsonify({"error": "El archivo de identidad está vacío."}), 400

    try:
        identity_data = json.loads(raw.decode("utf-8"))
    except Exception:
        return jsonify({"error": "El archivo de identidad no es JSON válido."}), 400

    encrypted_private_key = identity_data.get("encrypted_private_key")
    if not encrypted_private_key:
        return jsonify({"error": "El archivo no contiene llave privada cifrada."}), 400

    if identity_data.get("username") != session.get("usuario"):
        return jsonify({"error": "El archivo de identidad no corresponde al usuario en sesión."}), 400

    enc_pub = identity_data.get("public_key")
    sign_pub = identity_data.get("signing_public_key")
    if not enc_pub or not sign_pub:
        return jsonify({"error": "El archivo de identidad no incluye llaves públicas completas."}), 400

    try:
        validate_identity_payload(
            encrypted_private_key,
            (identity_data.get("keystore_metadata") or {}).get("salt"),
            (identity_data.get("keystore_metadata") or {}).get("nonce"),
            password,
            expected_encryption_pub=enc_pub,
            expected_signing_pub=sign_pub,
        )
    except ValueError as err:
        return jsonify({"error": str(err)}), 400

    user = user_repository.find_by_username(session['usuario'])
    user.encrypted_private_key = encrypted_private_key
    user.key_salt = (identity_data.get("keystore_metadata") or {}).get("salt")
    user.key_nonce = (identity_data.get("keystore_metadata") or {}).get("nonce")
    user.public_key = enc_pub
    user.signing_public_key = sign_pub
    meta = identity_data.get("keystore_metadata") or {}
    if meta.get("lifecycle_state") in ("active", "rotated", "retired"):
        user.keystore_lifecycle_state = meta["lifecycle_state"]
    db.session.commit()
    return jsonify({"status": "success", "message": "Identidad restaurada correctamente."}), 200
