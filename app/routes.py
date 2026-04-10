from flask import Blueprint, render_template, request, redirect, url_for, session, send_file, current_app, jsonify
import io, os, ecies, json
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask import Blueprint, render_template, request, redirect, url_for, session, send_file, current_app, flash
# Importaciones locales 
from extensions import db
from models import User, Document, Share
from utils import create_shares, reconstruct_key
from crypto_d3 import SecureVaultHybridCrypto 
from crypto_d2 import SecureVaultCrypto

# Blueprint
bp = Blueprint('main', __name__)

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

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password_hash, password):
            session['usuario'] = user.username
            return redirect(url_for('main.dashboard'))
        else:
            error = "Credenciales inválidas. Inténtalo de nuevo."

    return render_template('login.html', error=error)

@bp.route('/dashboard')
def dashboard():
    if 'usuario' not in session:
        return redirect(url_for('main.login'))
    
    user = User.query.filter_by(username=session['usuario']).first()
    
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
        
    owner = User.query.filter_by(username=session['usuario']).first()
    trustees = User.query.filter(User.id != owner.id).all()

    if request.method == 'POST':
        if 'file' not in request.files:
            return jsonify({"error": "No se detectó ningún archivo"}), 400
            
        file = request.files['file']
        if file.filename == '':
            return jsonify({"error": "No se seleccionó ningún archivo"}), 400

        try:

            plaintext = file.read()
            filename = secure_filename(file.filename)
            
            # Cifrar con D2
            crypto_sym = SecureVaultCrypto()
            file_key, nonce, ciphertext, aad = crypto_sym.encrypt_file(plaintext, filename)
            
            # Guardar en Base de Datos (solo metadatos básicos para la UI)
            vault_filename = f"{filename}.vault"
            storage_path = os.path.join(current_app.config['UPLOAD_FOLDER'], vault_filename)
            
            new_doc = Document(
                owner_id=owner.id,
                filename=filename,
                storage_path=storage_path,
                # Ya no es estrictamente necesario guardar nonce y aad en la BD, 
                # pero los dejamos por si acaso.
                nonce=nonce.hex(),
                aad=aad.hex() if isinstance(aad, bytes) else aad 
            )
            db.session.add(new_doc)
            db.session.flush()

            # Dividir llave (Shamir)
            total_shares = len(trustees)
            if total_shares < 2:
                return "Se requieren al menos 2 fiduciarios.", 400
                
            threshold = (total_shares // 2) + 1
            shares = create_shares(file_key, threshold, total_shares)

            # Repartir fragmentos y armar el JSON del contenedor
            recipients_data = []
            for i, trustee in enumerate(trustees):
                share_string = shares[i]
                encrypted_share = ecies.encrypt(trustee.public_key, share_string.encode('utf-8'))
                
                # Guardamos en la BD
                new_share = Share(
                    document_id=new_doc.id,
                    trustee_id=trustee.id,
                    encrypted_fragment=encrypted_share.hex()
                )
                db.session.add(new_share)
                
                # Añadimos al JSON
                recipients_data.append({
                    "trustee_id": trustee.id,
                    "trustee_username": trustee.username,
                    "encrypted_share": encrypted_share.hex()
                })

            # Escribir el contenedor portátil (.vault)
            vault_container = {
                "metadata": {
                    "filename": filename,
                    "nonce": nonce.hex(),
                    "aad": aad.hex() if isinstance(aad, bytes) else aad,
                    "algorithm": "AES-GCM-256 + Shamir + ECIES"
                },
                "recipients": recipients_data,
                "ciphertext": ciphertext.hex() # Se guarda en hexadecimal para ser compatible con JSON
            }

            with open(storage_path, "w", encoding="utf-8") as f:
                json.dump(vault_container, f, indent=4)
            db.session.commit()
            return jsonify({
                "status": "success", 
                "message": "El documento ha sido cifrado y la bóveda sellada correctamente."
            }), 200

        except Exception as e:
            db.session.rollback()
            return jsonify({"error": f"Error criptográfico: {str(e)}"}), 500
    return render_template('upload_file.html', trustees_count=len(trustees))

# Lógica de liberación y decifrado para los usuarios trusted
@bp.route('/trustee_dashboard')
def trustee_dashboard():
    if 'usuario' not in session:
        return redirect(url_for('main.login'))
        
    user = User.query.filter_by(username=session['usuario']).first()
    
    # Buscar todos los fragmentos asignados a este fiduciario
    mis_shares = Share.query.filter_by(trustee_id=user.id).all()
    
    return render_template('trustee_dashboard.html', shares=mis_shares)

@bp.route('/release/<int:share_id>', methods=['GET', 'POST'])
def release_share(share_id):
    if 'usuario' not in session:
        return redirect(url_for('main.login'))

    user = User.query.filter_by(username=session['usuario']).first()
    share = Share.query.get_or_404(share_id)
    doc = share.document

    # Verificamos que el fragmento realmente le pertenezca
    if share.trustee_id != user.id:
        return "Acceso denegado", 403

    if request.method == 'POST':
        password = request.form['password']
        crypto_sym = SecureVaultCrypto()
        
        try:
            # Desbloquear llave privada del fiduciario
            priv_hex = crypto_sym.unwrap_private_key(
                user.encrypted_private_key, 
                user.key_salt, 
                user.key_nonce, 
                password
            )
            
            # Descifrar el fragmento de Shamir usando ECIES
            encrypted_frag_bytes = bytes.fromhex(share.encrypted_fragment)
            plain_frag_bytes = ecies.decrypt(priv_hex, encrypted_frag_bytes)
            
            # Guardar el fragmento liberado en la BD
            share.plain_fragment = plain_frag_bytes.decode('utf-8')
            db.session.commit()
            
            # Verificar umbral
            total_shares_count = Share.query.filter_by(document_id=doc.id).count()
            threshold = (total_shares_count // 2) + 1
            
            liberados = Share.query.filter(Share.document_id == doc.id, Share.plain_fragment != None).all()
            
            if len(liberados) >= threshold:
                # Reconstruir y descifrar
                shares_list = [s.plain_fragment for s in liberados]
                file_key = reconstruct_key(shares_list)
                
                with open(doc.storage_path, "r", encoding="utf-8") as f:
                    vault_container = json.load(f)
                    
                file_nonce = bytes.fromhex(vault_container["metadata"]["nonce"])
                file_aad = bytes.fromhex(vault_container["metadata"]["aad"])
                ciphertext = bytes.fromhex(vault_container["ciphertext"])
                
                plaintext = crypto_sym.decrypt_file(file_key, file_nonce, ciphertext, file_aad)
                
                original_filename = vault_container["metadata"]["filename"]
                
                # Retornar el archivo
                return send_file(
                    io.BytesIO(plaintext),
                    as_attachment=True,
                    download_name=original_filename,
                    mimetype='application/octet-stream'
                )
            else:
                # Si faltanm tokens regresa json
                mensaje = f"Se han reunido {len(liberados)} de {threshold} tokens necesarios."
                return jsonify({"status": "success", "message": mensaje}), 200
                
        except Exception as e:
            # SI LA CONTRASEÑA ES INCORRECTA, RETORNAMOS UN ERROR JSON
            return jsonify({"error": "Error criptográfico o contraseña incorrecta."}), 400

    return render_template('release.html', document=doc)

# --- Ruta para descargar el archivo .vault (Para el Dueño) ---
@bp.route('/download_vault/<int:doc_id>')
def download_vault(doc_id):
    if 'usuario' not in session:
        return redirect(url_for('main.login'))
        
    user = User.query.filter_by(username=session['usuario']).first()
    doc = Document.query.get_or_404(doc_id)
    
    if doc.owner_id != user.id:
        return "No tienes permiso para descargar este archivo", 403
        
    return send_file(doc.storage_path, as_attachment=True)

# --- Ruta para descargar la Identidad Digital (Para todos los usuarios) ---
@bp.route('/download_identity')
def download_identity():
    if 'usuario' not in session:
        return redirect(url_for('main.login'))
        
    user = User.query.filter_by(username=session['usuario']).first()
    
    # Creamos un archivo de identidad portable
    identity_data = {
        "username": user.username,
        "public_key": user.public_key,
        "encrypted_private_key": user.encrypted_private_key,
        "key_salt": user.key_salt,
        "key_nonce": user.key_nonce,
        "kdf_iterations": 480000,
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
