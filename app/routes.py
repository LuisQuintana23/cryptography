from flask import Blueprint, render_template, request, redirect, url_for, session, send_file, current_app, jsonify, flash
import io, os, ecies, json, time
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature, InvalidTag
# Importaciones locales 
from extensions import db
from models import User, Document, Share
from utils import create_shares, reconstruct_key
from crypto_d3 import SecureVaultHybridCrypto 
from crypto_d2 import SecureVaultCrypto
from crypto_d5_signatures import SecureVaultSignedCrypto

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
    trustees = User.query.filter(
        User.id != owner.id,
        User.is_trustee == True
    ).all()

    if request.method == 'POST':
        if 'file' not in request.files:
            return jsonify({"error": "No se detectó ningún archivo"}), 400
            
        file = request.files['file']
        if file.filename == '':
            return jsonify({"error": "No se seleccionó ningún archivo"}), 400

        # Se solicita contraseña para desbloquear la fimra (Ed25519)
        password = request.form.get('password')
        if not password:
            return jsonify({"error": "Se requiere tu contraseña para firmar el documento."}), 400
        
        try:
            # Desbloquear el llavero privado del owner
            crypto_sym = SecureVaultCrypto()
            try:
                unwrapped_keystore = crypto_sym.unwrap_private_key(
                    owner.encrypted_private_key, 
                    owner.key_salt, 
                    owner.key_nonce, 
                    password
                )
                # Separar llave de cifrado (secp256k1) y llave de firma (Ed25519)
                owner_enc_priv, owner_sign_priv = unwrapped_keystore.split(':')
            except ValueError:
                return jsonify({"error": "Contraseña incorrecta. No se pudo autorizar la firma."}), 401
            
            plaintext = file.read()
            filename = secure_filename(file.filename)
            
            # Generar llaves y nonces simétricos (D5 logic)
            vault_signed = SecureVaultSignedCrypto()
            file_key = vault_signed.generate_symmetric_key()
            nonce = vault_signed.generate_nonce()
            aesgcm = AESGCM(file_key)
            
            # Dividir llave (Shamir) y cifrar fragmentos para fiduciarios
            total_shares = len(trustees)
            if total_shares < 2:
                return jsonify({"error": "Se requieren al menos 2 fiduciarios."}), 400
                
            threshold = (total_shares // 2) + 1
            shares = create_shares(file_key, threshold, total_shares)

            recipients_data = []
            for i, trustee in enumerate(trustees):
                share_string = shares[i]
                # Ciframos el fragmento con la llave pública de CIFRADO del trustee
                encrypted_share = ecies.encrypt(trustee.public_key, share_string.encode('utf-8'))
                
                recipients_data.append({
                    "id": trustee.public_key, # Usamos la pubkey como ID para coincidir con D5
                    "trustee_id": trustee.id,
                    "trustee_username": trustee.username,
                    "encrypted_share": encrypted_share.hex() # Se guarda el fragmento de Shamir
                })

            # Empaquetar Metadatos y Crear AAD
            metadata = {
                "filename": filename,
                "nonce": nonce.hex(),
                "symmetric_algorithm": "AES-GCM-256",
                "asymmetric_algorithm": "ECIES-secp256k1",
                "signature_algorithm": "Ed25519",
                "creation_timestamp": time.time()
            }

            aad_dict = {"metadata": metadata, "recipients": recipients_data}
            aad = json.dumps(aad_dict, sort_keys=True).encode('utf-8')

            # Cifrado final del archivo
            ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, aad)
            ciphertext = ciphertext_with_tag[:-16]
            tag = ciphertext_with_tag[-16:]

            # Construir contenedor base
            vault_container = {
                "metadata": metadata,
                "recipients": recipients_data,
                "ciphertext": ciphertext.hex(),
                "tag": tag.hex()
            }

            # FIRMAR EL CONTENEDOR (D5)
            data_to_sign = vault_signed._get_data_to_sign(vault_container)
            priv_key_obj = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(owner_sign_priv))
            signature = priv_key_obj.sign(data_to_sign)

            vault_container["signature"] = signature.hex()
            vault_container["signer_id"] = owner.signing_public_key

            vault_filename = f"{filename}.vault"
            storage_path = os.path.join(current_app.config['UPLOAD_FOLDER'], vault_filename)
            
            new_doc = Document(
                owner_id=owner.id,
                filename=filename,
                storage_path=storage_path,
                nonce=nonce.hex(),
                aad=aad.hex() 
            )
            db.session.add(new_doc)
            db.session.flush()

            # Guardar fragmentos en la BD
            for recipient in recipients_data:
                new_share = Share(
                    document_id=new_doc.id,
                    trustee_id=recipient["trustee_id"],
                    encrypted_fragment=recipient["encrypted_share"]
                )
                db.session.add(new_share)

            with open(storage_path, "w", encoding="utf-8") as f:
                json.dump(vault_container, f, indent=4)
                
            db.session.commit()
            return jsonify({
                "status": "success", 
                "message": "El documento ha sido cifrado, firmado digitalmente y sellado correctamente."
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

# Release para desbloquear documento
@bp.route('/release/<int:share_id>', methods=['GET', 'POST'])
def release_share(share_id):
    if 'usuario' not in session:
        return redirect(url_for('main.login'))

    user = User.query.filter_by(username=session['usuario']).first()
    share = Share.query.get_or_404(share_id)
    doc = share.document

    if share.trustee_id != user.id:
        return "Acceso denegado", 403

    if request.method == 'POST':
        password = request.form['password']
        crypto_sym = SecureVaultCrypto()
        vault_signed = SecureVaultSignedCrypto()
        
        try:
            # Desbloquear el Llavero Privado del Fiduciario
            unwrapped_keystore = crypto_sym.unwrap_private_key(
                user.encrypted_private_key, 
                user.key_salt, 
                user.key_nonce, 
                password
            )
            # El fiduciario usa su llave de cifrado (secp256k1) para descifrar el fragmento
            trustee_enc_priv, _ = unwrapped_keystore.split(':')
            
            # Descifrar el fragmento de Shamir usando ECIES
            encrypted_frag_bytes = bytes.fromhex(share.encrypted_fragment)
            plain_frag_bytes = ecies.decrypt(trustee_enc_priv, encrypted_frag_bytes)
            
            # Guardar el fragmento liberado en la BD
            share.plain_fragment = plain_frag_bytes.decode('utf-8')
            db.session.commit()
            
            # Verificar umbral
            total_shares_count = Share.query.filter_by(document_id=doc.id).count()
            threshold = (total_shares_count // 2) + 1
            liberados = Share.query.filter(Share.document_id == doc.id, Share.plain_fragment != None).all()
            
            if len(liberados) >= threshold:
                # Leer el contenedor
                with open(doc.storage_path, "r", encoding="utf-8") as f:
                    vault_container = json.load(f)
                
                # Verificación de firma digital (Antes de descifrar)
                if "signature" not in vault_container or "signer_id" not in vault_container:
                    return jsonify({"error": "Rechazado: El contenedor carece de firma digital."}), 400
                    
                data_to_verify = vault_signed._get_data_to_sign(vault_container)
                try:
                    pub_key_obj = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(vault_container["signer_id"]))
                    pub_key_obj.verify(bytes.fromhex(vault_container["signature"]), data_to_verify)
                except InvalidSignature:
                    return jsonify({"error": "ALERTA: Firma digital inválida. El documento ha sido modificado o falsificado."}), 400
                
                # Reconstruir llave y descifrar (Flujo Seguro)
                shares_list = [s.plain_fragment for s in liberados]
                file_key = reconstruct_key(shares_list)
                
                nonce = bytes.fromhex(vault_container["metadata"]["nonce"])
                aad_dict = {"metadata": vault_container["metadata"], "recipients": vault_container["recipients"]}
                aad = json.dumps(aad_dict, sort_keys=True).encode('utf-8')
                ciphertext_with_tag = bytes.fromhex(vault_container["ciphertext"]) + bytes.fromhex(vault_container["tag"])
                
                aesgcm = AESGCM(file_key)
                try:
                    plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, aad)
                except InvalidTag:
                    return jsonify({"error": "ALERTA: Integridad simétrica comprometida."}), 400
                
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
                mensaje = f"Firma válida. Se han reunido {len(liberados)} de {threshold} tokens necesarios."
                return jsonify({"status": "success", "message": mensaje}), 200
                
        except ValueError as e:
            # SI LA CONTRASEÑA ES INCORRECTA, RETORNAMOS UN ERROR JSON
            return jsonify({"error": f"Error criptográfico o contraseña incorrecta: {str(e)}"}), 400
        except Exception as e:
            return jsonify({"error": f"Error interno: {str(e)}"}), 500

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
