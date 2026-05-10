
## Quickstart (current implementation)
This repo contains a working Flask app under `app/` that seals documents into a portable `.vault` container and enforces a **50% + 1** trustee release threshold to recover the plaintext.

### Run the web app
```sh
python -m venv .venv
source ./.venv/bin/activate
pip install -r requirements.txt
flask --app app init-db
python app.py
```
### Test users (created by `init-db`)
- **Owner**: `admin` / `secreto123`
- **Trustees**: `trustee1` / `clave1`, `trustee2` / `clave2`

### End-to-end flow
- **Owner**: login → “Sellar Nuevo Documento” (`/upload`) → generates a `.vault` JSON in `app/vault_storage/` and assigns encrypted Shamir shares to trustees.
- **Trustee**: login → “Panel de Fiduciario” → “Liberar mi Token” (`/release/<share_id>`) → once threshold is met, the server reconstructs the file key and returns the decrypted file as a download.
- **Owner/Trustee**: can download an **identity file** (`/download_identity`) containing the public key plus the **password-wrapped private key** needed for offline recovery.

### Architecture diagram (Mermaid)
See `app/architecture.mermaid` for the app-level architecture used by the implementation.

### Baseline regression tests
Run the baseline regression suite before schema/auth refactors:
```sh
pytest tests/test_baseline_flows.py -q
```
