# Matriz de Trazabilidad D6

Este documento mapea los requerimientos de D6 con puntos de implementación, pruebas automatizadas y documentación de soporte.

## 1) Matriz Requerimiento-Evidencia

| Requerimiento D6 | Evidencia de Implementación | Evidencia de Prueba | Evidencia de Documentación |
|---|---|---|---|
| Llaves privadas cifradas en reposo | `crypto/crypto_d6.py` `wrap_private_key()` almacena solo material de llave privada cifrada | `tests/test_crypto_d6_unit.py::test_wrap_unwrap_roundtrip_and_keystore_shape` (aislado, sin app) | Esta matriz + requerimientos de seguridad en `README.md` |
| Desbloqueo por llave derivada de contraseña | `crypto/crypto_d6.py` `derive_key_from_password()` + unwrap en flujos de upload/release/restore de `app/routes.py` | `test_crypto_d6_unit.py::test_wrap_unwrap_roundtrip_and_keystore_shape`, `test_wrong_password_fails` | Esta matriz, sección de ciclo de vida abajo |
| Formato estructurado de keystore | `crypto/crypto_d6.py` incluye `kdf`, `wrap`, `key_id`, `wrap_version` | `test_wrap_unwrap_roundtrip_and_keystore_shape` valida metadata | Esta matriz |
| Identidad de llave sin ambigüedad (privadas ↔ públicas) | `crypto/crypto_d6.py` `assert_private_keys_match_public_identity()` + `app/services/keystore_service.py` | Unit: `test_crypto_d6_unit.py::test_assert_private_keys_match_*`; integración: `test_key_management.py::test_restore_rejects_mismatched_public_keys` | §3 ciclo de vida |
| Comportamiento seguro ante manipulación | Validación de tag AES-GCM en `unwrap_private_key()` produce fallo seguro | `test_crypto_d6_unit.py::test_modified_ciphertext_fails` | Esta matriz |
| Backup/restore seguro | `GET /download_identity` + `POST /restore_identity` en `app/routes.py` | `tests/test_key_management.py::test_backup_restore_identity_succeeds` | Esta matriz |
| Keystore robado por sí solo no descifra | No existe bypass por contraseña; unwrap requiere contraseña válida | `test_crypto_d6_unit.py::test_stolen_keystore_blob_wrong_password_cannot_decrypt`, `test_unwrap_requires_password` | Sección de alineación con threat model abajo |
| Rotación mínima de credenciales (mismo par, nuevo wrap) | `app/services/auth_service.py` `rotate_user_vault_credentials` + CLI `rotate-user-credentials` (sin ruta HTTP para reducir superficie) | `test_rotate_vault_credentials_updates_login_and_keystore` | §3 abajo |
| Política de trustees min-2 + consistencia de threshold | `app/routes.py` valida mínimo 2 trustees activos y consistencia del threshold en upload/release | `tests/test_baseline_flows.py::test_upload_requires_at_least_two_selected_trustees`, `test_recovery_blocked_when_trustee_policy_becomes_invalid` | Esta matriz |
| Autorización de trustees basada en relación | `app/routes.py` valida membresía activa `VaultTrustee` en dashboard/release | `tests/test_baseline_flows.py::test_trustee_release_threshold_reconstruction_flow` | Sección de notas de arquitectura abajo |

## 2) Actualización de Notas de Arquitectura (User unificado + Auth por relación)

- **`crypto/crypto_d6.py`** no importa Flask ni `app/`; las pruebas unitarias de cripto viven en `tests/test_crypto_d6_unit.py` y se ejecutan con `pytest tests/test_crypto_d6_unit.py` o `pytest -m "not integration"` (sin levantar la app).
- Flujo E2E con seeds (`admin`, `trustee1`, `trustee2`, `notrustee`): `tests/test_e2e_seeded_vault_flow.py`.
- La identidad se unifica bajo `User`.
- Cada bóveda pertenece a un solo `User` mediante `Vault.owner_user_id`.
- La membresía de trustee es explícita en `VaultTrustee` (`vault_id`, `trustee_user_id`, `status`).
- Las acciones de trustees se autorizan por membresía activa, no por flags globales de rol.
- La recuperación opera sobre shares atados a membresía (`Share.vault_trustee_id`) y está restringida por consistencia de política.

## 3) Ciclo de Vida de Llaves y Respuesta a Compromiso

- **Generada**: Durante registro (`/register`) o inicialización (`init-db`), se crean llaves de cifrado/firma y se envuelven en material de keystore cifrado.
- **Activa**: Una llave está activa cuando se requiere para descifrar/firmar y solo después de unwrap con contraseña en tiempo de solicitud.
- **Rotada**: `rotate_user_vault_credentials` (solo uso programático o CLI `flask rotate-user-credentials`) re-envuelve el mismo material con nueva contraseña y marca `User.keystore_lifecycle_state` / metadata exportada como `rotated` (deliberadamente sin endpoint web).
- **Revocada/Comprometida**: Las membresías de trustees pueden marcarse no activas (`VaultTrustee.status`) y la recuperación se bloquea si se rompen las invariantes de política.

Respuesta ante compromiso:
- Si se sospecha compromiso del backup de identidad, debe cambiarse contraseña y reemitir llaves.
- Un keystore cifrado robado sin contraseña no debe permitir recuperación de llaves.
- Material de keystore manipulado falla durante unwrap autenticado.

## 4) Alineación con Threat Model para D6

- **Keystore robado**: el atacante obtiene blob cifrado pero no puede hacer unwrap sin KEK derivada de contraseña.
- **Compromiso de dispositivo**: fuera de alcance si el host está totalmente comprometido; el atacante puede capturar la contraseña al ingresarla.
