# Matriz de Trazabilidad D6

Este documento mapea los requerimientos de D6 con puntos de implementación, pruebas automatizadas y documentación de soporte.

## 1) Matriz Requerimiento-Evidencia

| Requerimiento D6 | Evidencia de Implementación | Evidencia de Prueba | Evidencia de Documentación |
|---|---|---|---|
| Llaves privadas cifradas en reposo | `app/crypto_d6.py` `wrap_private_key()` almacena solo material de llave privada cifrada | `tests/test_key_management.py::test_keystore_correct_password_succeeds` | Esta matriz + requerimientos de seguridad en `README.md` |
| Desbloqueo por llave derivada de contraseña | `app/crypto_d6.py` `derive_key_from_password()` + unwrap en flujos de upload/release/restore de `app/routes.py` | `test_keystore_correct_password_succeeds`, `test_keystore_wrong_password_fails` | Esta matriz, sección de ciclo de vida abajo |
| Formato estructurado de keystore | `app/crypto_d6.py` incluye `kdf`, `wrap`, `key_id`, `wrap_version` | `test_keystore_correct_password_succeeds` valida presencia de metadata | Esta matriz |
| Comportamiento seguro ante manipulación | Validación de tag AES-GCM en `unwrap_private_key()` produce fallo seguro | `test_modified_keystore_fails` | Esta matriz |
| Backup/restore seguro | `GET /download_identity` + `POST /restore_identity` en `app/routes.py` | `test_backup_restore_identity_succeeds` | Esta matriz |
| Keystore robado por sí solo no descifra | No existe bypass por contraseña; unwrap requiere contraseña válida | `test_stolen_keystore_alone_cannot_decrypt` | Sección de alineación con threat model abajo |
| Política de trustees min-2 + consistencia de threshold | `app/routes.py` valida mínimo 2 trustees activos y consistencia del threshold en upload/release | `tests/test_baseline_flows.py::test_upload_requires_at_least_two_selected_trustees`, `test_recovery_blocked_when_trustee_policy_becomes_invalid` | Esta matriz |
| Autorización de trustees basada en relación | `app/routes.py` valida membresía activa `VaultTrustee` en dashboard/release | `tests/test_baseline_flows.py::test_trustee_release_threshold_reconstruction_flow` | Sección de notas de arquitectura abajo |

## 2) Actualización de Notas de Arquitectura (User unificado + Auth por relación)

- La identidad se unifica bajo `User`.
- Cada bóveda pertenece a un solo `User` mediante `Vault.owner_user_id`.
- La membresía de trustee es explícita en `VaultTrustee` (`vault_id`, `trustee_user_id`, `status`).
- Las acciones de trustees se autorizan por membresía activa, no por flags globales de rol.
- La recuperación opera sobre shares atados a membresía (`Share.vault_trustee_id`) y está restringida por consistencia de política.

## 3) Ciclo de Vida de Llaves y Respuesta a Compromiso

- **Generada**: Durante registro (`/register`) o inicialización (`init-db`), se crean llaves de cifrado/firma y se envuelven en material de keystore cifrado.
- **Activa**: Una llave está activa cuando se requiere para descifrar/firmar y solo después de unwrap con contraseña en tiempo de solicitud.
- **Rotada**: Operación conceptual para futuras renovaciones de trustees/llaves; el código actual mantiene compatibilidad con campo de ciclo de vida (`lifecycle_state` en metadata exportada).
- **Revocada/Comprometida**: Las membresías de trustees pueden marcarse no activas (`VaultTrustee.status`) y la recuperación se bloquea si se rompen las invariantes de política.

Respuesta ante compromiso:
- Si se sospecha compromiso del backup de identidad, debe cambiarse contraseña y reemitir llaves.
- Un keystore cifrado robado sin contraseña no debe permitir recuperación de llaves.
- Material de keystore manipulado falla durante unwrap autenticado.

## 4) Alineación con Threat Model para D6

- **Keystore robado**: el atacante obtiene blob cifrado pero no puede hacer unwrap sin KEK derivada de contraseña.
- **Contraseña débil**: persiste riesgo residual; la seguridad depende de la fortaleza de contraseña pese al endurecimiento de iteraciones PBKDF2.
- **Compromiso de dispositivo**: fuera de alcance si el host está totalmente comprometido; el atacante puede capturar la contraseña al ingresarla.

## 5) Riesgos Residuales y Límites

- La fortaleza de contraseña depende del usuario.
- No hay almacenamiento de llaves respaldado por hardware en la implementación actual.
- Aún no existe flujo automatizado completo de rotación de llaves (solo semántica de ciclo de vida y controles de política).
