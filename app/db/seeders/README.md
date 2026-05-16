# Seeders

This folder contains bootstrap logic for creating initial data in local/dev/testing.

## Default users

`app/db/seeders/seed_users.py` defines the default users used by the Flask CLI command:

- `flask --app app/app.py init-db`

`init-db` calls `seed_default_users()` and registers:

- `admin` / `secreto123`
- `trustee1` / `clave1`
- `trustee2` / `clave2`
- `notrustee` / `clave3`
