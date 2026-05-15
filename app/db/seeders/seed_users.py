"""
Default users for `flask ... init-db`.

These are only bootstrap credentials for local/dev/testing; replace them for production.
"""

from typing import TypedDict


class SeedUser(TypedDict):
    u: str
    p: str


DEFAULT_USERS: list[SeedUser] = [
    {"u": "admin", "p": "secreto123"},
    {"u": "trustee1", "p": "clave1"},
    {"u": "trustee2", "p": "clave2"},
    {"u": "notrustee", "p": "clave3"},
]


def seed_default_users() -> list[SeedUser]:
    return DEFAULT_USERS

