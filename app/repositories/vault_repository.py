from db.models import Vault, VaultTrustee


class VaultRepository:
    def create_vault(self, db, owner_user_id: int, threshold: int, status: str = "active"):
        vault = Vault(owner_user_id=owner_user_id, threshold=threshold, status=status)
        db.session.add(vault)
        db.session.flush()
        return vault

    def add_trustee_membership(self, db, vault_id: int, trustee_user_id: int, status: str = "active"):
        membership = VaultTrustee(vault_id=vault_id, trustee_user_id=trustee_user_id, status=status)
        db.session.add(membership)
        db.session.flush()
        return membership

    def find_active_membership(self, vault_trustee_id: int, trustee_user_id: int):
        return VaultTrustee.query.filter_by(id=vault_trustee_id, trustee_user_id=trustee_user_id, status="active").first()

    def count_active_trustees(self, vault_id: int):
        return VaultTrustee.query.filter_by(vault_id=vault_id, status="active").count()
