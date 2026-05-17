from db.models import Share, VaultTrustee


class ShareRepository:
    def add_share(self, db, **kwargs):
        share = Share(**kwargs)
        db.session.add(share)
        return share

    def get_or_404(self, db, share_id: int):
        return db.get_or_404(Share, share_id)

    def list_active_for_trustee(self, trustee_user_id: int):
        return (
            Share.query.join(VaultTrustee, Share.vault_trustee_id == VaultTrustee.id)
            .filter(
                Share.trustee_user_id == trustee_user_id,
                VaultTrustee.trustee_user_id == trustee_user_id,
                VaultTrustee.status == "active",
            )
            .all()
        )

    def list_released_for_document(self, document_id: int):
        return Share.query.filter(Share.document_id == document_id, Share.plain_fragment != None).all()
