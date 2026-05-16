from db.models import Document


class DocumentRepository:
    def create_document(self, db, **kwargs):
        document = Document(**kwargs)
        db.session.add(document)
        db.session.flush()
        return document

    def get_or_404(self, db, doc_id: int):
        return db.get_or_404(Document, doc_id)

    def latest(self):
        return Document.query.order_by(Document.id.desc()).first()
