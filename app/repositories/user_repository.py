from db.models import User


class UserRepository:
    def find_by_username(self, username: str):
        return User.query.filter_by(username=username).first()

    def find_by_id(self, user_id: int):
        return User.query.filter_by(id=user_id).first()

    def list_other_users(self, user_id: int):
        return User.query.filter(User.id != user_id).all()

    def find_by_ids(self, user_ids: list[int]):
        return User.query.filter(User.id.in_(user_ids)).all()

    def find_by_username_case_insensitive_excluding_user(self, username: str, exclude_user_id: int):
        return User.query.filter(User.id != exclude_user_id, User.username.ilike(username)).first()

    def add(self, db, user: User):
        db.session.add(user)
