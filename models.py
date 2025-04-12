from flask_sqlalchemy import SQLAlchemy
db = SQLAlchemy()
from datetime import datetime

class Video(db.Model):
    __tablename__ = 'videos'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    quiz_text = db.Column(db.Text)

    # リレーション（Userモデルがある場合）
    user = db.relationship('User', backref=db.backref('videos', lazy=True))
