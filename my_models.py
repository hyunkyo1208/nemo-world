from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime, timezone

db = SQLAlchemy()

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    userid = db.Column(db.String(80), unique=True, nullable=False)
    username = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    avatar = db.Column(db.String(255))
    avatar_color = db.Column(db.String(7))
    avatar_filename = db.Column(db.String(255), default="character ENFJ.svg")

    my_questions = db.relationship('Question', foreign_keys='Question.user_id', backref='author', lazy=True)
    received_questions = db.relationship('Question', foreign_keys='Question.friend_id', backref='receiver', lazy=True)

class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    question_text = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    friend_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    answer_text = db.Column(db.Text, nullable=True)
    is_read = db.Column(db.Boolean, default=False)
    is_private = db.Column(db.Boolean, default=False)

class Friendship(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # 요청 보낸 사람
    friend_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # 요청 받은 사람
    status = db.Column(db.String(20), default='pending')  # 'pending', 'accepted', 'rejected'
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    __table_args__ = (db.UniqueConstraint('user_id', 'friend_id', name='unique_friendship'),)

class Visit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    profile_user_id = db.Column(db.Integer, nullable=False)
    visitor_id = db.Column(db.Integer, nullable=False)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

class LetterBlock(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    is_read = db.Column(db.Boolean, default=False)
    is_public = db.Column(db.Boolean, default=False)
    is_anonymous = db.Column(db.Boolean, default=False)

    color = db.Column(db.String(7), nullable=False)
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    # ✅ 관계 추가
    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_letters')
    receiver = db.relationship('User', foreign_keys=[receiver_id], backref='received_letters')

    comment = db.Column(db.Text, nullable=True)


