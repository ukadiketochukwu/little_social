
from flask import session
from flask_login import UserMixin
from social import db, login_manager, app
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from datetime import datetime

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.before_request
def make_session_permanent():
    session.permanent = True


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String())
    profile_pic = db.Column(
        db.String(40), nullable=False, default='default.jpg')
    posts = db.relationship('Post', backref='author', lazy='dynamic')
    commenter = db.relationship('Comment', backref='commenter', lazy='dynamic')
    access_token = db.Column(db.String(180))
    liker = db.relationship('Like', backref='liker', lazy='dynamic')
    followed = db.relationship(
        'Follower', backref='followed', foreign_keys='Follower.followed_id', lazy='dynamic')
    follower = db.relationship(
        'Follower', backref='follower', foreign_keys='Follower.follower_id', lazy='dynamic')
    sender = db.relationship('Message', backref='sender',
                             foreign_keys='Message.sender_id', lazy='dynamic')
    receiver = db.relationship('Message', backref='receiver',
                               foreign_keys='Message.receiver_id', lazy='dynamic')
    bio_content = db.Column(db.String(1000))
    verified = db.Column(db.Boolean(), default=False)

    def has_liked_post(self, post):
        return Like.query.filter(
            Like.liker_id == self.id,
            Like.liked_id == post.id).count() > 0

    def has_followed_user(self, user):
        return Follower.query.filter(
            Follower.follower_id == self.id,
            Follower.followed_id == user.id).count() > 0

    def get_reset_token(self, expires_sec=1800):
        s = Serializer(app.config['SECRET_KEY'], expires_sec)
        return s.dumps({'user_id': self.id}).decode('utf-8')

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
        except:
            return None
        return User.query.get(user_id)





class Post(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    post_title = db.Column(db.String(100), nullable=False)
    post_content = db.Column(db.String(1000), nullable=False)
    post_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    commented = db.relationship('Comment', backref='commented', lazy='dynamic')
    likes = db.relationship('Like', backref='liked', lazy='dynamic')


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    commented_id = db.Column(db.Integer, db.ForeignKey('post.id'))
    commenter_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    comment_body = db.Column(db.String(100))


class Like(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    liked_id = db.Column(db.Integer, db.ForeignKey('post.id'))
    liker_id = db.Column(db.Integer, db.ForeignKey('user.id'))


class Follower(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    followed_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    follower_id = db.Column(db.Integer, db.ForeignKey('user.id'))


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    room = db.Column(db.String(), nullable=False)
    message = db.Column(db.String(), nullable=False)
    time = db.Column(db.String(), nullable=False)
    message_time = db.Column(
        db.DateTime())
    read = db.Column(db.Boolean())
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'))