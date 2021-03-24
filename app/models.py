from datetime import datetime
from app import db
from app import valid

class User(db.Model):
    id = db.Column(Integer, primary_key=True)
    username = db.Column(String(64), index=True, unique=True)
    password = db.Column(String(128))
    uid = db.Column(String(256))

    def __repr__(self):
        return '<User {}>'.format(self.username)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(128), index=True, unique=True)
    body = db.Column(db.String(440))

    def __repr__(self):
        return '<Post {}>'.format(self.body)
