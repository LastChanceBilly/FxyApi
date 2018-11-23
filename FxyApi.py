from flask import Flask
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)

#Get API key
key = ' '
with open("../keys/FxyApi.key") as f:
    key = f.readline()
app.config['SECRET_KEY'] = key

#Database configuration
db_path = 'sqlite:FxyAPI.db'
app.config['SQLALCHEMY_DATABASE_URI'] = db_path

db = SQLAlchemy(app)

class user(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(50))
    admin = db.Column(db.Boolean)

    posts = db.relationship('post', backref='usr', lazy=True)

class post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(50))
    content = db.Column(db.String(400))
    user_id = db.Column(db.Integer, db.ForeignKey('usr.id'))

