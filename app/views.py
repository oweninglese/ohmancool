###############################################################################
##################################imports######################################
###############################################################################

from flask import Flask
from flask import render_template, request, redirect, url_for, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager
from flask_login import current_user, login_user, login_required, logout_user
import hmac, re, hashlib, random
import os
from sqlalchemy import Column, Integer, String, ForeignKey, Date
import json
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired
import sqlite3

###############################################################################
##################################forms######################################
###############################################################################

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Sign in')

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Register')

class ArticleForm(FlaskForm):
    title  = StringField('Subject', validators=[DataRequired()])
    body  = StringField('Content', validators=[DataRequired()])
    submit = SubmitField('Submit')

###############################################################################
##################################regex######################################
###############################################################################

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,30}$")
EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
PASS_RE = re.compile(r"^.{3,20}$")
letters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'

def valid_username(username):
    return username and USER_RE.match(username)
def valid_password(password):
    return password and PASS_RE.match(password)
def valid_email(email):
    return EMAIL_RE.match(email)

###############################################################################
##################################config#######################################
###############################################################################

class Config(object):
    SECRET_KEY = os.environ.get('PORTFOLIO_KEY') or 'guess-what-this-98'

login = LoginManager()

app = Flask(__name__)
app.config.from_object(Config)

base_dir = os.path.abspath(os.path.dirname(__file__))

###############################################################################
##################################database#####################################
###############################################################################

db_path = os.path.join(base_dir, 'DATABASE.db')
database = db_path
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///DATABASE.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
db.init_app(app)


@app.before_first_request
def create_table():
    db.create_all()

###############################################################################
##################################models#####################################
###############################################################################

class User(UserMixin, db.Model):
    __tablename__ = 'user'
    
    id = db.Column(Integer, primary_key=True)
    username = db.Column(String(64), index=True, unique=True)
    password = db.Column(String(128))
    uid = db.Column(String(256), unique=True)

    def __repr__(self):
        return '<User {}>'.format(self.username)

@login.user_loader
def load_user(uid):
    
    return User.query.get(str(uid))

class Post(db.Model):
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(128), index=True, unique=True)
    body = db.Column(db.String(440))

    def __repr__(self):
        return '<Post {}>'.format(self.title)
class Contact(db.Model):
    
    id = db.Column(db.Integer, primary_key=True)
    first = db.Column(db.String(64))
    last = db.Column(db.String(64))
    address = db.Column(db.String(128))
    email = db.Column(db.String(128))
    skills = db.Column(db.String(256))

    def __repr__(self):
        return '<Contact {}>'.format(self.email)

###############################################################################
##################################tables#######################################
###############################################################################

usertable = """CREATE TABLE IF NOT EXISTS user (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    uid TEXT NOT NULL
    ); """

posttable = """CREATE TABLE IF NOT EXISTS post (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT UNIQUE NOT NULL,
    body TEXT NOT NULL
    ); """
contacttable = """CREATE TABLE IF NOT EXISTS contact (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    first TEXT NOT NULL,
    last TEXT NOT NULL,
    address TEXT,
    email TEXT NOT NULL,
    skills TEXT,
    ); """

###############################################################################
##################################login#####################################
###############################################################################

login.init_app(app)
login.login_view = 'login'

###############################################################################
##################################libtools#####################################
###############################################################################

def make_salt(length=5):
    return ''.join(random.choice(letters) for x in range(length))

def make_pw_hash(name, pw, salt=None):
    
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(str((name + pw + salt)).encode('utf-8')).hexdigest()
    
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def make_secure_val(val):
    val = str.encode(val)
    return '%s|%s' % (bytes.decode(val), hmac.new(
                    secret.encode('UTF-8'), val, digestmod='ripemd160').hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    secval = secure_val.split('|')[1]
    if secure_val == make_secure_val(val):
        return secure_val

def check_user(sn, pw):
    isvalid = False

    if valid_pw(sn, pw, user[2]):
        isvalid = True
    
    if isvalid ==  False:
        return redirect(url_for('login'))
    return user

def make_secret(passphrase):
    length = len(passphrase)
    salted = make_salt(length)
    secret = make_pw_hash(passphrase, salted)
    return secret

secret=make_secret(make_salt(32))

###############################################################################
##################################routes#####################################
###############################################################################

@app.route('/')
@app.route('/index')
@app.route('/main')
def index():
    db.create_all()
    posts = Post.query.all()
    
    return render_template('articles.html', posts=posts)

@app.route('/articles')
@app.route('/posts')
@app.route('/sites')
def articles():
    db.create_all()
    sites = Post.query.all()
    return render_template('articles.html', posts=sites)

###############################################################################
##################################newpost#####################################
###############################################################################

@app.route('/new', methods=['GET', 'POST'])
@login_required
def newArticle():
    
    if request.method =='GET':
        user = current_user

        if not user.username == 'ohman':
            return redirect('/index')
        
        form = ArticleForm()
        return render_template('new-article.html', form=form)

    if request.method =='POST':

        ptitle = request.form['title']
        link = request.form['body']
        post = Post(id=None, title=ptitle, body=link)
                
        db.session.add(post)
        db.session.commit()
        return render_template('index.html')

###############################################################################
##################################login#####################################
###############################################################################

@app.route('/signin', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    
    form = LoginForm()
    
    if request.method =='GET':
        
        if current_user.is_authenticated:
            return redirect('/main')
        
        return render_template('login.html', form=form)
        
    if request.method =='POST':
    
        form = LoginForm()
        user = request.form['username']
        password = request.form['password']
        usern = User.query.filter_by(username=user).first()
        
        if usern and valid_pw(user, password, usern.password):
            resp = make_response(render_template('index.html'))
            login_user(usern)
            return resp
        else:
            form = RegisterForm()
            return redirect('register')
    
###############################################################################
##################################logout#####################################
###############################################################################

@app.route('/logout')
@login_required
def logout():
    
    logout_user()
    
    return redirect(url_for('index'))

@app.route('/users')
@app.route('/userlist', methods=['GET'])
def users():
    
    if request.method == 'GET':
        users = User.query.all()
    return render_template('users.html', users=users)

###############################################################################
##################################register#####################################
###############################################################################

@app.route('/signup', methods=['GET', 'POST'])
@app.route('/register', methods=['GET', 'POST'])
def register():
    
    if request.method == 'GET':
        form = RegisterForm()
        return render_template('register.html', form=form)

    if request.method == 'POST':
        
        form = RegisterForm()
        fname = request.form['username']
        password = request.form['password']
        
        if valid_username(fname):
            name = fname
        else:
            return redirect(url_for('register', form=form))
        
        if valid_password(password):
                
                pw_hash = make_pw_hash(name, password)
                uid = pw_hash.split(',')[0]
                
                user = User(id=None, username=name, password=pw_hash, uid=uid)
                
                db.session.add(user)
                db.session.commit()
                
                return redirect('/login')
    
    return render_template('register.html')

###############################################################################
##################################contact######################################
###############################################################################
@app.route('/about', methods=['GET'])
@app.route('/aboutme', methods=['GET'])
@app.route('/contact', methods=['GET'])
@app.route('/social', methods=['GET'])
def contact():
    
    if request.method == 'GET':
        contacts=Contact.query.all()
        return render_template('contact.html', contacts=contacts)
    else:
        return redirect('/')

