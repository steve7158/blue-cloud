import os
from termcolor import colored
from flask import Flask
from flask import render_template, request
from flask import flash
from flask import redirect
from flask import url_for
from flask import session
from flask import logging
from wtforms import Form
from wtforms import StringField
from wtforms import TextAreaField
from wtforms import PasswordField
from wtforms import DateTimeField
from wtforms.fields.html5 import DateField
from wtforms import TextAreaField
from wtforms import IntegerField
from wtforms import BooleanField
from wtforms import FileField
from wtforms import validators
from passlib.hash import sha256_crypt
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.sql import func
# import pandas as pd
from pytz import timezone
from datetime import datetime
from werkzeug.utils import secure_filename

UPLOAD_FOLDER = 'static/files/'
ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'mkv', 'mp4'])
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
UTC = timezone('UTC')

def time_now():
    return datetime.now(UTC)
from functools import wraps
app = Flask('__main__')
db=SQLAlchemy(app)
app.config['SQLALCHEMY_DATABASE_URI']='postgresql://postgres:mark@2187@localhost/indo_russian'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    name=db.Column(db.String(200), unique=False, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password=db.Column(db.String(200), unique=False, nullable=False)

    def __init__(self, username, name, email, password):
        self.username=username;
        self.email=email
        self.password=password
        self.name=name
    def __repr__(self):
        return '<User %r>' % self.username

class Articles(db.Model):
    def __init__(self, author, filename, file):
        self.author=author
        self.filename=filename
        self.file=file
    def __getitem__(self, item):
        return getattr(self, item)
    id = db.Column(db.Integer, primary_key=True)
    author = db.Column(db.String(80), db.ForeignKey('user.username'))
    filename=db.Column(db.String(500), unique=False, nullable=False)
    file=db.Column(db.String(500), unique=False, nullable=True)
    created_date =db.Column(db.DateTime(timezone=True), primary_key=False, nullable=False, default=time_now)



class RegisterForm(Form):
    name=StringField('name', [validators.Length(min=1, max=50)])
    username=StringField('username', [validators.Length(min=1, max=25)])
    email=StringField('email', [validators.Length(min=6, max=60)])

    password=PasswordField('password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='password do not match')
    ])
    confirm=PasswordField('confirm password')

class ArticleForm(Form):
    filename=StringField('Filename', [validators.Length(min=1, max=200)])
    file=FileField(u'File')


@app.route('/')
def index():
    print(colored(time_now(),'red'))
    if 'logged_in' in session:
        print(True)
    return render_template('home.html')
@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form=RegisterForm(request.form)
    if request.method=='POST' and form.validate():
        name=form.name.data
        email=form.email.data

        username=form.username.data
        # profession=form.profession
        password=sha256_crypt.encrypt(str(form.password.data))
        add_user=User(username, name, email, password)
        db.session.add(add_user)
        db.session.commit()
        flash("you ar now registered and now can login", 'success')
        return redirect(url_for('index'))
    return render_template('register.html', form = form)


@app.route('/login',methods=['GET','POST'])
def login():
        if request.method=='POST':
            username=request.form['username']
            password_candidate=request.form['password']
            result=User.query.filter_by(username=username).first()
            if result:
                password=result.password
                if sha256_crypt.verify(password_candidate, password):
                    app.logger.info('PASSWORD MATCHED')
                    session['logged_in']=True
                    session['username']=username
                    # user=Loggers(username)
                    # db.session.add(user)
                    # db.session.commit()
                    print(colored(session['username'], 'yellow'))
                    return redirect(url_for('dashboard'))
                else:
                    app.logger.info('PASSWORD NOT MATCHED')
                    error='invalid password'
                    return render_template('login.html', error=error)
            else:
                app.logger.info('NO USER')
                error="invalide user"
                return render_template('login.html', error=error)
        return render_template('login.html')

def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args,**kwargs)
        else:
            flash('Unauthorised, you are not logged in!', 'danger')
            redirect(url_for('login'))
    return wrap


@app.route('/dashboard')
@is_logged_in
def dashboard():
    result=Articles.query.filter_by(author=session['username']).all()

    if len(result)>0:
        return render_template('dashbord.html', articles=result)
    else:
        msg= 'No articles found'
        return render_template('dashbord.html', msg=msg)
    return render_template('dashbord.html')


@app.route('/downloads')
def articles():
    result=db.session.query(Articles).all()
    print(result)
    print(type(result))
    print(len(result))

    if len(result)>0:
        return render_template('articles.html', articles=result)
    else:
        msg="No article found"
        return render_template('articles.html',msg=msg)

@app.route('/download/<string:id>/')
def article(id):
    result=Articles.query.filter_by(id=id).first()
    print(colored(result.file, 'red'))
    file='files/'+result.file
    print(colored(file, 'white', 'on_red'))
    return render_template('article.html', article=result, videos=videos)


@app.route('/logout')
@is_logged_in
def logut():
    print(colored(session['username'], 'yellow'))

    session.clear()
    flash('You are now logged out', 'success')
    return redirect(url_for('login'))


@app.route('/add_file', methods=['GET', 'POST'])
@is_logged_in
def add_article():
    form=ArticleForm(request.form)
    if request.method=='POST' or form.validate():
        filename=form.filename.data

        file = request.files['file']

        if file and allowed_file(file.filename):
            filename_sec = secure_filename(file.filename)
            print(colored(filename, 'white', 'on_red'))
            print(colored(type(filename), 'white', 'on_red'))
            print(colored(os.path.join(app.config['UPLOAD_FOLDER'], filename), 'red'))
            # test=os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            # test=filename
            print(colored(filename, 'red', 'on_yellow'))
        new_download=Articles(session['username'],filename,filename_sec)
        db.session.add(new_download)
        db.session.commit()
        flash('File saved', 'success')
        return redirect(url_for('dashboard'))
    return render_template('add_article.html', form=form)

@app.route('/edit_article/<string:id>/', methods=['GET','POST'])
@is_logged_in
def edit_article(id):
    result=Articles.query.filter_by(id=id).first()
    form=ArticleForm(request.form)
    # form.file.data=result['file']
    if request.method=='POST' and form.validate():
        filename=form.filename.data
        file=request.files['file']

        if file and allowed_file(file.filename):
            filename_sec = secure_filename(file.filename)
            print(colored(filename, 'white', 'on_red'))
            print(colored(type(filename), 'white', 'on_red'))
            print(colored(filename_sec, 'white', 'on_red'))
            print(colored(os.path.join(app.config['UPLOAD_FOLDER'], filename), 'red'))
            # test=os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            # test=filename
            print(colored(filename, 'red', 'on_yellow'))
        edit=Articles.query.filter_by(id=id).first()
        edit.filename=filename
        edit.file=filename_sec
        db.session.commit()
        # app.logger.info(title)
        flash('Article Updated', 'success')
        return redirect(url_for('dashboard'))
    return render_template('edit_article.html', form=form)

@app.route('/delete_article/<string:id>', methods=['POST'])
@is_logged_in
def delete_article(id):
    delete=Articles.query.filter_by(id=id).first()
    db.session.delete(delete)
    db.session.commit()
    flash('Article deleated', 'danger')
    return redirect(url_for('dashboard'))

if __name__=='__main__':
    app.secret_key='secret123'
    app.run( debug=True, port=8000)
