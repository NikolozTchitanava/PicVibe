from flask import Flask, render_template, redirect, url_for, flash, request, session
from flask_mail import Mail, Message
import sqlite3
import random
import os
from werkzeug.security import generate_password_hash, check_password_hash
from config import Config
from forms import SignupForm, LoginForm

app = Flask(__name__)
app.config.from_object(Config)
mail = Mail(app)

DATABASE_URL = os.path.join(os.getcwd(), 'site.db')

def get_db_connection():
    conn = sqlite3.connect(DATABASE_URL)
    conn.row_factory = sqlite3.Row
    return conn

def create_tables():
    conn = get_db_connection()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            verified INTEGER DEFAULT 0
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS temp_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            token INTEGER NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

create_tables()

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data
        hashed_password = generate_password_hash(password)
        
        conn = get_db_connection()
        cursor = conn.cursor()
        #no duplicate username shell pass!
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            flash('Username already exists', 'danger')
        else:
            #no duplicate email shell pass!
            cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
            if cursor.fetchone():
                flash('Email already exists', 'danger')
            else:
                token = random.randint(100000, 999999)
                cursor.execute("INSERT INTO temp_users (username, email, password, token) VALUES (?, ?, ?, ?)",
                               (username, email, hashed_password, token))
                conn.commit()
                send_verification_email(email, token)
                flash('A verification email has been sent to your email address', 'success')
                return redirect(url_for('verify_email'))
        conn.close()
    return render_template('signup.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        
        if user and check_password_hash(user['password'], password):
            if user['verified']:
                session['username'] = user['username']
                flash('Logged in successfully', 'success')
                return redirect(url_for('home'))
            else:
                flash('Email not verified', 'danger')
        else:
            flash('Invalid credentials', 'danger')
        conn.close()
    return render_template('login.html', form=form)

@app.route('/verify_email', methods=['GET', 'POST'])
def verify_email():
    if request.method == 'POST':
        token = request.form['token']
        email = session.get('email_to_verify') 

        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM temp_users WHERE email = ? AND token = ?", (email, int(token)))
        temp_user = cursor.fetchone()
        
        if temp_user:
            cursor.execute("INSERT INTO users (username, email, password, verified) VALUES (?, ?, ?, 1)",
                           (temp_user['username'], temp_user['email'], temp_user['password']))
            cursor.execute("DELETE FROM temp_users WHERE email = ?", (email,))
            conn.commit()
            flash('Email verified successfully', 'success')
            return redirect(url_for('login'))
        else:
            flash('Invalid verification token', 'danger')
        conn.close()
    return render_template('verify_email.html')

@app.route('/home')
def home():
    if 'username' in session:
        return render_template('home.html', username=session['username'])
    else:
        flash('Please log in first', 'danger')
        return redirect(url_for('login'))

@app.route('/')
def index():
    if 'username' in session:
        return redirect(url_for('home'))
    return redirect(url_for('login'))

def send_verification_email(email, token):
    msg = Message('Email Verification', sender=app.config['MAIL_USERNAME'], recipients=[email])
    msg.body = f'Your verification code is {token}'
    mail.send(msg)

email_verifications = {}

if __name__ == '__main__':
    app.run(debug=True)
