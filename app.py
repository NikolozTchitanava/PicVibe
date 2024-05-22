from flask import Flask, render_template, redirect, url_for, flash, request, session
from flask_mail import Mail, Message
import sqlite3
import random
import os
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from config import Config
from forms import SignupForm, LoginForm, ImageUploadForm

app = Flask(__name__)
app.config.from_object(Config)
mail = Mail(app)

DATABASE_URL = os.path.join(os.getcwd(), 'site.db')
UPLOAD_FOLDER = os.path.join(app.root_path, 'static/uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

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
    conn.execute('''
        CREATE TABLE IF NOT EXISTS images (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            name TEXT NOT NULL,
            user_id INTEGER NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS likes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            image_id INTEGER NOT NULL,
            vote INTEGER NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (image_id) REFERENCES images (id)
        )
    ''')
    conn.commit()
    conn.close()

create_tables()

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def send_verification_email(email, token):
    msg = Message('Email Verification', sender='your_email@example.com', recipients=[email])
    msg.body = f'Your verification token is {token}'
    mail.send(msg)

@app.route('/')
def index():
    return redirect(url_for('home'))

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
        
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            flash('Username already exists', 'danger')
        else:
            cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
            if cursor.fetchone():
                flash('Email already exists', 'danger')
            else:
                token = random.randint(100000, 999999)
                cursor.execute("INSERT INTO temp_users (username, email, password, token) VALUES (?, ?, ?, ?)",
                               (username, email, hashed_password, token))
                conn.commit()
                send_verification_email(email, token)
                session['email_to_verify'] = email 
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
                session['user_id'] = user['id'] 
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

@app.route('/home', methods=['GET', 'POST'])
def home():
    if 'username' not in session or 'user_id' not in session:
        flash('Please log in first', 'danger')
        return redirect(url_for('login'))

    form = ImageUploadForm()
    if form.validate_on_submit():
        if 'image' not in request.files:
            flash('No file part', 'danger')
            return redirect(request.url)
        file = request.files['image']
        if file.filename == '':
            flash('No selected file', 'danger')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            name = form.name.data
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("INSERT INTO images (filename, name, user_id) VALUES (?, ?, ?)",
                           (filename, name, session['user_id']))
            conn.commit()
            conn.close()
            flash('Image successfully uploaded', 'success')
            return redirect(url_for('home'))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM images WHERE user_id = ?", (session['user_id'],))
    images = cursor.fetchall()
    conn.close()

    return render_template('home.html', form=form, images=images)

@app.route('/picvibe')
def picvibe():
    if 'username' not in session or 'user_id' not in session:
        flash('Please log in first', 'danger')
        return redirect(url_for('login'))

    user_id = session['user_id']

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT images.id, images.filename, images.name, images.user_id, "
                   "(SELECT COUNT(*) FROM likes WHERE likes.image_id = images.id AND likes.vote = 1) as likes, "
                   "(SELECT COUNT(*) FROM likes WHERE likes.image_id = images.id AND likes.vote = -1) as dislikes "
                   "FROM images WHERE images.user_id != ?", (user_id,))
    images = cursor.fetchall()
    conn.close()

    image_list = []
    for image in images:
        total_votes = image['likes'] + image['dislikes']
        like_percentage = (image['likes'] / total_votes) * 100 if total_votes > 0 else 0
        dislike_percentage = (image['dislikes'] / total_votes) * 100 if total_votes > 0 else 0
        image_dict = {
            'id': image['id'],
            'filename': image['filename'],
            'name': image['name'],
            'user_id': image['user_id'],
            'likes': image['likes'],
            'dislikes': image['dislikes'],
            'like_percentage': like_percentage,
            'dislike_percentage': dislike_percentage
        }
        image_list.append(image_dict)

    return render_template('picvibe.html', images=image_list)

@app.route('/vote', methods=['POST'])
def vote():
    if 'username' not in session or 'user_id' not in session:
        flash('Please log in first', 'danger')
        return redirect(url_for('login'))

    image_id = request.form.get('image_id')
    vote = int(request.form.get('vote'))  

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM likes WHERE user_id = ? AND image_id = ?", (session['user_id'], image_id))
    existing_vote = cursor.fetchone()

    if existing_vote:
        if existing_vote['vote'] == vote:
            cursor.execute("DELETE FROM likes WHERE user_id = ? AND image_id = ?", (session['user_id'], image_id))
        else:
            cursor.execute("UPDATE likes SET vote = ? WHERE user_id = ? AND image_id = ?", (vote, session['user_id'], image_id))
    else:
        cursor.execute("INSERT INTO likes (user_id, image_id, vote) VALUES (?, ?, ?)", (session['user_id'], image_id, vote))

    conn.commit()
    conn.close()

    return redirect(url_for('picvibe'))

@app.route('/delete_image/<int:image_id>', methods=['POST'])
def delete_image(image_id):
    if 'username' not in session or 'user_id' not in session:
        flash('Please log in first', 'danger')
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM images WHERE id = ? AND user_id = ?", (image_id, session['user_id']))
    image = cursor.fetchone()

    if image:
        
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], image['filename'])
        if os.path.exists(image_path):
            os.remove(image_path)
        
       
        cursor.execute("DELETE FROM images WHERE id = ?", (image_id,))
        conn.commit()
        flash('Image successfully deleted', 'success')
    else:
        flash('Image not found or you do not have permission to delete this image', 'danger')

    conn.close()
    return redirect(url_for('home'))

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
