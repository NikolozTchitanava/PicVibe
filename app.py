from flask import Flask, render_template, redirect, url_for, flash, request, session
from flask_mail import Mail, Message
import sqlite3
import random
import os
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from forms import SignupForm, LoginForm, ImageUploadForm, ChangeUsernameForm, ChangePasswordForm
import logging
from dotenv import load_dotenv
from PIL import Image

load_dotenv()

logging.basicConfig(filename='error.log', level=logging.DEBUG, 
                    format='%(asctime)s %(levelname)s %(name)s %(threadName)s : %(message)s')

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True

mail = Mail(app)

DATABASE_URL = os.path.join(app.root_path, 'site.db')
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
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def send_verification_email(email, token):
    try:
        msg = Message('Email Verification', sender=app.config['MAIL_USERNAME'], recipients=[email])
        msg.body = f'Your verification token is {token}'
        mail.send(msg)
    except Exception as e:
        logging.error("Error sending email: %s", e)
        flash('Failed to send verification email. Please try again later.', 'danger')

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

        print(f"Signup attempt: username={username}, email={email}")  # Debugging

        try:
            conn = get_db_connection()
            cursor = conn.cursor()

            cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
            if cursor.fetchone():
                print(f"Username {username} already exists")  # Debugging
                flash('Username already exists', 'danger')
            else:
                cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
                if cursor.fetchone():
                    print(f"Email {email} already exists")  # Debugging
                    flash('Email already exists', 'danger')
                else:
                    token = random.randint(100000, 999999)
                    cursor.execute("INSERT INTO temp_users (username, email, password, token) VALUES (?, ?, ?, ?)",
                                   (username, email, hashed_password, token))
                    conn.commit()
                    send_verification_email(email, token)
                    session['email_to_verify'] = email
                    print(f"Verification email sent to {email} with token {token}")  # Debugging
                    flash('A verification email has been sent to your email address', 'success')
                    return redirect(url_for('verify_email'))
            conn.close()
        except Exception as e:
            logging.error("Error during signup: %s", e)
            print(f"Error during signup: {e}")  # Debugging
            flash('An error occurred. Please try again.', 'danger')
    return render_template('signup.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    print("login accessed")

    if request.method == 'POST':
        print("Form submitted")
        print(f"Form data: {request.form}")

    if form.validate_on_submit():
        print("Form validated successfully")
        username = form.username.data
        password = form.password.data

        print(f"Login attempt: username={username}")  # Debugging

        try:
            conn = get_db_connection()
            cursor = conn.cursor()

            cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
            user = cursor.fetchone()

            if user:
                print(f"User found: username={user['username']}, verified={user['verified']}")  # Debugging
                if check_password_hash(user['password'], password):
                    if user['verified']:
                        session['username'] = user['username']
                        session['user_id'] = user['id']
                        flash('Logged in successfully', 'success')
                        print(f"User {username} logged in successfully")  # Debugging
                        return redirect(url_for('home'))
                    else:
                        flash('Email not verified', 'danger')
                        print(f"User {username} email not verified")  # Debugging
                else:
                    flash('Invalid credentials', 'danger')
                    print(f"User {username} provided incorrect password")  # Debugging
            else:
                flash('Invalid credentials', 'danger')
                print(f"User {username} not found")  # Debugging
            conn.close()
        except Exception as e:
            logging.error("Error during login: %s", e)
            print(f"Error during login: {e}")  # Debugging
            flash('An error occurred. Please try again.', 'danger')
    else:
        print("Form validation failed")
        print(f"Form errors: {form.errors}")

    return render_template('login.html', form=form)

@app.route('/verify_email', methods=['GET', 'POST'])
def verify_email():
    if request.method == 'POST':
        token = request.form['token']
        email = session.get('email_to_verify')
        print(f"Email verification attempt: email={email}, token={token}")  # Debugging

        try:
            conn = get_db_connection()
            cursor = conn.cursor()

            cursor.execute("SELECT * FROM temp_users WHERE email = ? AND token = ?", (email, int(token)))
            temp_user = cursor.fetchone()

            if temp_user:
                print(f"Token matched for email {email}, creating user account")  # Debugging
                cursor.execute("INSERT INTO users (username, email, password, verified) VALUES (?, ?, ?, 1)",
                               (temp_user['username'], temp_user['email'], temp_user['password']))
                cursor.execute("DELETE FROM temp_users WHERE email = ?", (email,))
                conn.commit()
                flash('Email verified successfully', 'success')
                return redirect(url_for('login'))
            else:
                flash('Invalid verification token', 'danger')
                print(f"Invalid token {token} for email {email}")  # Debugging
            conn.close()
        except Exception as e:
            logging.error("Error during email verification: %s", e)
            print(f"Error during email verification: {e}")  # Debugging
            flash('An error occurred. Please try again.', 'danger')
    return render_template('verify_email.html')
@app.route('/home', methods=['GET', 'POST'])
def home():
    if 'username' not in session or 'user_id' not in session:
        flash('Please log in first', 'danger')
        return redirect(url_for('login'))

    form = ImageUploadForm()
    if form.validate_on_submit():
        if 'image' not in request.files and 'image' not in request.form:
            flash('No file part', 'danger')
            return redirect(request.url)
        
        file = None
        filename = None
        
        if 'image' in request.files:
            file = request.files['image']
            if file.filename == '':
                flash('No selected file', 'danger')
                return redirect(request.url)
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        elif 'image' in request.form:
            file_data = request.form['image']
            import base64
            from io import BytesIO
            from PIL import Image
            import re

            image_data = re.sub('^data:image/.+;base64,', '', file_data)
            image = Image.open(BytesIO(base64.b64decode(image_data)))
            filename = secure_filename(f"{form.name.data}.png")
            image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        if filename:
            name = form.name.data
            try:
                conn = get_db_connection()
                cursor = conn.cursor()
                cursor.execute("INSERT INTO images (filename, name, user_id) VALUES (?, ?, ?)",
                               (filename, name, session['user_id']))
                conn.commit()
                conn.close()
                flash('Image successfully uploaded', 'success')
                return redirect(url_for('home'))
            except Exception as e:
                logging.error("Error during image upload: %s", e)
                flash('An error occurred. Please try again.', 'danger')

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM images WHERE user_id = ?", (session['user_id'],))
        images = cursor.fetchall()
        conn.close()
    except Exception as e:
        logging.error("Error fetching images: %s", e)
        flash('An error occurred. Please try again.', 'danger')
        images = []

    return render_template('home.html', form=form, images=images)

@app.route('/picvibe')
def picvibe():
    if 'username' not in session or 'user_id' not in session:
        flash('Please log in first', 'danger')
        return redirect(url_for('login'))

    user_id = session['user_id']

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT images.id, images.filename, images.name, images.user_id, "
                       "(SELECT COUNT(*) FROM likes WHERE likes.image_id = images.id AND likes.vote = 1) as likes, "
                       "(SELECT COUNT(*) FROM likes WHERE likes.image_id = images.id AND likes.vote = -1) as dislikes "
                       "FROM images WHERE images.user_id != ?", (user_id,))
        images = cursor.fetchall()
        conn.close()
    except Exception as e:
        logging.error("Error fetching images for picvibe: %s", e)
        flash('An error occurred. Please try again.', 'danger')
        images = []

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

    try:
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
    except Exception as e:
        logging.error("Error during voting: %s", e)
        flash('An error occurred. Please try again.', 'danger')

    return redirect(url_for('picvibe'))

@app.route('/delete_image/<int:image_id>', methods=['POST'])
def delete_image(image_id):
    if 'username' not in session or 'user_id' not in session:
        flash('Please log in first', 'danger')
        return redirect(url_for('login'))

    try:
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
    except Exception as e:
        logging.error("Error during image deletion: %s", e)
        flash('An error occurred. Please try again.', 'danger')

    return redirect(url_for('home'))

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'success')
    return redirect(url_for('login'))

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'username' not in session or 'user_id' not in session:
        flash('Please log in first', 'danger')
        return redirect(url_for('login'))

    change_username_form = ChangeUsernameForm()
    change_password_form = ChangePasswordForm()

    if change_username_form.validate_on_submit() and change_username_form.new_username.data:
        new_username = change_username_form.new_username.data
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username = ?", (new_username,))
            if cursor.fetchone():
                flash('Username already exists', 'danger')
            else:
                cursor.execute("UPDATE users SET username = ? WHERE id = ?", (new_username, session['user_id']))
                conn.commit()
                session['username'] = new_username
                flash('Username successfully changed', 'success')
            conn.close()
        except Exception as e:
            logging.error("Error during username change: %s", e)
            flash('An error occurred. Please try again.', 'danger')

    if change_password_form.validate_on_submit() and change_password_form.new_password.data:
        current_password = change_password_form.current_password.data
        new_password = change_password_form.new_password.data
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],))
            user = cursor.fetchone()
            if user and check_password_hash(user['password'], current_password):
                hashed_new_password = generate_password_hash(new_password)
                cursor.execute("UPDATE users SET password = ? WHERE id = ?", (hashed_new_password, session['user_id']))
                conn.commit()
                flash('Password successfully changed', 'success')
            else:
                flash('Current password is incorrect', 'danger')
            conn.close()
        except Exception as e:
            logging.error("Error during password change: %s", e)
            flash('An error occurred. Please try again.', 'danger')

    return render_template('profile.html', change_username_form=change_username_form, change_password_form=change_password_form)

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=8001)
