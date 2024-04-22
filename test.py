
from flask import Flask, request, redirect, url_for, flash, render_template_string
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
import os
from werkzeug.utils import secure_filename
from flask import send_from_directory
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import time



app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['UPLOAD_FOLDER'] = 'uploads/'
app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024  # 1 MB limit

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'png', 'jpg', 'jpeg', 'gif', 'txt', 'pdf', 'docx', 'xlsx'}


db = SQLAlchemy(app)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(300), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('files', lazy=True))



@login_manager.user_loader
def load_user(user_id):
    if user_id is not None and user_id.isdigit():
        return User.query.get(int(user_id))
    return None

with app.app_context():
    db.create_all()

@app.route('/')
def home():
    return '<h1>Welcome to the Crypto Operations Service</h1> <a href="/register">Register</a> | <a href="/login">Login</a>'

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        flash('Your account has been created!', 'success')
        return redirect(url_for('login'))

    return render_template_string('''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Register</title>
    </head>
    <body>
        <h1>Register</h1>
        <form method="post">
            <label for="username">Username:</label>
            <input type="text" id="username" name="username" required>
            <br>
            <label for="email">Email:</label>
            <input type="email" id="email" name="email" required>
            <br>
            <label for="password">Password:</label>
            <input type="password" id="password" name="password" required>
            <br>
            <button type="submit">Register</button>
        </form>
    </body>
    </html>
    ''')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user)
            files = File.query.filter_by(user_id=current_user.id).all()
            return render_template_string('''
                Logged In Successfully! <br>
                <a href="/change_password">Change Password</a> | 
                <a href="/logout">Logout</a> | 
                <a href="/generate_keys">Generate Keys</a> | 
                <form action="/delete_account" method="post" style="display:inline;">
                    <button type="submit">Delete Account</button>
                </form>
                <h1>Upload File</h1>
                <form method="post" action="/handle_files" enctype="multipart/form-data">
                    <input type="file" name="file">
                    <input type="submit" value="Upload">
                </form>
                <h2>Your Files</h2>
                {% for file in files %}
                <li>{{ file.filename }} 
                    <a href="/files/{{ file.id }}/download">Download</a> 
                    <form action="/files/{{ file.id }}/delete" method="post" style="display:inline;">
                        <input type="hidden" name="delete_file_id" value="{{ file.id }}">
                        <button type="submit">Delete</button>
                    </form>
                </li>
                {% endfor %}
            ''', files=files)
        else:
            flash('Invalid username or password')
            return redirect(url_for('login'))
    return render_template_string('''
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Login</title>
        </head>
        <body>
            <h1>Login</h1>
            <form method="post">
                <label for="username">Username:</label>
                <input type="text" id="username" name="username" required>
                <br>
                <label for="password">Password:</label>
                <input type="password" id="password" name="password" required>
                <br>
                <button type="submit">Login</button>
            </form>
        </body>
        </html>
    ''')







@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        user = User.query.get(current_user.id)
        if user and user.check_password(current_password):
            user.set_password(new_password)
            db.session.commit()
            flash('Your password has been updated.')
            return redirect(url_for('home'))
        else:
            flash('Invalid current password.')
    return render_template_string('''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Change Password</title>
    </head>
    <body>
        <h1>Change Password</h1>
        <form method="post">
            <label for="current_password">Current Password:</label>
            <input type="password" id="current_password" name="current_password" required>
            <br>
            <label for="new_password">New Password:</label>
            <input type="password" id="new_password" name="new_password" required>
            <br>
            <button type="submit">Change Password</button>
        </form>
    </body>
    </html>
    ''')

@app.route('/delete_account', methods=['POST'])
@login_required
def delete_account():
    # Manually delete all files associated with the user
    File.query.filter_by(user_id=current_user.id).delete()

    # Now it's safe to delete the user
    db.session.delete(current_user)
    db.session.commit()
    logout_user()
    flash('Your account has been successfully deleted.')
    return redirect(url_for('home'))


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/generate_keys')
@login_required
def generate_keys():
    starttime = time.time()
    keys = [Fernet.generate_key().decode() for _ in range(20)]
    keys_html = '<br>'.join(keys)
    eclipse_time = time.time() - starttime
    return render_template_string('''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Generate Keys</title>
    </head>
    <body>
        <h1>Generated Cryptographic Keys</h1>
        <p>Here are your keys:</p>
        <p>{{ keys_html|safe }}</p>
        <p>Time taken to generate keys: {{ eclipse_time }} seconds</p>
        <a href="/">Home</a> | <a href="/logout">Logout</a>
    </body>
    </html>
    ''', keys_html=keys_html, eclipse_time=eclipse_time)


@app.route('/files', methods=['GET', 'POST'])
@login_required
def file_upload():
    if request.method == 'POST' and 'file' in request.files:
        file = request.files['file']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            new_file = File(filename=filename, user_id=current_user.id)
            db.session.add(new_file)
            db.session.commit()
            flash('File successfully uploaded')
        else:
            flash('Invalid file type')

    files = File.query.filter_by(user_id=current_user.id).all()
    return render_template_string('''
    Logged In Successfully! <br>
    <h1>Upload File</h1>
    <form method="post" enctype="multipart/form-data">
        <input type="file" name="file">
        <input type="submit" value="Upload">
    </form>
    <h2>Your Files</h2>
    {% for file in files %}
    <li>{{ file.filename }} 
        <a href="/files/{{ file.id }}/download">Download</a> | 
        <a href="/hash_file/{{ file.id }}/sha256">Hash SHA256</a> | 
        <a href="/hash_file/{{ file.id }}/md5">Hash MD5</a> | 
        <a href="/encrypt_file/{{ file.id }}/aes">Encrypt AES-192</a> | 
        <a href="/encrypt_file/{{ file.id }}/des">Encrypt DES</a> | 
        <a href="/encrypt_file/{{ file.id }}/blowfish">Encrypt Blowfish</a> 
        <form action="/files/{{ file.id }}/delete" method="post" style="display:inline;">
            <button type="submit">Delete</button>
        </form>
    </li>
    {% endfor %}
    <a href="/logout">Logout</a>
    ''', files=files)
    return render_template_string('''
        {% with messages = get_flashed_messages() %}
        {% if messages %}
            {% for message in messages %}
            <div>{{ message }}</div>
            {% endfor %}
        {% endif %}
        {% endwith %}
        Logged In Successfully! <br>
        ...
        ''', files=files)


# Adjust file download and delete routes to handle within the login route context
@app.route('/files/<int:file_id>/download')
@login_required
def file_download(file_id):
    file = File.query.get(file_id)
    if file and file.user_id == current_user.id:
        return send_from_directory(app.config['UPLOAD_FOLDER'], file.filename, as_attachment=True)
    else:
        flash('File not found')
        return redirect(url_for('login'))


@app.route('/handle_files', methods=['POST'])
@login_required
def handle_files():
    # Handle file upload
    file = request.files.get('file')
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        new_file = File(filename=filename, user_id=current_user.id)
        db.session.add(new_file)
        db.session.commit()
        flash('File successfully uploaded')

    # Handle deletion request from form
    file_id_to_delete = request.form.get('delete_file_id')
    if file_id_to_delete:
        file_to_delete = File.query.get(int(file_id_to_delete))
        if file_to_delete and file_to_delete.user_id == current_user.id:
            try:
                os.remove(os.path.join(app.config['UPLOAD_FOLDER'], file_to_delete.filename))
            except FileNotFoundError:
                flash('File already deleted or not found on disk')
            db.session.delete(file_to_delete)
            db.session.commit()
            flash('File deleted')

    return redirect(url_for('file_upload'))  # Redirect back to the login page to refresh the file list


@app.route('/files/<int:file_id>/delete', methods=['POST'])
@login_required
def file_delete(file_id):
    file = File.query.get(file_id)
    if file and file.user_id == current_user.id:
        os.remove(os.path.join(app.config['UPLOAD_FOLDER'], file.filename))  # Delete file from filesystem
        db.session.delete(file)
        db.session.commit()
        flash('File deleted')
    else:
        flash('File not found')
    return redirect(url_for('file_upload'))



def hash_file(filename, method="sha256"):
    start_time = time.time()  # Start timing
    hash_func = hashlib.sha256() if method == "sha256" else hashlib.md5()
    with open(filename, "rb") as f:
        while chunk := f.read(4096):
            hash_func.update(chunk)
    end_time = time.time()  # End timing
    duration = end_time - start_time
    return hash_func.hexdigest(), duration




def encrypt_file(filename, method="aes", key=None):
    start_time = time.time()  # Start timing
    with open(filename, "rb") as file:
        data = file.read()

    # Adjust IV size based on the encryption algorithm
    iv = os.urandom(16) if method == "aes" else os.urandom(8)
    if method == "aes":
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    elif method == "des":
        cipher = Cipher(algorithms.TripleDES(key), modes.CFB(iv), backend=default_backend())
    elif method == "blowfish":
        cipher = Cipher(algorithms.Blowfish(key), modes.CFB(iv), backend=default_backend())

    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data) + encryptor.finalize()

    # Filename for the encrypted file
    encrypted_filename = os.path.basename(filename).replace('.', f'_{method}.')
    encrypted_file_path = os.path.join(app.config['UPLOAD_FOLDER'], encrypted_filename)

    # Save the encrypted file
    with open(encrypted_file_path, "wb") as file:
        file.write(encrypted_data)
    
    end_time = time.time()  # End timing
    duration = end_time - start_time
    return encrypted_filename, duration  # Return filename and duration





@app.route('/hash_file/<int:file_id>/<hash_type>')
@login_required
def hash_file_route(file_id, hash_type):
    file = File.query.get(file_id)
    if file and file.user_id == current_user.id:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file_hash, duration = hash_file(file_path, hash_type)
        flash(f"Hash ({hash_type.upper()}): {file_hash} - Completed in {duration:.4f} seconds")
    else:
        flash('File not found')
    return redirect(url_for('file_upload'))

@app.route('/encrypt_file/<int:file_id>/<enc_type>')
@login_required
def encrypt_file_route(file_id, enc_type):
    file = File.query.get(file_id)
    if file and file.user_id == current_user.id:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        key = os.urandom(24 if enc_type == "aes" else 8)  # Proper key size
        encrypted_filename, duration = encrypt_file(file_path, enc_type, key)
        flash(f"File encrypted using {enc_type.upper()}. New file: {encrypted_filename} - Completed in {duration:.4f} seconds")
        # Add encrypted file to the database
        new_file = File(filename=encrypted_filename, user_id=current_user.id)
        db.session.add(new_file)
        db.session.commit()
    else:
        flash('File not found')
    return redirect(url_for('file_upload'))




with app.app_context():
    db.create_all()


if __name__ == '__main__':
    app.run(debug=True)