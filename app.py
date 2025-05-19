from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import hashlib
import os
import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import secrets
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(16))  # Use environment variable in production
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(os.path.dirname(os.path.abspath(__file__)), 'users.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    salt = db.Column(db.String(64), nullable=False)
    encrypted_password = db.Column(db.Text, nullable=False)
    fail_attempts = db.Column(db.Integer, default=0)
    is_locked = db.Column(db.Boolean, default=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class LoginLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False)
    success = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(50))

# Security functions
def generate_salt():
    return secrets.token_hex(16)

def get_aes_key():
    return hashlib.sha256(b'super_secret_master_key').digest()[:32]  # 256-bit key

def hash_password(password, salt, username):
    try:
        password_salt = (password + salt).encode('utf-8')
        password_hash = hashlib.sha256(password_salt).hexdigest()

        username_hash = hashlib.sha256(username.encode('utf-8')).hexdigest()

        combined = (password_hash + username_hash).encode('utf-8')
        final_hash = hashlib.sha256(combined).hexdigest()

        key = get_aes_key()
        cipher = AES.new(key, AES.MODE_CBC)
        iv = cipher.iv
        encrypted = cipher.encrypt(pad(final_hash.encode('utf-8'), AES.block_size))

        encrypted_data = base64.b64encode(iv + encrypted).decode('utf-8')
        return encrypted_data
    except Exception as e:
        print(f"Error in hash_password: {e}")
        return None

def verify_password(password, salt, username, stored_encrypted):
    try:
        decoded = base64.b64decode(stored_encrypted.encode('utf-8'))
        iv = decoded[:16]
        encrypted_data = decoded[16:]

        password_salt = (password + salt).encode('utf-8')
        password_hash = hashlib.sha256(password_salt).hexdigest()

        username_hash = hashlib.sha256(username.encode('utf-8')).hexdigest()

        combined = (password_hash + username_hash).encode('utf-8')
        final_hash = hashlib.sha256(combined).hexdigest()

        key = get_aes_key()
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        decrypted = unpad(cipher.decrypt(encrypted_data), AES.block_size).decode('utf-8')

        return decrypted == final_hash
    except Exception as e:
        print(f"Error in verify_password: {e}")
        return False

def log_login_attempt(username, success, ip_address):
    try:
        log = LoginLog(username=username, success=success, ip_address=ip_address)
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        print(f"Error logging login attempt: {e}")
        db.session.rollback()

# Decorators
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'username' not in session:
            flash('Please log in.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'username' not in session:
            flash('Please log in.', 'danger')
            return redirect(url_for('login'))
        user = User.query.filter_by(username=session['username']).first()
        if not user or not user.is_admin:
            flash('Admin access required.', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            username = request.form['username']
            password = request.form['password']
            if User.query.filter_by(username=username).first():
                flash('Username already exists.', 'danger')
                return redirect(url_for('register'))

            salt = generate_salt()
            encrypted_password = hash_password(password, salt, username)

            if not encrypted_password:
                flash('Registration error.', 'danger')
                return redirect(url_for('register'))

            user = User(username=username, salt=salt, encrypted_password=encrypted_password)

            if User.query.count() == 0:
                user.is_admin = True

            db.session.add(user)
            db.session.commit()
            flash('Registered successfully.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            print(f"Error in register: {e}")
            db.session.rollback()
            flash('Registration failed.', 'danger')
            return redirect(url_for('register'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        try:
            username = request.form['username']
            password = request.form['password']
            user = User.query.filter_by(username=username).first()

            if not user:
                flash('Invalid login.', 'danger')
                log_login_attempt(username, False, request.remote_addr)
                return redirect(url_for('login'))

            if user.is_locked:
                flash('Account is locked.', 'danger')
                return redirect(url_for('login'))

            if verify_password(password, user.salt, username, user.encrypted_password):
                session['username'] = username
                user.fail_attempts = 0
                db.session.commit()
                log_login_attempt(username, True, request.remote_addr)
                return redirect(url_for('admin_dashboard' if user.is_admin else 'dashboard'))
            else:
                user.fail_attempts += 1
                if user.fail_attempts >= 5:
                    user.is_locked = True
                    flash('Too many failed attempts. Account locked.', 'danger')
                else:
                    flash(f'Wrong password. {5 - user.fail_attempts} attempts left.', 'danger')
                db.session.commit()
                log_login_attempt(username, False, request.remote_addr)
                return redirect(url_for('login'))
        except Exception as e:
            print(f"Error in login: {e}")
            flash('Login error.', 'danger')
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('Logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    user = User.query.filter_by(username=session['username']).first()
    return render_template('dashboard.html', user=user)

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current = request.form['current_password']
        new = request.form['new_password']
        confirm = request.form['confirm_password']
        user = User.query.filter_by(username=session['username']).first()

        if not verify_password(current, user.salt, user.username, user.encrypted_password):
            flash('Current password incorrect.', 'danger')
            return redirect(url_for('change_password'))

        if new != confirm:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('change_password'))

        new_salt = generate_salt()
        new_encrypted = hash_password(new, new_salt, user.username)

        if not new_encrypted:
            flash('Password update error.', 'danger')
            return redirect(url_for('change_password'))

        user.salt = new_salt
        user.encrypted_password = new_encrypted
        db.session.commit()
        flash('Password changed successfully.', 'success')
        return redirect(url_for('dashboard'))
    return render_template('change_password.html')

# Admin
@app.route('/admin')
@admin_required
def admin_dashboard():
    users = User.query.all()
    return render_template('admin/dashboard.html', users=users)

@app.route('/admin/logs')
@admin_required
def admin_logs():
    logs = LoginLog.query.order_by(LoginLog.timestamp.desc()).all()
    return render_template('admin/logs.html', logs=logs)

@app.route('/admin/unlock/<int:user_id>')
@admin_required
def unlock_user(user_id):
    try:
        user = User.query.get_or_404(user_id)
        user.fail_attempts = 0
        user.is_locked = False
        db.session.commit()
        flash('User unlocked.', 'success')
    except:
        db.session.rollback()
        flash('Unlock failed.', 'danger')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete/<int:user_id>')
@admin_required
def delete_user(user_id):
    try:
        user = User.query.get_or_404(user_id)
        if user.is_admin and User.query.filter_by(is_admin=True).count() == 1:
            flash("Can't delete the last admin.", 'danger')
            return redirect(url_for('admin_dashboard'))

        if user.username == session['username']:
            flash("Can't delete yourself.", 'danger')
            return redirect(url_for('admin_dashboard'))

        db.session.delete(user)
        db.session.commit()
        flash('User deleted.', 'success')
    except:
        db.session.rollback()
        flash('Delete failed.', 'danger')
    return redirect(url_for('admin_dashboard'))

def init_db():
    with app.app_context():
        db.create_all()
        if User.query.count() == 0:
            username = "admin"
            password = "admin"
            salt = generate_salt()
            encrypted = hash_password(password, salt, username)
            user = User(username=username, salt=salt, encrypted_password=encrypted, is_admin=True)
            db.session.add(user)
            db.session.commit()
            print("Admin created: admin / admin")

if __name__ == '__main__':
    init_db()
    # app.run(debug=True)
    app.run(host='0.0.0.0', port=5000, debug=True)
