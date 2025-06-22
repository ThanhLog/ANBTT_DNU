# Đề tài 21: Ứng dụng SHA và Triple DES để bảo vệ mật khẩu người dùng trong cơ sở dữ liệu


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
from rsa_secure_file import hash_password_sha, encrypt_hashed_password, verify_password as verify_password_3des, generate_3des_key
import random, string
from sqlalchemy import func
import json

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

# Đường dẫn file lưu khóa 3DES
TRIPLE_DES_KEY_FILE = '3des.key'

def get_3des_key():
    if not os.path.exists(TRIPLE_DES_KEY_FILE):
        key = generate_3des_key()
        with open(TRIPLE_DES_KEY_FILE, 'wb') as f:
            f.write(key)
        return key
    with open(TRIPLE_DES_KEY_FILE, 'rb') as f:
        return f.read()

# Security functions
def generate_salt():
    return secrets.token_hex(16)

def get_aes_key():
    return hashlib.sha256(b'super_secret_master_key').digest()[:32]  # 256-bit key

def hash_password(password, salt, username):
    try:
        # Kết hợp password + salt + username để tăng độ phức tạp
        password_salt = (password + salt + username).encode('utf-8')
        hashed = hash_password_sha(password_salt.decode())
        key = get_3des_key()
        encrypted = encrypt_hashed_password(hashed, key)
        return encrypted
    except Exception as e:
        print(f"Error in hash_password: {e}")
        return None

def verify_password(password, salt, username, stored_encrypted):
    try:
        password_salt = (password + salt + username).encode('utf-8')
        key = get_3des_key()
        return verify_password_3des(password_salt.decode(), stored_encrypted, key)
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
            flash('Vui lòng đăng nhập.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'username' not in session:
            flash('Vui lòng đăng nhập.', 'danger')
            return redirect(url_for('login'))
        user = User.query.filter_by(username=session['username']).first()
        if not user or not user.is_admin:
            flash('Yêu cầu truy cập quản trị.', 'danger')
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
                flash('Tên đăng nhập đã tồn tại.', 'danger')
                return redirect(url_for('register'))

            salt = generate_salt()
            encrypted_password = hash_password(password, salt, username)

            if not encrypted_password:
                flash('Có lỗi khi đăng ký. Vui lòng thử lại.', 'danger')
                return redirect(url_for('register'))

            user = User(username=username, salt=salt, encrypted_password=encrypted_password)

            if User.query.count() == 0:
                user.is_admin = True

            db.session.add(user)
            db.session.commit()
            flash('Đăng ký thành công! Bạn có thể đăng nhập.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            print(f"Error in register: {e}")
            db.session.rollback()
            flash('Đăng ký thất bại. Vui lòng thử lại.', 'danger')
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
                flash('Tên đăng nhập hoặc mật khẩu không đúng.', 'danger')
                log_login_attempt(username, False, request.remote_addr)
                return redirect(url_for('login'))

            if user.is_locked:
                flash('Tài khoản của bạn đã bị khóa. Vui lòng liên hệ quản trị viên.', 'danger')
                return redirect(url_for('login'))

            if verify_password(password, user.salt, username, user.encrypted_password):
                session['username'] = username
                user.fail_attempts = 0
                db.session.commit()
                log_login_attempt(username, True, request.remote_addr)
                flash('Đăng nhập thành công!', 'success')
                return redirect(url_for('admin_dashboard' if user.is_admin else 'home'))
            else:
                cfg = get_config()
                max_fail = cfg.get('max_fail_attempts', 5)
                user.fail_attempts += 1
                if user.fail_attempts >= max_fail:
                    user.is_locked = True
                    flash('Bạn đã nhập sai quá số lần cho phép. Tài khoản đã bị khóa.', 'danger')
                else:
                    flash(f'Mật khẩu không đúng. Bạn còn {max_fail - user.fail_attempts} lần thử.', 'danger')
                db.session.commit()
                log_login_attempt(username, False, request.remote_addr)
                return redirect(url_for('login'))
        except Exception as e:
            print(f"Error in login: {e}")
            flash('Có lỗi khi đăng nhập. Vui lòng thử lại.', 'danger')
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('Đăng xuất thành công.', 'info')
    return redirect(url_for('index'))

@app.route('/')
@login_required
def home():
    user = User.query.filter_by(username=session['username']).first()
    return render_template('index.html', user=user)


@app.route('/dashboard')
@login_required
def dashboard():
    user = User.query.filter_by(username=session['username']).first()
    login_logs = LoginLog.query.filter_by(username=user.username).order_by(LoginLog.timestamp.desc()).limit(10).all()
    return render_template('dashboard.html', user=user, login_logs=login_logs)

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current = request.form['current_password']
        new = request.form['new_password']
        confirm = request.form['confirm_password']
        user = User.query.filter_by(username=session['username']).first()

        if not verify_password(current, user.salt, user.username, user.encrypted_password):
            flash('Mật khẩu hiện tại không đúng.', 'danger')
            return redirect(url_for('change_password'))

        if new != confirm:
            flash('Mật khẩu không khớp.', 'danger')
            return redirect(url_for('change_password'))

        new_salt = generate_salt()
        new_encrypted = hash_password(new, new_salt, user.username)

        if not new_encrypted:
            flash('Có lỗi khi cập nhật mật khẩu.', 'danger')
            return redirect(url_for('change_password'))

        user.salt = new_salt
        user.encrypted_password = new_encrypted
        db.session.commit()
        flash('Mật khẩu đã được thay đổi thành công.', 'success')
        return redirect(url_for('dashboard'))
    return render_template('change_password.html')

# Admin
@app.route('/admin')
@admin_required
def admin_dashboard():
    search = request.args.get('search', '').strip()
    query = User.query
    if search:
        query = query.filter(User.username.ilike(f"%{search}%"))
    users = query.all()
    total_users = User.query.count()
    locked_users = User.query.filter_by(is_locked=True).count()
    admin_count = User.query.filter_by(is_admin=True).count()
    total_logs = LoginLog.query.count()
    return render_template('admin/dashboard.html', users=users, total_users=total_users, locked_users=locked_users, admin_count=admin_count, total_logs=total_logs)

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
        flash('Người dùng đã được mở khóa.', 'success')
    except:
        db.session.rollback()
        flash('Mở khóa thất bại.', 'danger')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete/<int:user_id>')
@admin_required
def delete_user(user_id):
    try:
        user = User.query.get_or_404(user_id)
        if user.is_admin and User.query.filter_by(is_admin=True).count() == 1:
            flash("Không thể xóa người quản trị cuối cùng.", 'danger')
            return redirect(url_for('admin_dashboard'))

        if user.username == session['username']:
            flash("Không thể xóa chính bạn.", 'danger')
            return redirect(url_for('admin_dashboard'))

        db.session.delete(user)
        db.session.commit()
        flash('Người dùng đã được xóa.', 'success')
    except:
        db.session.rollback()
        flash('Xóa thất bại.', 'danger')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/reset_password/<int:user_id>')
@admin_required
def reset_user_password(user_id):
    user = User.query.get_or_404(user_id)
    if user.username == session['username']:
        flash("Bạn không thể đặt lại mật khẩu của bạn.", 'danger')
        return redirect(url_for('admin_dashboard'))
    new_password = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
    new_salt = generate_salt()
    new_encrypted = hash_password(new_password, new_salt, user.username)
    user.salt = new_salt
    user.encrypted_password = new_encrypted
    db.session.commit()
    flash(f"Mật khẩu cho người dùng '{user.username}' đã được đặt lại. Mật khẩu mới: {new_password}", 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/toggle_admin/<int:user_id>')
@admin_required
def toggle_admin(user_id):
    user = User.query.get_or_404(user_id)
    if user.username == session['username']:
        flash("Bạn không thể thay đổi trạng thái quản trị của bạn.", 'danger')
        return redirect(url_for('admin_dashboard'))
    user.is_admin = not user.is_admin
    db.session.commit()
    flash(f"Trạng thái quản trị của người dùng '{user.username}' đã được thay đổi thành: {'Quản trị' if user.is_admin else 'Người dùng'}.", 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/statistics')
@admin_required
def admin_statistics():
    total_users = User.query.count()
    locked_users = User.query.filter_by(is_locked=True).count()
    admin_count = User.query.filter_by(is_admin=True).count()
    total_logs = LoginLog.query.count()
    success_logs = LoginLog.query.filter_by(success=True).count()
    failed_logs = LoginLog.query.filter_by(success=False).count()
    # Top 5 user đăng nhập nhiều nhất
    top_users = db.session.query(LoginLog.username, func.count(LoginLog.id).label('login_count')) \
        .group_by(LoginLog.username).order_by(func.count(LoginLog.id).desc()).limit(5).all()
    # Top 5 user bị khóa nhiều nhất (dựa vào fail_attempts)
    top_locked = User.query.order_by(User.fail_attempts.desc()).limit(5).all()
    return render_template('admin/statistics.html',
        total_users=total_users,
        locked_users=locked_users,
        admin_count=admin_count,
        total_logs=total_logs,
        success_logs=success_logs,
        failed_logs=failed_logs,
        top_users=top_users,
        top_locked=top_locked
    )

@app.route('/admin/settings', methods=['GET', 'POST'])
@admin_required
def admin_settings():
    cfg = get_config()
    if request.method == 'POST':
        if 'regenerate_key' in request.form:
            key = generate_3des_key()
            with open('3des.key', 'wb') as f:
                f.write(key)
            flash('3DES key regenerated! All current passwords are now invalid and cannot be verified.', 'danger')
        else:
            try:
                max_fail_attempts = int(request.form['max_fail_attempts'])
                cfg['max_fail_attempts'] = max(1, max_fail_attempts)
                save_config(cfg)
                flash('Settings updated.', 'success')
            except Exception as e:
                flash('Invalid input.', 'danger')
    return render_template('admin/settings.html', config=cfg)

def get_config():
    default = {'max_fail_attempts': 5}
    try:
        with open('config.json', 'r') as f:
            return json.load(f)
    except Exception:
        return default

def save_config(cfg):
    with open('config.json', 'w') as f:
        json.dump(cfg, f)

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
