import os
import secrets
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import bcrypt
from flask import Flask, request, render_template, redirect, url_for, flash, send_from_directory
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.utils import secure_filename
import mysql.connector
from flask_wtf.csrf import CSRFProtect
from functools import wraps

app = Flask(__name__)

app.secret_key = 'secreto'
csrf = CSRFProtect(app)
csrf.init_app(app)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['WTF_CSRF_SECRET_KEY'] = 'clave_csrf'
app.config['WTF_CSRF_TIME_LIMIT'] = 60


# Define os_path_join function
def os_path_join(*args):
    return os.path.join(*args).replace("\\", "/")

# Update Jinja environment to include os_path_join
app.jinja_env.globals.update(os_path_join=os_path_join)


# Conexión a la base de datos
conexion = mysql.connector.connect(user='root', password='Mysqlserver1',
                                   host='localhost',
                                   database='web_app',
                                   port='3306')

# Configuración de Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 587
SMTP_USERNAME = os.getenv('SMTP_USERNAME', 'servermy188@gmail.com')
SMTP_PASSWORD = os.getenv('SMTP_PASSWORD', 'pmen jwza dxvj znnw')

# Función de utilidad para construir la ruta correctamente
def os_path_join(folder, filename):
    return os.path.join(folder, filename).replace("\\", "/")

# Modelo de Usuario
class User(UserMixin):
    def __init__(self, id, username, password_hash, role_id):
        self.id = id
        self.username = username
        self.password_hash = password_hash
        self.role_id = role_id

@login_manager.user_loader
def load_user(user_id):
    cursor = conexion.cursor(dictionary=True)
    cursor.execute("""
        SELECT u.*, ur.role_id 
        FROM users u
        LEFT JOIN user_roles ur ON u.id = ur.user_id
        WHERE u.id = %s
    """, (user_id,))
    user = cursor.fetchone()
    cursor.close()
    if user:
        return User(id=user['id'], username=user['username'], password_hash=user['password_hash'], role_id=user['role_id'])
    return None

def roles_required(*roles):
    def decorator(func):
        @wraps(func)
        def decorated_view(*args, **kwargs):
            if not current_user.is_authenticated or current_user.role_id not in roles:
                flash('No tienes permiso para acceder a esta página.', 'danger')
                return redirect(url_for('login'))
            return func(*args, **kwargs)
        return decorated_view
    return decorator


@app.route('/')
def principal():
    return render_template('/index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        cursor = conexion.cursor(dictionary=True)
        cursor.execute("SELECT u.*, ur.role_id FROM users u LEFT JOIN user_roles ur ON u.id = ur.user_id WHERE u.username = %s", (username,))
        user = cursor.fetchone()

        if user and bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
            user_obj = User(id=user['id'], username=user['username'], password_hash=user['password_hash'], role_id=user['role_id'])
            login_user(user_obj)
            if user['role_id'] == 1:
                flash('Inicio de sesión exitoso como administrador', 'success')
                return redirect(url_for('home2_commonUsers'))
            elif user['role_id'] == 3:
                flash('Inicio de sesión exitoso como espectador', 'success')
                return redirect(url_for('home2'))
            else:
                flash('Rol no reconocido', 'danger')
        else:
            flash('Nombre de usuario o contraseña incorrectos', 'danger')

    return render_template('auth/login.html')

if __name__ == '__main__':
    app.run(debug=True)
