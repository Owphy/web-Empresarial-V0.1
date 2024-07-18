from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import os
import secrets
import smtplib
import bcrypt
from flask import Flask, request, render_template, redirect, url_for, flash, send_from_directory, jsonify, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_socketio import SocketIO, emit, join_room, leave_room
import mysql.connector
from flask_wtf.csrf import CSRFProtect
from functools import wraps
import socketio
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'secreto'
csrf = CSRFProtect(app)
csrf.init_app(app)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['WTF_CSRF_SECRET_KEY'] = 'clave_csrf'
csrf.init_app(app)
socketio = SocketIO(app, cors_allowed_origins="*")

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

# Verificar conexión a la base de datos
def check_db_connection():
    try:
        conexion.ping(reconnect=True, attempts=3, delay=5)
        print("Conexión a la base de datos exitosa.---------------------------------------------------------------")
    except mysql.connector.Error as err:
        print(f"-------------------------------------------------------Error al conectar a la base de datos: {err}")

check_db_connection()

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
#chat-events-start--------------------------------------------------------

@app.route('/chat_all_users', methods=['GET', 'POST'])
@login_required
@roles_required(1, 2, 3)
def chat_all_users():
    if request.method == 'POST':
        data = request.get_json()
        room = 'chat_all_users'
        message = data.get('message')
        file_path = data.get('file_path', None)
        username = current_user.username

        # Guardar el mensaje en la base de datos
        cursor = conexion.cursor()
        query = """
            INSERT INTO chat_message (room_id, user_id, username, message, file_path)
            VALUES (%s, %s, %s, %s, %s)
        """
        cursor.execute(query, (room, current_user.id, username, message, file_path))
        conexion.commit()
        cursor.close()

        # Emitir el mensaje a la sala correspondiente
        socketio.emit('receive_message', {
            'username': username,
            'message': message,
            'file_path': file_path
        }, room=room)

        return jsonify(success=True)

    # Manejar GET para cargar la página de chat
    return render_template('chat/chat_all_users.html')

@app.route('/chat_all_admin', methods=['GET', 'POST'])
@login_required
@roles_required(2, 1)  # Asegúrate de que los roles sean correctos
def chat_all_admin():
    if request.method == 'POST':
        try:
            data = request.get_json()
            room = 'chat_all_admin'
            message = data.get('message')
            file_path = data.get('file_path', None)
            username = current_user.username

            # Guardar el mensaje en la base de datos
            cursor = conexion.cursor()
            query = """
                INSERT INTO chat_message (room_id, user_id, username, message, file_path)
                VALUES (%s, %s, %s, %s, %s)
            """
            cursor.execute(query, (room, current_user.id, username, message, file_path))
            conexion.commit()
            cursor.close()

            # Emitir el mensaje a la sala correspondiente
            socketio.emit('receive_message', {
                'username': username,
                'message': message,
                'file_path': file_path
            }, room=room)

            return jsonify(success=True)
        except Exception as e:
            print(f"----------------------------------------------------Error processing request: {e}")
            return jsonify(success=False, error=str(e)), 500

    # Manejar GET para cargar la página de chat
    return render_template('chat/chat_all_admin.html')

@app.route('/chat_all_editor', methods=['GET, POST'])
@login_required
@roles_required(2)
def chat_all_editor():
    if request.method == 'POST':
        data = request.get_json()
        room = 'chat_all_editor'
        message = data.get('message')
        file_path = data.get('file_path', None)
        username = current_user.username

        # Guardar el mensaje en la base de datos
        cursor = conexion.cursor()
        query = """
            INSERT INTO chat_message (room_id, user_id, username, message, file_path)
            VALUES (%s, %s, %s, %s, %s)
        """
        cursor.execute(query, (room, current_user.id, username, message, file_path))
        conexion.commit()
        cursor.close()

        # Emitir el mensaje a la sala correspondiente
        socketio.emit('receive_message', {
            'username': username,
            'message': message,
            'file_path': file_path
        }, room=room)

        return jsonify(success=True)

    # Manejar GET para cargar la página de chat
    return render_template('chat/chat_all_editor.html')


@app.route('/get_messages/<room>', methods=['GET'])
@login_required
def get_messages(room):
    try:
        cursor = conexion.cursor(dictionary=True)
        cursor.execute("SELECT * FROM chat_message WHERE room_id = %s ORDER BY created_at ASC", (room,))
        messages = cursor.fetchall()
        cursor.close()
    except mysql.connector.Error as err:
        return jsonify(success=False, error=str(err)), 500

    return jsonify(messages)

@app.route('/upload_file', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    if file:
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        try:
            file.save(filepath)
        except Exception as e:
            return jsonify({'error': str(e)}), 500

        return jsonify({'file_path': filepath}), 200
    return jsonify({'error': 'File not saved'}), 500


@socketio.on('join')
def on_join(data):
    room = data['room']
    join_room(room)
    emit('receive_message', {'message': f'{current_user.username} ha entrado al chat.'}, room=room)

@socketio.on('leave')
def on_leave(data):
    room = data['room']
    leave_room(room)
    emit('receive_message', {'message': f'{current_user.username} ha salido del chat.'}, room=room)

@socketio.on('clear')
def clear_messages(data):
    room = data['room']
    # Eliminar mensajes de la base de datos
    cursor = conexion.cursor()
    cursor.execute("DELETE FROM chat_message WHERE room_id = %s", (room,))
    conexion.commit()
    cursor.close()

    emit('clear', room=room)

@socketio.on('disable_role_1')
def disable_role_1(data):
    room = data['room']
    # Aquí puedes añadir lógica para deshabilitar a los usuarios de rol 1
    emit('disable_role_1', room=room)

@socketio.on('enable_role_1')
def enable_role_1(data):
    room = data['room']
    # Aquí puedes añadir lógica para habilitar a los usuarios de rol 1
    emit('enable_role_1', room=room)

# Definir la ruta para cargar archivos estáticos
@app.route('/chat_uploads/<filename>')
@login_required
def chat_uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


#chat-events-end----------------------------------------------------------
#templates

@app.route('/')
def index():
    return redirect(url_for('login'))

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
                flash('Inicio de sesión exitoso como Administrador', 'success')
                return redirect(url_for('home2_commonUsers'))
            if user['role_id'] == 2:
                flash('Inicio de sesión exitoso como Editor', 'success')
                return redirect(url_for('home_editor'))
            elif user['role_id'] == 3:
                flash('Inicio de sesión exitoso como Espectador', 'success')
                return redirect(url_for('home2'))
            else:
                flash('Rol no reconocido', 'danger')
        else:
            flash('Nombre de usuario o contraseña incorrectos', 'danger')

    return render_template('auth/login.html')

#Home-editor-templates
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    cursor = conexion.cursor(dictionary=True)
    cursor.execute("SELECT username, email, created_at FROM users WHERE id = %s", (current_user.id,))
    user_data = cursor.fetchone()
    cursor.close()

    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if not bcrypt.checkpw(current_password.encode('utf-8'), current_user.password_hash.encode('utf-8')):
            flash('La contraseña actual es incorrecta', 'danger')
        elif new_password != confirm_password:
            flash('Las nuevas contraseñas no coinciden', 'danger')
        else:
            new_password_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            cursor = conexion.cursor()
            cursor.execute("UPDATE users SET password_hash = %s WHERE id = %s", (new_password_hash, current_user.id))
            conexion.commit()
            cursor.close()
            flash('Password updated successfully', 'success')
    
    return render_template('auth/profile.html', user_data=user_data)

@app.route('/home_editor')
@login_required
@roles_required(2)
def home_editor():
    cursor = conexion.cursor(dictionary=True)
    cursor.execute("SELECT section_id, content FROM editable_texts")
    editable_texts = cursor.fetchall()
    cursor.close()
    texts = {text['section_id']: text['content'] for text in editable_texts}
    return render_template('edit/home_editor.html', editable_texts=texts)

@app.route('/home_editor')
@login_required
@roles_required(2) 
def layout_editor():
    return render_template('edit/layout_editor.html')

@app.route('/save_text', methods=['POST'])
@login_required
@roles_required(2)
def save_text():
    data = request.get_json()
    section_id = data['section_id']
    content = data['content']

    cursor = conexion.cursor()
    cursor.execute("UPDATE editable_texts SET content = %s WHERE section_id = %s", (content, section_id))
    conexion.commit()
    cursor.close()

    return jsonify(success=True)

#Home
@app.route('/logout', methods=['POST'])
def logout():
    logout_user()
    flash('Has cerrado sesión', 'success')
    return redirect(url_for('login'))

@app.route('/chatUsers')
@login_required
@roles_required(1, 3, 2)
def chatUsers():
    return render_template('user/chatUsers.html')

@app.route('/home2')
@login_required
@roles_required(1, 3, 2)
def home2():
    return render_template('user/home2.html')

@app.route('/library_commonUsers')
@login_required
@roles_required(1, 3, 2)
def library_commonUsers():
    cursor = conexion.cursor(dictionary=True)
    cursor.execute("SELECT * FROM library")
    files = cursor.fetchall()
    cursor.close()
    return render_template('user/library_commonUsers.html', files=files, os_path_join=os_path_join)

@app.route('/layout')
@login_required
@roles_required(1, 3, 2)
def layout():
    return render_template('user/layout.html')

@app.route('/layout_commonUsers')
@login_required
@roles_required(1, 2)
def layout_commonUsers():
    return render_template('admin/layout_commonUsers.html')

@app.route('/home2_commonUsers')
@login_required
@roles_required(1, 2)
def home2_commonUsers():
    return render_template('admin/home2_commonUsers.html')

@app.route('/uploads/<path:filename>')
@login_required
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/library_admin', methods=['GET', 'POST'])
@login_required
@roles_required(1, 2)
def library_admin():
    cursor = conexion.cursor(dictionary=True)
    cursor.execute("SELECT * FROM library")
    files = cursor.fetchall()
    cursor.close()

    if request.method == 'POST':
        file = request.files['file']
        category = request.form['category']
        if file:
            filename = secure_filename(file.filename)
            letter = filename[0].upper()
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], letter, filename)
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            file.save(filepath)
            
            # Guarda la ruta en la forma correcta en la base de datos
            file_path_db = os.path.join(letter, filename).replace("\\", "/")
            
            cursor = conexion.cursor()
            cursor.execute("INSERT INTO library (filename, file_path, category) VALUES (%s, %s, %s)", 
                           (filename, file_path_db, category))
            conexion.commit()
            cursor.close()
                
            flash(f'Archivo {filename} subido exitosamente en la categoría {category}.', 'success')
            return redirect(url_for('library_admin'))

    return render_template('admin/library_admin.html', files=files)


@app.route('/recover_password', methods=['GET', 'POST'])
def recover_password():
    if request.method == 'POST':
        email = request.form['email']
        cursor = conexion.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        
        if user:
            token = secrets.token_urlsafe(16)
            cursor.execute("INSERT INTO password_reset_tokens (email, token) VALUES (%s, %s)", (email, token))
            conexion.commit()
            
            send_email(email, token)
            flash('Se ha enviado un código de recuperación a tu correo electrónico.', 'success')
        else:
            flash('El correo electrónico no está registrado.', 'danger')
        
        cursor.close()
    
    return render_template('auth/recover_password.html')

def send_email(to_email, token):
    msg = MIMEMultipart()
    msg['From'] = SMTP_USERNAME
    msg['To'] = to_email
    msg['Subject'] = 'Recuperación de contraseña'

    body = f'Tu código de recuperación es: {token}\n\n'
    body += f'http://127.0.0.1:5000/reset_password/{token}'
    msg.attach(MIMEText(body, 'plain'))

    server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
    server.starttls()
    server.login(SMTP_USERNAME, SMTP_PASSWORD)
    text = msg.as_string()
    server.sendmail(SMTP_USERNAME, to_email, text)
    server.quit()

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if request.method == 'POST':
        password = request.form['password']
        password2 = request.form['password2']
        
        if password != password2:
            flash('Las contraseñas no coinciden.', 'danger')
            return redirect(url_for('reset_password', token=token))
        
        cursor = conexion.cursor(dictionary=True)
        cursor.execute("SELECT email FROM password_reset_tokens WHERE token = %s", (token,))
        record = cursor.fetchone()
        
        if record:
            email = record['email']
            password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            cursor.execute("UPDATE users SET password_hash = %s WHERE email = %s", (password_hash, email))
            conexion.commit()
            cursor.execute("DELETE FROM password_reset_tokens WHERE token = %s", (token,))
            conexion.commit()
            cursor.close()
            flash('Tu contraseña ha sido actualizada.', 'success')
            return redirect(url_for('login'))
        else:
            flash('El token de recuperación es inválido o ha expirado.', 'danger')
            return redirect(url_for('recover_password'))
    
    return render_template('auth/reset_password.html', token=token)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        password2 = request.form['password2']
        gender = request.form['gender']

        cursor = conexion.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE username = %s OR email = %s", (username, email))
        user = cursor.fetchone()

        if user:
            if user['username'] == username:
                flash('El nombre de usuario ya existe. Por favor, elige otro.', 'danger')
            if user['email'] == email:
                flash('El correo electrónico ya existe. Por favor, elige otro.', 'danger')
            cursor.close()
            return redirect(url_for('register'))

        if password != password2:
            flash('Las contraseñas no coinciden.', 'danger')
            return redirect(url_for('register'))

        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        cursor.execute("INSERT INTO users (username, email, password_hash, gender) VALUES (%s, %s, %s, %s)", 
                       (username, email, password_hash, gender))
        user_id = cursor.lastrowid  #  ID del usuario recién insertado

        # rol de 'viewer' (id 3) al nuevo usuario
        cursor.execute("INSERT INTO user_roles (user_id, role_id) VALUES (%s, 3)", (user_id,))


        conexion.commit()
        cursor.close()

        flash('Usuario registrado exitosamente', 'success')
        return redirect(url_for('login'))

    return render_template('auth/register.html')

@app.route('/worker_layout_admin', methods=['GET', 'POST'])
@login_required
@roles_required(1, 2)
def worker_layout_admin():
    docs = {chr(i): [] for i in range(65, 65+26)}
    
    cursor = conexion.cursor(dictionary=True)
    cursor.execute("SELECT * FROM files")
    files = cursor.fetchall()
    cursor.close()

    for file in files:
        docs[file['letter']].append(file['filename'])

    if request.method == 'POST':
        file = request.files['file']
        if file:
            filename = secure_filename(file.filename)
            first_letter = filename[0].upper()
            if first_letter in docs:
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], first_letter, filename)
                os.makedirs(os.path.dirname(filepath), exist_ok=True)
                file.save(filepath)
                
                cursor = conexion.cursor()
                cursor.execute("INSERT INTO files (filename, file_path, letter) VALUES (%s, %s, %s)", 
                               (filename, filepath, first_letter))
                conexion.commit()
                cursor.close()
                
                docs[first_letter].append(filename)
                flash(f'Archivo {filename} subido exitosamente en la sección {first_letter}.', 'success')
            else:
                flash('La primera letra del nombre del archivo no es válida.', 'danger')

    return render_template('admin/worker_layout_admin.html', docs=docs, os_path_join=os_path_join)

if __name__ == '__main__':
    app.config['UPLOAD_FOLDER'] = 'uploads'
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    socketio.run(app, debug=True)

    