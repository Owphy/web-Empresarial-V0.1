from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import os
import secrets
import smtplib
import bcrypt
from flask import Flask, json, request, render_template, redirect, url_for, flash, send_from_directory, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from functools import wraps
from sqlalchemy import text
from werkzeug.utils import secure_filename
import logging
logging.basicConfig(level=logging.DEBUG)


app = Flask(__name__)
app.secret_key = 'secreto'
csrf = CSRFProtect(app)
csrf.init_app(app)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['WTF_CSRF_SECRET_KEY'] = 'clave_csrf'
csrf.init_app(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Configuración de la base de datos
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://root:Mysqlserver1@localhost:3306/web_app'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Configuración de Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Crear la base de datos y las tablas
@app.before_request
def create_tables():
    if not hasattr(app, 'db_initialized'):
        db.create_all()
        app.db_initialized = True

# Define os_path_join function
def os_path_join(*args):
    return os.path.join(*args).replace("\\", "/")

# Update Jinja environment to include os_path_join
app.jinja_env.globals.update(os_path_join=os_path_join)

SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 587
SMTP_USERNAME = os.getenv('SMTP_USERNAME', 'servermy188@gmail.com')
SMTP_PASSWORD = os.getenv('SMTP_PASSWORD', 'pmen jwza dxvj znnw')

# Modelo de Usuario
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    gender = db.Column(db.String(50), nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

# Modelo de Rol de Usuario
class UserRole(db.Model):
    __tablename__ = 'user_roles'
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
    role_id = db.Column(db.Integer, primary_key=True)

# Modelo de Mensaje de Chat
class ChatMessage(db.Model):
    __tablename__ = 'chat_message'
    id = db.Column(db.Integer, primary_key=True)
    room_id = db.Column(db.String(255), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    username = db.Column(db.String(255), nullable=False)
    message = db.Column(db.Text, nullable=True)
    file_path = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def get_user_roles(user_id):
    roles = UserRole.query.filter_by(user_id=user_id).all()
    return [role.role_id for role in roles]

def roles_required(*roles):
    def decorator(func):
        @wraps(func)
        def decorated_view(*args, **kwargs):
            if not current_user.is_authenticated or not any(role in roles for role in get_user_roles(current_user.id)):
                flash('No tienes permiso para acceder a esta página.', 'danger')
                return redirect(url_for('login'))
            return func(*args, **kwargs)
        return decorated_view
    return decorator

# Modelo para estado de envío de mensajes
class SendState(db.Model):
    __tablename__ = 'send_state'
    id = db.Column(db.Integer, primary_key=True)
    state = db.Column(db.String(50), nullable=False)
#-----------------Start_templates
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.checkpw(password.encode('utf-8'), user.password_hash.encode('utf-8')):
            login_user(user)
            user_roles = get_user_roles(user.id)
            if 1 in user_roles:
                flash('Inicio de sesión exitoso como Administrador', 'success')
                return redirect(url_for('general_home'))
            if 2 in user_roles:
                flash('Inicio de sesión exitoso como Editor', 'success')
                return redirect(url_for('general_home'))
            if 3 in user_roles:
                flash('Inicio de sesión exitoso como Espectador', 'success')
                return redirect(url_for('general_home'))
            else:
                flash('Rol no reconocido', 'danger')
        else:
            flash('Nombre de usuario o contraseña incorrectos', 'danger')
    return render_template('auth/login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        password2 = request.form['password2']
        gender = request.form['gender']

        user = User.query.filter((User.username == username) | (User.email == email)).first()

        if user:
            if user.username == username:
                flash('El nombre de usuario ya existe. Por favor, elige otro.', 'danger')
            if user.email == email:
                flash('El correo electrónico ya existe. Por favor, elige otro.', 'danger')
            return redirect(url_for('register'))

        if password != password2:
            flash('Las contraseñas no coinciden.', 'danger')
            return redirect(url_for('register'))

        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        new_user = User(username=username, email=email, password_hash=password_hash, gender=gender)
        db.session.add(new_user)
        db.session.commit()

        user_role = UserRole(user_id=new_user.id, role_id=3)
        db.session.add(user_role)
        db.session.commit()

        flash('Usuario registrado exitosamente', 'success')
        return redirect(url_for('login'))

    return render_template('auth/register.html')


@app.route('/layout_commonUsers')
@login_required
@roles_required(1, 2)
def layout_commonUsers():
    return render_template('admin/layout_commonUsers.html')



#General_templates_start#####

@app.route('/general_home')
@login_required
@roles_required(1, 2, 3)
def general_home():
    user_roles = get_user_roles(current_user.id)
    is_editor = 2 in user_roles 

    editable_texts = db.session.execute(text("SELECT section_id, content FROM editable_texts")).fetchall()
    texts = {text[0]: text[1] for text in editable_texts}
    return render_template('general_templates/general_home.html', user_roles=user_roles, editable_texts=texts, is_editor=is_editor)

@app.route('/general_layout')
@login_required
@roles_required(1, 2, 3)
def general_layout():
    user_roles = get_user_roles(current_user.id)
    is_admin = 1 in user_roles
    is_editor = 2 in user_roles
    is_user = 3 in user_roles

    return render_template('general_templates/general_layout.html', is_editor=is_editor, is_admin=is_admin, is_user=is_user)

#General_templates_end#####

#########################################################
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user_data = {
        'username': current_user.username,
        'email': current_user.email,
        'gender': current_user.gender,
        'created_at': current_user.created_at
    }
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
            current_user.password_hash = new_password_hash
            db.session.commit()
            flash('Password updated successfully', 'success')
    return render_template('auth/profile.html', user_data=user_data)

@app.route('/logout', methods=['POST'])
def logout():
    logout_user()
    flash('Has cerrado sesión', 'success')
    return redirect(url_for('login'))

#send_button
@app.route('/toggle_send', methods=['POST'])
@login_required
def toggle_send():
    action = request.form['action']
    state = 'disabled' if action == 'disable' else 'enabled'
    send_state = SendState.query.first()
    if send_state:
        send_state.state = state
    else:
        send_state = SendState(state=state)
        db.session.add(send_state)
    db.session.commit()
    return jsonify(success=True)

@app.route('/check_disable_state', methods=['GET'])
@login_required
def check_disable_state():
    send_state = SendState.query.first()
    disable_send = send_state and send_state.state == 'disabled'
    return jsonify(disable_send=disable_send)

#end_send_button
@app.route('/chat_all_admin', methods=['GET', 'POST'])
@login_required
@roles_required(1, 2, 3)
def chat_all_admin():
    user_roles = get_user_roles(current_user.id)
    is_admin = 1 in user_roles
    is_editor = 2 in user_roles
    is_user = 3 in user_roles
    if request.method == 'POST':
        try:
            logging.debug(f"Request Content-Type: {request.content_type}")
            if request.is_json:
                data = request.get_json()
            else:
                logging.debug("Unsupported Media Type")
                return jsonify(success=False, error="Unsupported Media Type"), 415

            logging.debug(f"Received data: {data}")
            if not data:
                return jsonify(success=False, error="No data provided"), 400

            room = 'chat_all_admin'
            message = data.get('message')
            file_path = data.get('file_path', None)
            username = current_user.username

            if not message:
                return jsonify(success=False, error="Message cannot be empty"), 400

            user_role = UserRole.query.filter_by(user_id=current_user.id).first()
            if not user_role:
                return jsonify(success=False, error="Role not found"), 400

            chat_message = ChatMessage(
                room_id=room,
                role_id=user_role.role_id,
                username=username,
                message=message,
                file_path=file_path
            )
            db.session.add(chat_message)
            db.session.commit()

            socketio.emit('receive_message', {
                'username': username,
                'message': message,
                'file_path': file_path,
                'role_id': user_role.role_id
            }, room=room)

            return jsonify(success=True)
        except Exception as e:
            logging.error(f"Error processing request: {e}")
            return jsonify(success=False, error=str(e)), 500

    return render_template('admin/chat_all_admin.html', user_roles=user_roles, is_editor=is_editor, is_admin=is_admin, is_user=is_user)

@app.route('/worker_layout_admin', methods=['GET', 'POST'])
@login_required
@roles_required(1, 2, 3)
def worker_layout_admin():
    user_roles = get_user_roles(current_user.id)
    is_admin = 1 in user_roles
    is_editor = 2 in user_roles
    is_user = 3 in user_roles
    docs = {chr(i): [] for i in range(65, 65+26)}

    # Consultar los archivos en la base de datos
    files = db.session.execute(text("SELECT filename, letter FROM files")).fetchall()
    for file in files:
        letter = file[1][0].upper()  # Asegurarse de que la letra está en mayúscula
        if letter.isalpha():
            docs[letter].append(file[0])  # Añadir el nombre del archivo a la lista correspondiente

    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No se encontró la parte del archivo en la solicitud', 'danger')
            return redirect(request.url)

        file = request.files['file']
        if file.filename == '':
            flash('No se seleccionó ningún archivo', 'danger')
            return redirect(request.url)

        if file:
            filename = secure_filename(file.filename)
            first_letter = filename[0].upper()
            if first_letter.isalpha():
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], first_letter, filename)
                os.makedirs(os.path.dirname(filepath), exist_ok=True)
                file.save(filepath)
                db.session.execute(text("INSERT INTO files (filename, file_path, letter) VALUES (:filename, :file_path, :letter)"),
                                   {'filename': filename, 'file_path': filepath, 'letter': first_letter})
                db.session.commit()
                docs[first_letter].append(filename)
                flash(f'Archivo {filename} subido exitosamente en la sección {first_letter}.', 'success')
            else:
                flash('La primera letra del nombre del archivo no es válida.', 'danger')
    return render_template('admin/worker_layout_admin.html', docs=docs, os_path_join=os_path_join, is_editor=is_editor, is_admin=is_admin, is_user=is_user, user_roles=user_roles)    


@app.route('/get_messages/<room>', methods=['GET'])
@login_required
def get_messages(room):
    try:
        messages = ChatMessage.query.filter_by(room_id=room).order_by(ChatMessage.created_at.asc()).all()
        return jsonify([{
            'username': msg.username,
            'message': msg.message,
            'file_path': msg.file_path,
            'created_at': msg.created_at
        } for msg in messages])
    except Exception as e:
        return jsonify(success=False, error=str(e)), 500

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
            return jsonify({'file_path': filepath}), 200
        except Exception as e:
            return jsonify({'error': str(e)}), 500
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
    ChatMessage.query.filter_by(room_id=room).delete()
    db.session.commit()
    emit('clear', room=room)

@socketio.on('disable_role_1')
def disable_role_1(data):
    room = data['room']
    print("emit('disable_role_1")
     # Emitir el mensaje a la sala correspondiente
    emit('receive_message', {'message': 'Se ha deshabilitado el chat a los usuarios normales.'}, room=room)

@socketio.on('enable_role_1')
def enable_role_1(data):
    room = data['room']
    emit('enable_role_1', room=room)
    
@socketio.on('send_message')
def handle_send_message(data):
    send_state = SendState.query.first()
    if send_state and send_state.state == 'disabled':
        return jsonify(success=False, error="El envío de mensajes está deshabilitado."), 403
    
    user_role = UserRole.query.filter_by(user_id=current_user.id).first()

    print(f"Received message: {data['message']} from user: {data['username']} in room: {data['room']}")
    
    # Save the message to the database
    chat_message = ChatMessage(
        room_id=data['room'],
        role_id=user_role.role_id,
        username=data['username'],
        message=data['message'],
        file_path=data.get('file_path', None)
    )
    db.session.add(chat_message)
    db.session.commit()
    print("Message saved in database via SocketIO")

    # Emit the message to the appropriate room
    emit('receive_message', data, room=data['room'])

# Definir la ruta para cargar archivos estáticos
@app.route('/chat_uploads/<filename>')
@login_required
def chat_uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/save_text', methods=['POST'])
@login_required
def save_text():
    data = request.get_json()
    section_id = data['section_id']
    content = data['content']
    db.session.execute(text("UPDATE editable_texts SET content = :content WHERE section_id = :section_id"),
                       {'content': content, 'section_id': section_id})
    db.session.commit()
    return jsonify(success=True)

@app.route('/chatUsers')
@login_required
@roles_required(1, 3, 2)
def chatUsers():
    user_roles = get_user_roles(current_user.id)
    is_admin = 1 in user_roles
    is_editor = 2 in user_roles
    is_user = 3 in user_roles
    return render_template('user/chatUsers.html', is_admin=is_admin, is_editor=is_editor, is_user=is_user, user_roles=user_roles)

@app.route('/library_commonUsers')
@login_required
@roles_required(1, 3, 2)
def library_commonUsers():
    files = db.session.execute(text("SELECT * FROM library")).fetchall()
    return render_template('user/library_commonUsers.html', files=files, os_path_join=os_path_join)


@app.route('/uploads/<path:filename>')
@login_required
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/library_admin', methods=['GET', 'POST'])
@login_required
@roles_required(1, 2, 3)
def library_admin():
    user_roles = get_user_roles(current_user.id)
    is_admin = 1 in user_roles
    is_editor = 2 in user_roles
    is_user = 3 in user_roles
    
    files = db.session.execute(text("SELECT * FROM library")).fetchall()
    docs = {chr(i): [] for i in range(65, 65+26)}
    for file in files:
        letter = file[2][0].upper()
        if letter.isalpha():
            if letter not in docs:
                docs[letter] = []
            docs[letter].append(str(file[0]))
    if request.method == 'POST':
        file = request.files['file']
        category = request.form['category']
        if file:
            filename = secure_filename(file.filename)
            letter = filename[0].upper()
            if letter.isalpha():
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], letter, filename)
                os.makedirs(os.path.dirname(filepath), exist_ok=True)
                file.save(filepath)
                file_path_db = os.path.join(letter, filename).replace("\\", "/")
                db.session.execute(text("INSERT INTO library (filename, file_path, category) VALUES (:filename, :file_path, :category)"),
                                   {'filename': filename, 'file_path': file_path_db, 'category': category})
                db.session.commit()
                if letter not in docs:
                    docs[letter] = []
                docs[letter].append(filename)
                flash(f'Archivo {filename} subido exitosamente en la categoría {category}.', 'success')
            else:
                flash('La primera letra del nombre del archivo no es válida.', 'danger')
    return render_template('admin/library_admin.html', files=files, docs=docs, is_admin=is_admin, is_editor=is_editor, is_user=is_user, user_roles=user_roles)

@app.route('/recover_password', methods=['GET', 'POST'])
def recover_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            token = secrets.token_urlsafe(16)
            db.session.execute(text("INSERT INTO password_reset_tokens (email, token) VALUES (:email, :token)"),
                               {'email': email, 'token': token})
            db.session.commit()
            send_email(email, token)
            flash('Se ha enviado un código de recuperación a tu correo electrónico.', 'success')
        else:
            flash('El correo electrónico no está registrado.', 'danger')
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
        record = db.session.execute(text("SELECT email FROM password_reset_tokens WHERE token = :token"), {'token': token}).fetchone()
        if record:
            email = record[0]
            password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            db.session.execute(text("UPDATE users SET password_hash = :password_hash WHERE email = :email"),
                               {'password_hash': password_hash, 'email': email})
            db.session.execute(text("DELETE FROM password_reset_tokens WHERE token = :token"), {'token': token})
            db.session.commit()
            flash('Tu contraseña ha sido actualizada.', 'success')
            return redirect(url_for('login'))
        else:
            flash('El token de recuperación es inválido o ha expirado.', 'danger')
            return redirect(url_for('recover_password'))
    return render_template('auth/reset_password.html', token=token)



@app.route('/new_file', methods=['POST'])
@login_required
@roles_required(1, 2)
def new_file():
    if 'file' not in request.files:
        return jsonify(success=False, error='No file part in the request')
    
    file = request.files['file']
    if file.filename == '':
        return jsonify(success=False, error='No selected file')

    if file:
        filename = secure_filename(file.filename)
        first_letter = filename[0].upper()
        category = request.form['category']
        if first_letter.isalpha():
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], first_letter, filename)
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            file.save(filepath)
            db.session.execute(text("INSERT INTO library (filename, file_path, category) VALUES (:filename, :file_path, :category)"),
                               {'filename': filename, 'file_path': filepath, 'category': category})
            db.session.commit()
            file_url = url_for('uploaded_file', filename=os.path.join(first_letter, filename))
            return jsonify(success=True, filename=filename, file_url=file_url)
        else:
            return jsonify(success=False, error='Invalid file name')


@app.route('/delete_selected_files', methods=['POST'])
@login_required
@roles_required(1, 2)
def delete_selected_files():
    try:
        selected_files = json.loads(request.form.get('selected_files', '[]'))
        if not selected_files:
            raise ValueError("No files selected")

        for file_info in selected_files:
            filename, category = file_info.split('|')
            # Buscar el archivo en la base de datos
            file_record = db.session.execute(text("SELECT file_path FROM library WHERE filename = :filename AND category = :category"),
                                             {'filename': filename, 'category': category}).fetchone()

            if file_record:
                file_path = file_record[0]
                # Eliminar el archivo del sistema de archivos
                full_path = os.path.join(app.config['UPLOAD_FOLDER'], file_path)
                if os.path.exists(full_path):
                    os.remove(full_path)

                # Eliminar el registro de la base de datos
                db.session.execute(text("DELETE FROM library WHERE filename = :filename AND category = :category"),
                                   {'filename': filename, 'category': category})
                db.session.commit()

        flash('Archivos seleccionados eliminados exitosamente.', 'success')

    except Exception as e:
        flash(f'Error al eliminar los archivos seleccionados: {str(e)}', 'danger')

    return redirect(url_for('library_admin'))

@app.route('/delete_selected', methods=['POST'])
@login_required
@roles_required(1, 2)
def delete_selected():
    try:
        selected_files = json.loads(request.form.get('selected_files', '[]'))
        if not selected_files:
            raise ValueError("No files selected")

        for file_info in selected_files:
            filename, letter = file_info.split('|')
            # Buscar el archivo en la base de datos
            file_record = db.session.execute(text("SELECT file_path FROM files WHERE filename = :filename AND letter = :letter"),
                                             {'filename': filename, 'letter': letter}).fetchone()

            if file_record:
                file_path = file_record[0]
                # Eliminar el archivo del sistema de archivos
                full_path = os.path.join(app.config['UPLOAD_FOLDER'], file_path)
                if os.path.exists(full_path):
                    os.remove(full_path)

                # Eliminar el registro de la base de datos
                db.session.execute(text("DELETE FROM files WHERE filename = :filename AND letter = :letter"),
                                   {'filename': filename, 'letter': letter})
                db.session.commit()

        flash('Archivos seleccionados eliminados exitosamente.', 'success')

    except Exception as e:
        flash(f'Error al eliminar los archivos seleccionados: {str(e)}', 'danger')

    return redirect(url_for('worker_layout_admin'))


if __name__ == '__main__':
    app.config['UPLOAD_FOLDER'] = 'uploads'
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    socketio.run(app, debug=True)
