import os
import bcrypt
from flask import Flask, request, render_template, redirect, url_for, flash
from werkzeug.utils import secure_filename
import mysql.connector

app = Flask(__name__)

app.secret_key = 'secreto'
app.config['UPLOAD_FOLDER'] = 'uploads'
conexion = mysql.connector.connect(user='root', password='Mysqlserver1',
                                   host='localhost',
                                   database='web_app',
                                   port='3306')



@app.route('/')
def principal():
    return render_template('home2.html')

@app.route('/library')
def library():
    return render_template('library.html')

@app.route('/recover_password')
def recover_password():
    return render_template('recover_password.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password_hash = request.form['password_hash']

        cursor = conexion.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()
        cursor.close()

        if user and bcrypt.checkpw(password_hash.encode('utf-8'), user['password_hash'].encode('utf-8')):
            flash('Inicio de sesión exitoso', 'success')
            return redirect(url_for('principal'))
        else:
            flash('Nombre de usuario o contraseña incorrectos', 'danger')
    
    return render_template('login.html')

#Register
@app.route('/register', methods=['GET', 'POST'])
def register():
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            password2 = request.form['password2']

            cursor = conexion.cursor(dictionary=True)
            cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
            user = cursor.fetchone()
            if password == password2:

                if user:
                    flash('El nombre de usuario ya existe. Por favor, elige otro.', 'danger')
                    cursor.close()

                password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

                cursor.execute("INSERT INTO users (username, password_hash, gender) VALUES (%s, %s, %s)", (username, password_hash, 'Otro'))
                conexion.commit()
                cursor.close()

            flash('Usuario registrado exitosamente', 'success')
            return redirect(url_for('login'))

        return render_template('register.html')

@app.route('/worker_layout', methods=['GET', 'POST'])
def worker_layout():
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
            first_letter = filename[0].upper()  # Leer la primera letra y convertirla a mayúscula
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

    return render_template('worker_layout.html', docs=docs)

if __name__ == '__main__':
    app.run(debug=True)