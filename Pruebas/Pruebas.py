from flask import Flask, render_template, request
from flask_socketio import SocketIO, emit, join_room

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app, cors_allowed_origins="*")

@socketio.on('join')
def on_join(data):
    room = data['room']
    join_room(room)
    emit('receive_message', {'message': f"{data['username']} ha entrado al chat.", 'username': 'System'}, room=room)

@socketio.on('send_message')
def handle_send_message(data):
    print(f"Received message: {data['message']} from user: {data['username']} in room: {data['room']}")
    emit('receive_message', data, room=data['room'])

@app.route('/')
def index():
    return render_template('index.html')

if __name__ == '__main__':
    socketio.run(app, debug=True)
