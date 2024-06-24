import os
from flask import Flask

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'

@app.route('/check_write_permissions')
def check_write_permissions():
    try:
        test_path = os.path.join(app.config['UPLOAD_FOLDER'], 'test.txt')
        with open(test_path, 'w') as test_file:
            test_file.write('Testing write permissions.')
        os.remove(test_path)
        return 'Permissions are set correctly for writing.'
    except IOError:
        return 'Permissions are NOT set correctly for writing.'

if __name__ == '__main__':
    app.run(debug=True)
