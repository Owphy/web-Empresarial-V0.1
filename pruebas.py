from flask import Flask, app
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

app = Flask(__name__)
# URL de conexión a la base de datos
DATABASE_URL = "mysql+mysqlconnector://root:Mysqlserver1@localhost:3306/web_app"

# Crear el motor de conexión
engine = create_engine(DATABASE_URL)

# Crear una sesión
Session = sessionmaker(bind=engine)
session = Session()

# Definir el modelo base
Base = declarative_base()

# Definir el modelo User
class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String(80), unique=True, nullable=False)
    email = Column(String(120), unique=True, nullable=False)

    def __repr__(self):
        return f"<User(username='{self.username}', email='{self.email}')>"

# Consultar datos (asegúrate de que la tabla 'users' exista en la base de datos 'web_app')
try:
    users = session.query(User).all()
    count = session.query(User).count()
    print(f'Number of users: {count}')

except Exception as e:
    print("________________________________________________Erro")

# Cerrar la sesión
session.close()

if __name__ == '__main__':
    app.run(debug=True)

