from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_restx import Api, Resource, fields
from werkzeug.security import generate_password_hash, check_password_hash
from jose import jwt, JWTError
import datetime

# Configuração do Flask
app = Flask(__name__)

# Configuração do SQLAlchemy
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'fallback-secret-key'

# Inicialização do SQLAlchemy
db = SQLAlchemy(app)

# API do Flask-RESTPlus
api = Api(app, version='1.0', title='User API', description='A simple User API')

# Modelo do Banco de Dados
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

    def __repr__(self):
        return f'<User {self.username}>'

# Definir o modelo de entrada para o cadastro de usuário
user_model = api.model('User', {
    'username': fields.String(required=True, description='Nome de usuário'),
    'email': fields.String(required=True, description='Email do usuário'),
    'password': fields.String(required=True, description='Senha do usuário')
})

# Funções para JWT
def generate_jwt(payload):
    """Gera um JWT para autenticação."""
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm="HS256")

def verify_jwt(token):
    """Verifica e decodifica um JWT."""
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        return payload
    except JWTError:
        return None

# Rota para registrar usuários
@api.route('/register')
class Register(Resource):
    @api.expect(user_model)
    def post(self):
        data = request.get_json()
        if not all(k in data for k in ('username', 'email', 'password')):
            return jsonify({"error": "Dados insuficientes"}), 400

        hashed_password = generate_password_hash(data['password'], method='sha256')
        new_user = User(username=data['username'], email=data['email'], password=hashed_password)

        db.session.add(new_user)
        db.session.commit()

        return jsonify({"message": "Usuário criado com sucesso"}), 201

# Rota para login
@api.route('/login')
class Login(Resource):
    @api.expect(user_model)
    def post(self):
        data = request.get_json()
        user = User.query.filter_by(username=data['username']).first()
        if user and check_password_hash(user.password, data['password']):
            payload = {
                'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30),
                'iat': datetime.datetime.utcnow(),
                'sub': user.id
            }
            token = generate_jwt(payload)
            return jsonify({"token": token})
        return jsonify({"error": "Nome de usuário ou senha inválidos"}), 401

# Inicializando o banco de dados
if __name__ == '__main__':
    with app.app_context():  # Garante que a criação das tabelas aconteça dentro do contexto da aplicação
        db.create_all()  # Cria as tabelas antes de rodar o app
    app.run(debug=True)

