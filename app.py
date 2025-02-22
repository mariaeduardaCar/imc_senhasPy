from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from authlib.integrations.flask_client import OAuth
import psycopg2
import os
from models import  Usuario, bcrypt
from config import DATABASE_URL, SECRET_KEY, GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET
from dotenv import load_dotenv
import jwt
from datetime import datetime, timedelta, timezone
import random
import string
import sqlite3
from flask_cors import CORS
import pytz

# Carrega as variáveis do arquivo .env
load_dotenv()

app = Flask(__name__)
CORS(app)  # Permite chamadas do frontend

bcrypt.init_app(app)


# Converte postgres:// para postgresql:// se necessário
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

app.config["SECRET_KEY"] = SECRET_KEY

# Configuração do Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)

# Configuração do Banco de Dados
conn = psycopg2.connect(DATABASE_URL)
cursor = conn.cursor()

# Configuração do OAuth
oauth = OAuth(app)

google = oauth.register(
    name='google',
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    access_token_url='https://oauth2.googleapis.com/token',
    client_kwargs={
        'scope': 'openid email profile',
        'token_endpoint_auth_method': 'client_secret_post',
        'userinfo_endpoint': 'https://openidconnect.googleapis.com/v1/userinfo',
    },
    jwks_uri='https://www.googleapis.com/oauth2/v3/certs'
)

@login_manager.user_loader
def load_user(user_id):
    cursor.execute("SELECT id, nome, email FROM usuario WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    return Usuario(*user) if user else None

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/imc")
def index_imc():
    return render_template("imc.html")

@app.route("/login/google")
def login_google():
    return google.authorize_redirect("http://127.0.0.1:5000/login/google/callback", prompt="consent")


@app.route("/login/google/callback")
def google_authorized():
    token = google.authorize_access_token()
    if not token:
        return jsonify({"erro": "Falha no login com o Google."}), 400
    
    session['google_token'] = token
    user_info = google.get('https://www.googleapis.com/oauth2/v1/userinfo').json()
    
    cursor.execute("SELECT id FROM usuario WHERE email = %s", (user_info['email'],))
    usuario = cursor.fetchone()
    
    if not usuario:
        cursor.execute("INSERT INTO usuario (nome, email) VALUES (%s, %s) RETURNING id", (user_info['name'], user_info['email']))
        conn.commit()
        usuario = cursor.fetchone()
    
    login_user(Usuario(usuario[0], user_info['name'], user_info['email']))
    return redirect(url_for('index_imc'))

@app.route("/cadastro", methods=["POST"])
def cadastrar_usuario():
    dados = request.json
    if not dados or not dados.get("nome") or not dados.get("email") or not dados.get("senha_hash"):
        return jsonify({"erro": "Todos os campos são obrigatórios"}), 400
    
    # Verifica se o e-mail já está cadastrado
    cursor.execute("SELECT id FROM usuario WHERE email = %s", (dados["email"],))
    if cursor.fetchone():
        return jsonify({"erro": "E-mail já cadastrado"}), 400

    # Cria o hash da senha
    senha_hash = bcrypt.generate_password_hash(dados["senha_hash"]).decode("utf-8")
    
    # Insere o usuário no banco de dados com a senha criptografada
    cursor.execute("INSERT INTO usuario (nome, email, senha_hash) VALUES (%s, %s, %s)", (dados["nome"], dados["email"], senha_hash))
    conn.commit()
    
    return jsonify({"mensagem": "Usuário cadastrado com sucesso!"}), 201


from flask_login import login_user

@app.route("/login", methods=["POST"])
def login():
    dados = request.json
    cursor.execute("SELECT id, nome, senha_hash FROM usuario WHERE email = %s", (dados["email"],))
    usuario = cursor.fetchone()
    
    if usuario and bcrypt.check_password_hash(usuario[2], dados["senha_hash"]):
        user_obj = Usuario(usuario[0], usuario[1], dados["email"])
        login_user(user_obj)  # Registra o usuário como logado
        token = criar_token(usuario[0])
        return jsonify({"mensagem": f"Bem-vindo, {usuario[1]}!", "token": token})

    return jsonify({"erro": "Credenciais inválidas"}), 401


@app.route("/perfil", methods=["GET"])
def perfil():
    token = request.headers.get("Authorization")
    if not token:
        return jsonify({"erro": "Token não fornecido"}), 401
    
    user_id = verificar_token(token)
    if not user_id:
        return jsonify({"erro": "Token inválido ou expirado"}), 401
    
    cursor.execute("SELECT nome, email FROM usuario WHERE id = %s", (user_id,))
    usuario = cursor.fetchone()
    
    if usuario:
        return jsonify({"nome": usuario[0], "email": usuario[1]})
    return jsonify({"erro": "Usuário não encontrado"}), 404


@app.route("/logout", methods=["GET"])
@login_required
def logout():
    logout_user()
    return jsonify({"mensagem": "Logout realizado com sucesso!"})

# Função para criar um token JWT

def criar_token(user_id):
    payload = {
        "user_id": user_id,
        "exp": datetime.now(timezone.utc) + timedelta(hours=1)  # Token expira em 1 hora
    }
    token = jwt.encode(payload, app.config["SECRET_KEY"], algorithm="HS256")
    return token


def verificar_token(token):
    try:
        payload = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
        return payload["user_id"]
    except jwt.ExpiredSignatureError:
        return None  # Token expirou
    except jwt.InvalidTokenError:
        return None  # Token inválido

# Função para gerar senha aleatória
def gerar_senha(comprimento=12, com_numeros=True, com_simbolos=True):
    caracteres = string.ascii_letters  # Letras (maiúsculas e minúsculas)
    
    if com_numeros:
        caracteres += string.digits  # Adiciona números
    
    if com_simbolos:
        caracteres += string.punctuation  # Adiciona símbolos

    senha = ''.join(random.choice(caracteres) for _ in range(comprimento))
    return senha

# Criar banco de dados e tabela
def criar_banco():
    conn = sqlite3.connect('senhas.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS senhas (
            id INTEGER PRIMARY KEY,
            senha TEXT
        )
    ''')
    conn.commit()
    conn.close()

# Salvar senha no banco de dados (criptografada)
def salvar_senha(senha):
    senha_criptografada = bcrypt.generate_password_hash(senha).decode('utf-8')  # Gera o hash e converte para string
    conn = sqlite3.connect('senhas.db')
    cursor = conn.cursor()
    cursor.execute('INSERT INTO senhas (senha) VALUES (?)', (senha_criptografada,))
    conn.commit()
    conn.close()

# Rota para gerar senha
@app.route('/gerar_senha', methods=['POST'])
def gerar_senha_api():
    dados = request.json
    comprimento = int(dados.get('comprimento', 12))
    com_numeros = dados.get('com_numeros', True)
    com_simbolos = dados.get('com_simbolos', True)
    
    senha_gerada = gerar_senha(comprimento, com_numeros, com_simbolos)
    salvar_senha(senha_gerada)  # Salvar no banco de dados
    
    return jsonify({'senha': senha_gerada})


@app.route("/calcular_imc", methods=["POST"])
@login_required
def calcular_imc():
    dados = request.json
    altura = float(dados.get("altura"))
    peso = float(dados.get("peso"))

    if not altura or not peso:
        return jsonify({"erro": "Altura e peso são obrigatórios"}), 400

    imc = peso / (altura ** 2)  # Cálculo do IMC
    data_consulta_utc = datetime.now(timezone.utc)  # Data atual em UTC

    # Converter para o fuso horário desejado (exemplo: Brasil)
    fuso_horario = pytz.timezone('America/Sao_Paulo')  # Ajuste conforme necessário
    data_consulta = data_consulta_utc.astimezone(fuso_horario)  # Converter para o fuso horário

    # Salvar no banco
    cursor.execute(
        "INSERT INTO imc (user_id, altura, peso, imc, data_consulta) VALUES (%s, %s, %s, %s, %s)",
        (current_user.id, altura, peso, imc, data_consulta)
    )
    conn.commit()

    return jsonify({
        "mensagem": "IMC calculado e salvo com sucesso!",
        "imc": round(imc, 2),
        "data": data_consulta.strftime("%d/%m/%Y %H:%M:%S")
    })

# Rodar o servidor Flask
if __name__ == '__main__':
    criar_banco()
    app.run(debug=True)