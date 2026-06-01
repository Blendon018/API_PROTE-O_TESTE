import os
import bcrypt
from dotenv import load_dotenv
from flask import Flask, request, render_template, redirect, make_response
from flask_jwt_extended import JWTManager, create_access_token, verify_jwt_in_request, get_jwt_identity
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import datetime

load_dotenv()

# =========================================
# APP
# =========================================

app = Flask(__name__)

# =========================================
# JWT
# =========================================

app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", "chave_local_dev_32_caracteres_ok!")
app.config["JWT_TOKEN_LOCATION"] = ["cookies"]
app.config["JWT_COOKIE_CSRF_PROTECT"] = False

jwt = JWTManager(app)

# =========================================
# FIREWALL / RATE LIMIT
# =========================================

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["10 per minute"]
)

# =========================================
# VARIÁVEIS
# =========================================

blocked_ips = set()

login_attempts = {}

USUARIO = {
    "login": os.getenv("APP_LOGIN", ""),
    "senha_hash": os.getenv("APP_SENHA", "").encode("utf-8")
}

# =========================================
# LOGS
# =========================================

def log_event(evento):

    ip = get_remote_address()

    horario = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

    with open("logs.txt", "a", encoding="utf-8") as log:

        log.write(
            f"[{horario}] IP: {ip} - {evento}\n"
        )

# =========================================
# FIREWALL GLOBAL
# =========================================

@app.before_request
def firewall_check():

    ip = get_remote_address()

    if ip in blocked_ips:

        log_event("IP bloqueado tentando acessar")

        return "IP bloqueado pelo firewall", 403

# =========================================
# TELA LOGIN
# =========================================

@app.route("/")
def tela_login():

    return render_template("login.html")

# =========================================
# LOGIN
# =========================================

@app.route("/login", methods=["POST"])
@limiter.limit("3 per minute")
def login():

    ip = get_remote_address()

    login_input = request.form.get("login")

    senha_input = request.form.get("senha", "").encode("utf-8")

    # contador de tentativas
    if ip not in login_attempts:

        login_attempts[ip] = 0

    login_attempts[ip] += 1

    log_event("tentativa de login")

    # brute force
    if login_attempts[ip] > 5:

        blocked_ips.add(ip)

        log_event("IP bloqueado por brute force")

        return "IP bloqueado por tentativas suspeitas", 403

    # login correto
    if (
        login_input == USUARIO["login"]
        and
        bcrypt.checkpw(senha_input, USUARIO["senha_hash"])
    ):

        # resetar tentativas
        login_attempts[ip] = 0

        # criar token
        token = create_access_token(identity=login_input)

        log_event("login bem sucedido")

        # ler logs
        with open("logs.txt", "r", encoding="utf-8") as log:

            logs = log.read()

        # criar resposta com cookie
        response = make_response(render_template(
            "dashboard.html",
            token=token,
            total_bloqueados=len(blocked_ips),
            tentativas=login_attempts,
            logs=logs
        ))

        response.set_cookie(
            "access_token_cookie",
            token,
            httponly=True,
            samesite="Strict"
        )

        return response

    log_event("login invalido")

    return "Login invalido", 401

# =========================================
# PAINEL DE IPS BLOQUEADOS
# =========================================

@app.route("/ips")
def painel_ips():

    try:
        verify_jwt_in_request()
    except:
        log_event("acesso negado a /ips sem token")
        return redirect("/")

    return render_template(
        "ips.html",
        blocked_ips=blocked_ips
    )

# =========================================
# DESBLOQUEAR IP
# =========================================

@app.route("/desbloquear/<ip>")
def desbloquear_ip(ip):

    try:
        verify_jwt_in_request()
    except:
        log_event("acesso negado a /desbloquear sem token")
        return redirect("/")

    if ip in blocked_ips:

        blocked_ips.remove(ip)

        log_event(f"IP {ip} desbloqueado")

    return redirect("/ips")

# =========================================
# LOGOUT
# =========================================

@app.route("/logout")
def logout():

    try:
        verify_jwt_in_request()
    except:
        return redirect("/")

    response = make_response(redirect("/"))

    response.delete_cookie("access_token_cookie")

    log_event("logout realizado")

    return response

# =========================================
# API LOGS
# =========================================

@app.route("/api/logs")
@limiter.exempt
def api_logs():

    try:
        verify_jwt_in_request()
    except:
        return "Não autorizado", 401

    with open("logs.txt", "r", encoding="utf-8") as log:
        logs = log.read()

    return logs

# =========================================
# EXECUTAR SERVIDOR
# =========================================

if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=os.getenv("FLASK_DEBUG", "false").lower() == "true"
    )