🛡️ API de Proteção com Flask
Projeto prático desenvolvido durante o curso de Cybersegurança no curso de Análise e Desenvolvimento de Sistemas.
Uma API construída com Flask que implementa múltiplas camadas de segurança reais, desde autenticação até proteção contra ataques de força bruta.

🔐 Funcionalidades de Segurança

Variáveis de Ambiente — credenciais armazenadas no .env, nunca no código
Hash de Senha com Bcrypt — senha irreversível, nunca em texto puro
JWT em Cookie HttpOnly — token protegido contra ataques XSS
Rate Limiting — limite de 10 req/min globais e 3 req/min no login
Proteção Brute Force — IP bloqueado automaticamente após 5 tentativas falhas
Firewall Global — verificação de IP em todas as requisições via @before_request
Rotas Protegidas — /ips e /desbloquear exigem autenticação JWT
Logout Seguro — cookie deletado ao sair
Debug desligado — controlado por variável de ambiente
Servidor em Localhost — não exposto à rede por padrão


📊 Dashboard
Interface web com monitoramento em tempo real:

IPs monitorados e bloqueados
Gráfico de tentativas por IP com indicador de risco por cor
Logs do sistema atualizados automaticamente a cada 5 segundos
Token JWT ativo exibido para diagnóstico


🧰 Tecnologias

Python 3.14
Flask
Flask-JWT-Extended
Flask-Limiter
Bcrypt
Python-dotenv

 Como rodar
1. Clone o repositório
bashgit clone https://github.com/Blendon018/API_PROTE-O_TESTE.git
cd API_PROTE-O_TESTE
2. Instale as dependências
bashpip install flask flask-jwt-extended flask-limiter bcrypt python-dotenv
3. Crie o arquivo .env
APP_LOGIN=seu_login
APP_SENHA=hash_bcrypt_da_sua_senha
JWT_SECRET_KEY=sua_chave_secreta_com_32_caracteres
FLASK_DEBUG=false
4. Gere o hash da sua senha
bashpython -c "import bcrypt; print(bcrypt.hashpw(b'suasenha', bcrypt.gensalt()).decode())"
5. Rode o servidor
bashpython app.py
Acesse em http://127.0.0.1:5000


📁 Estrutura do Projeto
api-protecao-flask/
├── app.py
├── .env            ← não versionado
├── .gitignore
├── logs.txt        ← não versionado
└── templates/
    ├── login.html
    ├── dashboard.html
    └── ips.html


 Aviso
Este projeto foi desenvolvido para fins educacionais. Não utilize em produção sem as devidas adaptações como banco de dados, HTTPS e servidor WSGI.
