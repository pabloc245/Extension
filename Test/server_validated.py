#!/usr/bin/env python3
"""
Serveur d'authentification avec bibliothèques de validation
"""
from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import jwt
import secrets
from datetime import datetime, timedelta
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import sqlite3
import logging
import bleach
from email_validator import validate_email, EmailNotValidError
import html

# Logging
import sys

# Fix Windows encoding
if sys.platform == 'win32':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('auth.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)

# Config
SECRET_KEY = os.getenv("SECRET_KEY", secrets.token_urlsafe(32))
PORT = int(os.getenv("PORT", "8000"))
DB_PATH = os.getenv("DB_PATH", "auth.db")

# SMTP Config
SMTP_HOST = os.getenv("SMTP_HOST")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")

rate_limits = {}

def init_db():
    """Initialise la base de données SQLite"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        email TEXT PRIMARY KEY,
        created_at TIMESTAMP,
        last_login TIMESTAMP
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS codes (
        email TEXT PRIMARY KEY,
        code TEXT,
        expires_at TIMESTAMP,
        attempts INTEGER
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS failed_attempts (
        ip TEXT,
        email TEXT,
        timestamp TIMESTAMP
    )''')
    
    conn.commit()
    conn.close()

def sanitize_email(email_input):
    """
    Validation et normalisation d'email avec email-validator
    https://github.com/JoshData/python-email-validator
    """
    try:
        # email-validator fait:
        # - Validation syntaxe RFC 5322
        # - Normalisation (lowercase, trim)
        # - Vérification longueur
        # - Protection contre homoglyphs
        # - Validation domaine
        emailinfo = validate_email(email_input, check_deliverability=False)
        normalized_email = emailinfo.normalized
        
        # Escape HTML au cas où (defense in depth)
        safe_email = html.escape(normalized_email)
        
        return safe_email
        
    except EmailNotValidError as e:
        logging.warning(f"Invalid email attempt: {email_input} - {str(e)}")
        return None

def sanitize_code(code_input):
    """Validation code de vérification"""
    if not isinstance(code_input, str):
        return None
    
    # Bleach pour nettoyer
    clean_code = bleach.clean(code_input.strip())
    
    # Doit être exactement 6 chiffres
    if not clean_code.isdigit() or len(clean_code) != 6:
        return None
    
    return clean_code

def sanitize_ip(ip_input):
    """Validation IP"""
    if not isinstance(ip_input, str):
        return "unknown"
    
    # Bleach pour nettoyer
    clean_ip = bleach.clean(ip_input.strip())
    
    # Limite longueur (IPv6 max = 45 chars)
    if len(clean_ip) > 45:
        return "unknown"
    
    return clean_ip

def check_rate_limit(ip):
    """Max 10 requests/minute per IP"""
    now = datetime.utcnow()
    
    if ip not in rate_limits:
        rate_limits[ip] = {'count': 1, 'reset': now + timedelta(minutes=1)}
        return True
    
    data = rate_limits[ip]
    
    if now > data['reset']:
        data['count'] = 1
        data['reset'] = now + timedelta(minutes=1)
        return True
    
    if data['count'] >= 10:
        logging.warning(f"Rate limit exceeded for IP: {ip}")
        return False
    
    data['count'] += 1
    return True

def generate_code():
    """Code à 6 chiffres cryptographiquement sûr"""
    return str(secrets.randbelow(1000000)).zfill(6)

def send_email(email, code):
    """
    Envoie email via SMTP
    
    Configuration requise en variables d'environnement:
    - SMTP_HOST (ex: smtp.gmail.com)
    - SMTP_PORT (ex: 587)
    - SMTP_USER (votre email)
    - SMTP_PASSWORD (mot de passe ou app password)
    """
    smtp_host = os.getenv('SMTP_HOST')
    smtp_port = int(os.getenv('SMTP_PORT', '587'))
    smtp_user = os.getenv('SMTP_USER')
    smtp_password = os.getenv('SMTP_PASSWORD')
    
    # Mode dev - affiche le code
    if not smtp_host or not smtp_user or not smtp_password:
        logging.warning(f"SMTP not configured - displaying code for {email}")
        print(f"\n{'='*50}")
        print(f"CODE pour {email}: {code}")
        print(f"{'='*50}\n")
        return
    
    try:
        # Création du message
        msg = MIMEMultipart('alternative')
        msg['Subject'] = 'Code de verification'
        msg['From'] = smtp_user
        msg['To'] = email
        
        # Version texte
        text = f"""
Votre code de verification: {code}

Ce code expire dans 10 minutes.

Si vous n'avez pas demande ce code, ignorez cet email.
"""
        
        # Version HTML
        html_content = f"""
<html>
  <body>
    <h2>Code de verification</h2>
    <p>Votre code de verification: <strong style="font-size: 24px; color: #2563eb;">{code}</strong></p>
    <p>Ce code expire dans 10 minutes.</p>
    <hr>
    <p style="color: #666; font-size: 12px;">Si vous n'avez pas demande ce code, ignorez cet email.</p>
  </body>
</html>
"""
        
        # Attacher les deux versions
        part1 = MIMEText(text, 'plain')
        part2 = MIMEText(html_content, 'html')
        msg.attach(part1)
        msg.attach(part2)
        
        # Connexion SMTP
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls()  # Chiffrement TLS
            server.login(smtp_user, smtp_password)
            server.send_message(msg)
        
        logging.info(f"Email sent to {email}")
        
    except smtplib.SMTPAuthenticationError:
        logging.error("SMTP Authentication failed - check credentials")
        raise Exception("Erreur authentification SMTP")
    except smtplib.SMTPException as e:
        logging.error(f"SMTP error: {e}")
        raise Exception("Erreur envoi email")
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        raise Exception("Erreur envoi email")

def create_token(email):
    """JWT avec expiration"""
    payload = {
        "sub": email,
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(days=7),
        "jti": secrets.token_urlsafe(16)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

def verify_token(token):
    """Vérifie et décode le token"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload.get("sub")
    except jwt.ExpiredSignatureError:
        logging.warning("Expired token used")
        return None
    except jwt.JWTError as e:
        logging.warning(f"Invalid token: {e}")
        return None

class Handler(BaseHTTPRequestHandler):
    
    def _send_json(self, data, status=200):
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        
        # Security headers
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('X-XSS-Protection', '1; mode=block')
        self.send_header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
        self.send_header('Content-Security-Policy', "default-src 'none'")
        
        allowed_origin = os.getenv('ALLOWED_ORIGIN', '*')
        self.send_header('Access-Control-Allow-Origin', allowed_origin)
        
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())
    
    def _get_body(self):
        try:
            length = int(self.headers.get('Content-Length', 0))
            if length > 10000:  # Max 10KB
                return {}
            
            body_bytes = self.rfile.read(length) if length else b'{}'
            body_str = body_bytes.decode('utf-8')
            
            # Bleach pour nettoyer le JSON brut (paranoia)
            clean_body = bleach.clean(body_str)
            
            return json.loads(clean_body)
        except Exception as e:
            logging.warning(f"Invalid body: {e}")
            return {}
    
    def _get_ip(self):
        """Get real IP (handles proxies)"""
        forwarded = self.headers.get('X-Forwarded-For')
        if forwarded:
            ip = forwarded.split(',')[0].strip()
        else:
            ip = self.client_address[0]
        
        return sanitize_ip(ip)
    
    def _log_failed_attempt(self, ip, email):
        """Log failed attempts"""
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute(
            'INSERT INTO failed_attempts (ip, email, timestamp) VALUES (?, ?, ?)',
            (ip, email, datetime.utcnow())
        )
        conn.commit()
        conn.close()
    
    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', os.getenv('ALLOWED_ORIGIN', '*'))
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.end_headers()
    
    def do_POST(self):
        ip = self._get_ip()
        
        if not check_rate_limit(ip):
            return self._send_json({'error': 'Trop de requêtes'}, 429)
        
        body = self._get_body()
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        
        try:
            # Route: Register
            if self.path == '/register':
                email = sanitize_email(body.get('email', ''))
                if not email:
                    return self._send_json({'error': 'Email invalide'}, 400)
                
                c.execute('SELECT email FROM users WHERE email = ?', (email,))
                if c.fetchone():
                    return self._send_json({'error': 'Email déjà utilisé'}, 400)
                
                code = generate_code()
                
                c.execute(
                    'INSERT OR REPLACE INTO codes (email, code, expires_at, attempts) VALUES (?, ?, ?, ?)',
                    (email, code, datetime.utcnow() + timedelta(minutes=10), 0)
                )
                conn.commit()
                
                send_email(email, code)
                logging.info(f"Registration initiated for {email} from {ip}")
                
                return self._send_json({'message': 'Code envoyé', 'email': email})
            
            # Route: Verify
            elif self.path == '/verify':
                email = sanitize_email(body.get('email', ''))
                code = sanitize_code(body.get('code', ''))
                
                if not email or not code:
                    return self._send_json({'error': 'Données invalides'}, 400)
                
                c.execute('SELECT code, expires_at, attempts FROM codes WHERE email = ?', (email,))
                row = c.fetchone()
                
                if not row:
                    self._log_failed_attempt(ip, email)
                    return self._send_json({'error': 'Pas de code pour cet email'}, 400)
                
                stored_code, expires_at, attempts = row
                expires_at = datetime.fromisoformat(expires_at)
                
                if datetime.utcnow() > expires_at:
                    c.execute('DELETE FROM codes WHERE email = ?', (email,))
                    conn.commit()
                    return self._send_json({'error': 'Code expiré'}, 400)
                
                if attempts >= 5:
                    c.execute('DELETE FROM codes WHERE email = ?', (email,))
                    conn.commit()
                    logging.warning(f"Too many attempts for {email} from {ip}")
                    return self._send_json({'error': 'Trop de tentatives'}, 400)
                
                if stored_code != code:
                    c.execute('UPDATE codes SET attempts = attempts + 1 WHERE email = ?', (email,))
                    conn.commit()
                    self._log_failed_attempt(ip, email)
                    return self._send_json({'error': 'Code incorrect'}, 400)
                
                c.execute(
                    'INSERT INTO users (email, created_at, last_login) VALUES (?, ?, ?)',
                    (email, datetime.utcnow(), datetime.utcnow())
                )
                c.execute('DELETE FROM codes WHERE email = ?', (email,))
                conn.commit()
                
                token = create_token(email)
                logging.info(f"User {email} verified from {ip}")
                
                return self._send_json({'token': token})
            
            return self._send_json({'error': 'Route non trouvée'}, 404)
            
        finally:
            conn.close()
    
    def do_GET(self):
        ip = self._get_ip()
        
        if not check_rate_limit(ip):
            return self._send_json({'error': 'Trop de requêtes'}, 429)
        
        if self.path == '/me':
            auth = self.headers.get('Authorization', '')
            if not auth.startswith('Bearer '):
                return self._send_json({'error': 'Non authentifié'}, 401)
            
            token = auth[7:]
            email = verify_token(token)
            
            if not email:
                return self._send_json({'error': 'Token invalide'}, 401)
            
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute('SELECT created_at, last_login FROM users WHERE email = ?', (email,))
            row = c.fetchone()
            conn.close()
            
            if not row:
                return self._send_json({'error': 'Utilisateur non trouvé'}, 404)
            
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute('UPDATE users SET last_login = ? WHERE email = ?', (datetime.utcnow(), email))
            conn.commit()
            conn.close()
            
            return self._send_json({
                'email': email,
                'created_at': row[0],
                'last_login': row[1]
            })
        
        elif self.path == '/':
            return self._send_json({
                'status': 'running',
                'endpoints': {
                    'POST /register': 'Créer un compte',
                    'POST /verify': 'Vérifier le code',
                    'GET /me': 'Info utilisateur (auth requise)'
                }
            })
        
        return self._send_json({'error': 'Route non trouvée'}, 404)
    
    def log_message(self, format, *args):
        logging.info(f"{self._get_ip()} - {self.command} {args[0]} - {args[1]}")

if __name__ == '__main__':
    init_db()
    
    if SECRET_KEY == secrets.token_urlsafe(32):
        logging.warning("WARNING: Using generated SECRET_KEY - set SECRET_KEY env var for production!")
    
    logging.info(f"Server starting on http://0.0.0.0:{PORT}")
    logging.info(f"Database: {DB_PATH}")
    logging.info("Using: email-validator + bleach for input sanitization")
    
    server = HTTPServer(('0.0.0.0', PORT), Handler)
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logging.info("Server stopped")
