#!/usr/bin/env python3

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
from dotenv import load_dotenv
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import binascii
import ipaddress
import stripe

# Charger le fichier .env
load_dotenv()

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

# AES Config
AES_KEY = os.getenv("AES_KEY", "")  # 64 caractères hex (32 bytes)
AES_IV = os.getenv("AES_IV", "")    # 32 caractères hex (16 bytes)

# Stripe Config
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET")


# Format: liste d'IPs séparées par des virgules dans TRUSTED_PROXIES
TRUSTED_PROXIES = set(
    ip.strip()
    for ip in os.getenv("TRUSTED_PROXIES", "").split(",")
    if ip.strip()
)

rate_limits = {}

def init_db():
    """Initialise la base de données SQLite"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        email TEXT PRIMARY KEY,
        created_at TIMESTAMP,
        last_login TIMESTAMP,
        stripe_customer_id TEXT,
        stripe_subscription_id TEXT,
        subscription_status TEXT DEFAULT 'inactive',
        subscription_ends_at TIMESTAMP,
        decode_attempts INTEGER DEFAULT 0
    )''')
    
    # Migrations pour les bases existantes
    for column, definition in [
        ('stripe_customer_id',      'TEXT'),
        ('stripe_subscription_id',  'TEXT'),
        ('subscription_status',     "TEXT DEFAULT 'inactive'"),
        ('subscription_ends_at',    'TIMESTAMP'),
        ('decode_attempts',         'INTEGER DEFAULT 0'),
    ]:
        try:
            c.execute(f'ALTER TABLE users ADD COLUMN {column} {definition}')
        except sqlite3.OperationalError:
            pass  # Colonne déjà existante
    
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
    # Vérification de type stricte — rejette int, list, dict, etc.
    if not isinstance(email_input, str):
        logging.warning(f"Invalid email type: {type(email_input)}")
        return None

    # Limite RFC 5321 : 254 chars max — coupe court avant email-validator
    if len(email_input) > 254:
        logging.warning("Email input exceeds RFC max length (254)")
        return None

    try:
        emailinfo = validate_email(email_input, check_deliverability=False)
        # email-validator retourne déjà un email normalisé et sûr
        return emailinfo.normalized

    except EmailNotValidError as e:
        logging.warning(f"Invalid email attempt: {email_input} - {str(e)}")
        return None

def sanitize_code(code_input):
    """Validation code de vérification — doit être exactement 6 chiffres"""
    # Vérification de type stricte
    if not isinstance(code_input, str):
        return None

    stripped = code_input.strip()

    # Doit être exactement 6 chiffres — isdigit() suffit, bleach n'apporte rien ici
    if not stripped.isdigit() or len(stripped) != 6:
        return None

    return stripped

def sanitize_ip(ip_input):
    """Validation IP — vérifie le format réel avec ipaddress (IPv4 et IPv6)"""
    if not isinstance(ip_input, str):
        return "unknown"

    stripped = ip_input.strip()

    try:
        # ipaddress.ip_address() lève ValueError si ce n'est pas une IP valide
        ipaddress.ip_address(stripped)
        return stripped
    except ValueError:
        logging.warning(f"Invalid IP format: {stripped!r}")
        return "unknown"

def hex_to_bytes(hex_string):
    """Convertit hexadécimal en bytes"""
    return binascii.unhexlify(hex_string)

def decrypt_aes_cbc(encrypted_data, key_hex, iv_hex):
    """
    Déchiffre les données avec AES-CBC
    
    Args:
        encrypted_data: bytes chiffrés
        key_hex: clé en hexadécimal (64 chars pour AES-256)
        iv_hex: IV en hexadécimal (32 chars)
    
    Returns:
        dict: JSON déchiffré ou None si erreur
    """
    try:
        key = hex_to_bytes(key_hex)
        iv = hex_to_bytes(iv_hex)
        
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(encrypted_data)
        unpadded = unpad(decrypted, AES.block_size)
        text = unpadded.decode('utf-8')
        
        return json.loads(text)
        
    except Exception as e:
        logging.error(f"Decryption error: {e}")
        return None

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

            # Parse JSON directement — chaque champ est sanitisé individuellement ensuite
            parsed = json.loads(body_str)

            # On n'accepte que des objets JSON (dict), pas des arrays ou primitives
            if not isinstance(parsed, dict):
                logging.warning("JSON body is not an object")
                return {}

            return parsed
        except Exception as e:
            logging.warning(f"Invalid body: {e}")
            return {}
    
    def _get_ip(self):
        """
        Récupère la vraie IP cliente.
        X-Forwarded-For n'est accepté que si la requête vient d'un proxy de confiance
        (défini dans TRUSTED_PROXIES), pour éviter le spoofing du rate limiting.
        """
        direct_ip = self.client_address[0]

        if direct_ip in TRUSTED_PROXIES:
            forwarded = self.headers.get('X-Forwarded-For')
            if forwarded:
                # Prendre la première IP de la chaîne (IP originale du client)
                ip = forwarded.split(',')[0].strip()
                return sanitize_ip(ip)

        return sanitize_ip(direct_ip)
    
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
            
            # Route: Decode
            elif self.path == '/decode':
                # Vérifier config AES
                if not AES_KEY or not AES_IV:
                    return self._send_json({'error': 'AES not configured'}, 500)

                # Authentification requise pour /decode
                auth = self.headers.get('Authorization', '')
                if not auth.startswith('Bearer '):
                    return self._send_json({'error': 'Non authentifié'}, 401)

                email = verify_token(auth[7:])
                if not email:
                    return self._send_json({'error': 'Token invalide'}, 401)

                # Récupérer l'utilisateur et ses infos subscription
                c.execute(
                    'SELECT decode_attempts, subscription_status, subscription_ends_at FROM users WHERE email = ?',
                    (email,)
                )
                user_row = c.fetchone()
                if not user_row:
                    return self._send_json({'error': 'Utilisateur non trouvé'}, 404)

                decode_attempts, sub_status, sub_ends_at = user_row

                # Au-delà de 3 tentatives : subscription active requise
                FREE_TIER_LIMIT = 3
                if decode_attempts >= FREE_TIER_LIMIT:
                    is_active = sub_status == 'active'
                    # Vérifier aussi que l'abonnement n'est pas expiré
                    if is_active and sub_ends_at:
                        try:
                            if datetime.fromisoformat(sub_ends_at) < datetime.utcnow():
                                is_active = False
                        except (ValueError, TypeError):
                            is_active = False

                    if not is_active:
                        logging.warning(f"Decode attempt over free tier limit for {email} (attempts={decode_attempts})")
                        return self._send_json({
                            'error': 'subscription_required',
                            'message': 'Vous avez atteint la limite gratuite (3 déchiffrements). Un abonnement actif est requis pour continuer.',
                            'decode_attempts': decode_attempts,
                            'limit': FREE_TIER_LIMIT
                        }, 402)

                try:
                    length = int(self.headers.get('Content-Length', 0))
                    if length == 0:
                        return self._send_json({'error': 'No data provided'}, 400)

                    encrypted_data = self.rfile.read(length)

                    decrypted = decrypt_aes_cbc(encrypted_data, AES_KEY, AES_IV)

                    if decrypted is None:
                        return self._send_json({'error': 'Decryption failed'}, 400)

                    # Incrémenter le compteur seulement sur succès
                    c.execute(
                        'UPDATE users SET decode_attempts = decode_attempts + 1 WHERE email = ?',
                        (email,)
                    )
                    conn.commit()

                    logging.info(f"Data decrypted successfully for {email} from {ip} (attempt #{decode_attempts + 1})")

                    return self._send_json({
                        'success': True,
                        'data': decrypted,
                        'decode_attempts': decode_attempts + 1,
                        'limit': FREE_TIER_LIMIT
                    })

                except Exception as e:
                    logging.error(f"Decode error: {e}")
                    return self._send_json({'error': 'Internal error'}, 500)
            
            # Route: Webhook Stripe
            elif self.path == '/webhook':
                if not STRIPE_WEBHOOK_SECRET:
                    logging.error("STRIPE_WEBHOOK_SECRET not configured")
                    return self._send_json({'error': 'Webhook not configured'}, 500)

                length = int(self.headers.get('Content-Length', 0))
                if length == 0:
                    return self._send_json({'error': 'No payload'}, 400)

                # Payload raw bytes obligatoire — ne pas passer par _get_body()
                payload = self.rfile.read(length)
                sig_header = self.headers.get('Stripe-Signature')

                if not sig_header:
                    logging.warning(f"Webhook call without Stripe-Signature from {ip}")
                    return self._send_json({'error': 'Missing signature'}, 400)

                try:
                    event = stripe.Webhook.construct_event(
                        payload, sig_header, STRIPE_WEBHOOK_SECRET
                    )
                except stripe.error.SignatureVerificationError:
                    logging.warning(f"Invalid Stripe signature from {ip}")
                    return self._send_json({'error': 'Invalid signature'}, 400)
                except Exception as e:
                    logging.error(f"Webhook parse error: {e}")
                    return self._send_json({'error': 'Invalid payload'}, 400)

                obj = event['data']['object']
                event_type = event['type']
                logging.info(f"Stripe event received: {event_type}")

                if event_type == 'checkout.session.completed':
                    # Récupérer l'email via metadata (le plus fiable) ou customer_email
                    email = (obj.get('metadata') or {}).get('user_email') or obj.get('customer_email')
                    if email:
                        c.execute(
                            '''UPDATE users SET
                                stripe_customer_id = ?,
                                stripe_subscription_id = ?,
                                subscription_status = 'active',
                                subscription_ends_at = NULL
                               WHERE email = ?''',
                            (obj.get('customer'), obj.get('subscription'), email)
                        )
                        conn.commit()
                        logging.info(f"Subscription activated for {email}")
                    else:
                        logging.warning(f"checkout.session.completed: no email found in event {event['id']}")

                elif event_type == 'customer.subscription.deleted':
                    # Abonnement résilié — on identifie l'user par son subscription_id
                    c.execute(
                        '''UPDATE users SET
                            subscription_status = 'inactive',
                            subscription_ends_at = ?
                           WHERE stripe_subscription_id = ?''',
                        (datetime.utcnow(), obj.get('id'))
                    )
                    conn.commit()
                    logging.info(f"Subscription deleted: {obj.get('id')}")

                elif event_type == 'customer.subscription.updated':
                    # Changement de statut (ex: trial → active, active → past_due)
                    stripe_status = obj.get('status')  # 'active', 'past_due', 'canceled', etc.
                    # On mappe les statuts Stripe vers nos statuts internes
                    internal_status = 'active' if stripe_status == 'active' else 'inactive'
                    c.execute(
                        'UPDATE users SET subscription_status = ? WHERE stripe_subscription_id = ?',
                        (internal_status, obj.get('id'))
                    )
                    conn.commit()
                    logging.info(f"Subscription updated: {obj.get('id')} → {internal_status}")

                elif event_type == 'invoice.payment_failed':
                    # Paiement échoué — on passe en past_due sans couper l'accès immédiatement
                    c.execute(
                        'UPDATE users SET subscription_status = ? WHERE stripe_customer_id = ?',
                        ('past_due', obj.get('customer'))
                    )
                    conn.commit()
                    logging.warning(f"Payment failed for customer: {obj.get('customer')}")

                # Stripe exige un 200 rapide — toujours répondre même pour les events non gérés
                return self._send_json({'received': True})

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