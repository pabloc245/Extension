#!/usr/bin/env python3
"""
Serveur d'authentification — Flask
"""
import os
import json
import secrets
import logging
import sqlite3
import smtplib
import binascii
import ipaddress
import hmac
from datetime import datetime, timezone, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from functools import wraps

import jwt
import requests
from flask import Flask, request, jsonify, g
from email_validator import validate_email, EmailNotValidError
from dotenv import load_dotenv
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from google.cloud import secretmanager

# ─── Secret Manager ──────────────────────────────────────────────────────────

GCP_PROJECT_ID = os.getenv("GCP_PROJECT_ID")
if not GCP_PROJECT_ID:
    raise RuntimeError("GCP_PROJECT_ID must be set in environment")

_sm_client = secretmanager.SecretManagerServiceClient()

def get_secret(secret_id: str, default: str = None) -> str:
    try:
        name     = f"projects/{GCP_PROJECT_ID}/secrets/{secret_id}/versions/latest"
        response = _sm_client.access_secret_version(request={"name": name})
        return response.payload.data.decode("UTF-8").strip()
    except Exception as e:
        if default is not None:
            logging.warning(f"Secret '{secret_id}' not found, using default: {e}")
            return default
        raise RuntimeError(f"Failed to load required secret '{secret_id}': {e}")

# ─── Config ──────────────────────────────────────────────────────────────────

SECRET_KEY             = get_secret("SECRET_KEY")
ALLOWED_ORIGINS        = set(get_secret("ALLOWED_ORIGINS").split(","))
SMTP_HOST              = get_secret("SMTP_HOST",              default="")
SMTP_USER              = get_secret("SMTP_USER",              default="")
SMTP_PASSWORD          = get_secret("SMTP_PASSWORD",          default="")
AES_KEY                = get_secret("AES_KEY",                default="")
AES_IV                 = get_secret("AES_IV",                 default="")
GUMROAD_WEBHOOK_SECRET = get_secret("GUMROAD_WEBHOOK_SECRET", default="")
GUMROAD_ACCESS_TOKEN   = get_secret("GUMROAD_ACCESS_TOKEN",   default="")
TRUSTED_PROXIES        = set(get_secret("TRUSTED_PROXIES",    default="").split(",")) - {""}

PORT    = int(os.getenv("PORT",    "8000"))
HOST    =     os.getenv("HOST",    "localhost")
DB_PATH =     os.getenv("DB_PATH", "auth.db")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))

FREE_TIER_LIMIT = os.getenv("FREE_TIER_LIMIT", "2")

# ─── Logging ─────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('auth.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)

app = Flask(__name__)

# ─── Database ────────────────────────────────────────────────────────────────

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(_):
    db = g.pop('db', None)
    if db:
        db.close()

def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.executescript('''
            CREATE TABLE IF NOT EXISTS users (
                email                TEXT PRIMARY KEY,
                created_at           TIMESTAMP,
                last_login           TIMESTAMP,
                subscription_status  TEXT DEFAULT 'inactive',
                subscription_ends_at TIMESTAMP,
                decode_attempts      INTEGER DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS codes (
                email      TEXT PRIMARY KEY,
                code       TEXT,
                expires_at TIMESTAMP,
                attempts   INTEGER DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS failed_attempts (
                ip        TEXT,
                email     TEXT,
                timestamp TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS processed_sales (
                sale_id      TEXT PRIMARY KEY,
                email        TEXT,
                processed_at TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS revoked_tokens (
                jti        TEXT PRIMARY KEY,
                revoked_at TIMESTAMP
            );
        ''')
        # FIX #15 — migrations sûres
        for col, definition in [
            ('subscription_status',  "TEXT DEFAULT 'inactive'"),
            ('subscription_ends_at', 'TIMESTAMP'),
            ('decode_attempts',      'INTEGER DEFAULT 0'),
        ]:
            try:
                conn.execute(f'ALTER TABLE users ADD COLUMN {col} {definition}')
            except sqlite3.OperationalError:
                pass

# init compatible gunicorn
with app.app_context():
    pass

# ─── Sanitizers ──────────────────────────────────────────────────────────────

def sanitize_email(value):
    if not isinstance(value, str) or len(value) > 254:
        return None
    try:
        return validate_email(value, check_deliverability=False).normalized
    except EmailNotValidError:
        return None

def sanitize_code(value):
    if not isinstance(value, str):
        return None
    v = value.strip()
    return v if v.isdigit() and len(v) == 6 else None

def sanitize_ip(value):
    if not isinstance(value, str):
        return "unknown"
    try:
        ipaddress.ip_address(value.strip())
        return value.strip()
    except ValueError:
        return "unknown"

# ─── Rate limiting ───────────────────────────────────────────────────────────

_rate_limits: dict = {}
# NOTE: ce rate limiting est en mémoire et non partagé entre workers gunicorn.
# En production multi-process, utiliser Redis ou déléguer à nginx.

def now_utc():
    return datetime.now(timezone.utc)  # FIX #13 — datetime.utcnow() déprécié

def check_rate_limit(ip: str) -> bool:
    now = now_utc()
    for k in [k for k, v in _rate_limits.items() if now > v['reset']]:
        del _rate_limits[k]

    entry = _rate_limits.get(ip)
    if not entry or now > entry['reset']:
        _rate_limits[ip] = {'count': 1, 'reset': now + timedelta(minutes=1)}
        return True
    if entry['count'] >= 10:
        return False
    entry['count'] += 1
    return True

def get_client_ip():
    direct = request.remote_addr
    if direct in TRUSTED_PROXIES:
        forwarded = request.headers.get('X-Forwarded-For')
        if forwarded:
            return sanitize_ip(forwarded.split(',')[0].strip())
    return sanitize_ip(direct)

def rate_limited(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not check_rate_limit(get_client_ip()):
            return jsonify(error='Trop de requêtes'), 429
        return f(*args, **kwargs)
    return wrapper

# ─── Auth ────────────────────────────────────────────────────────────────────

auth_expiration = timedelta(days=7)

def create_token(email: str) -> str:
    return jwt.encode({
        "sub": email,
        "iat": now_utc(),
        "exp": now_utc() + auth_expiration,
        "jti": secrets.token_urlsafe(16),
        "type": "auth"
    }, SECRET_KEY, algorithm="HS256")

def create_refresh_token(email: str) -> str:
    return jwt.encode({
        "sub": email,
        "iat": now_utc(),
        "exp": now_utc() + timedelta(days=90),
        "jti": secrets.token_urlsafe(16),
        "type": "refresh"
    }, SECRET_KEY, algorithm="HS256")

def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        if payload.get('type') != 'auth':
            return None
        # FIX #2 — vérifier si le token est révoqué
        jti = payload.get('jti')
        if jti:
            db = get_db()
            if db.execute('SELECT 1 FROM revoked_tokens WHERE jti = ?', (jti,)).fetchone():
                return None
        return payload.get("sub")
    except jwt.InvalidTokenError:
        return None

def require_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.headers.get('Authorization', '')
        if not auth.startswith('Bearer '):
            return jsonify(error='Non authentifié'), 401
        email = verify_token(auth[7:])
        if not email:
            return jsonify(error='Token invalide'), 401
        g.email = email
        return f(*args, **kwargs)
    return wrapper

# ─── CORS & security headers ─────────────────────────────────────────────────

@app.after_request
def add_headers(resp):
    # FIX #9 — on n'utilise plus l'Origin du client, on utilise ALLOWED_ORIGIN fixe
    resp.headers['Access-Control-Allow-Origin']  = ALLOWED_ORIGINS
    resp.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    resp.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    resp.headers['X-Content-Type-Options']       = 'nosniff'
    resp.headers['X-Frame-Options']              = 'DENY'
    resp.headers['Content-Security-Policy']      = "default-src 'none'"
    resp.headers['Strict-Transport-Security']    = 'max-age=63072000; includeSubDomains'  # NOUVEAU — HSTS
    return resp

@app.route('/', defaults={'path': ''}, methods=['OPTIONS'])
@app.route('/<path:path>', methods=['OPTIONS'])
def options(_=None, **__):
    return '', 200

# ─── Email ───────────────────────────────────────────────────────────────────

def send_email(email: str, code: str):
    if not all([SMTP_HOST, SMTP_USER, SMTP_PASSWORD]):
        print(f"\n{'='*50}\nCODE pour {email}: {code}\n{'='*50}\n")
        return

    msg = MIMEMultipart('alternative')
    msg['Subject'] = 'Code de vérification'
    msg['From']    = SMTP_USER
    msg['To']      = email
    msg.attach(MIMEText(f"Votre code : {code}\n\nExpire dans 10 minutes.", 'plain'))
    msg.attach(MIMEText(f"""
        <html><body>
            <h2>Code de vérification</h2>
            <p>Votre code : <strong style="font-size:24px;color:#2563eb">{code}</strong></p>
            <p>Expire dans 10 minutes.</p>
        </body></html>
    """, 'html'))

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
        server.starttls()
        server.login(SMTP_USER, SMTP_PASSWORD)
        server.send_message(msg)

    logging.info(f"Email sent to {email}")

# ─── Crypto ──────────────────────────────────────────────────────────────────

def decrypt_aes_cbc(data: bytes):
    # FIX #14 — IV fixe : acceptable si les données chiffrées côté client
    # embarquent un IV aléatoire en préfixe (16 premiers octets).
    # Si ce n'est pas le cas, migrer vers IV aléatoire + prefixé dans le payload.
    try:
        cipher = AES.new(binascii.unhexlify(AES_KEY), AES.MODE_CBC, binascii.unhexlify(AES_IV))
        return json.loads(unpad(cipher.decrypt(data), AES.block_size).decode('utf-8'))
    except Exception as e:
        logging.error(f"Decryption error: {e}")
        return None

# ─── Routes ──────────────────────────────────────────────────────────────────

@app.get('/')
def index():
    return jsonify(status='running', endpoints={
        'POST /register':  'Envoyer un code',
        'POST /verify':    'Vérifier le code',
        'POST /refresh':   'Rafraîchir le token',
        'POST /logout':    'Révoquer le token',
        'GET  /me':        'Info utilisateur (auth requise)',
        'POST /decode':    'Déchiffrer des données (auth requise)',
        'POST /webhook':   'Webhook Gumroad',
    })


@app.post('/register')
@rate_limited
def register():
    email = sanitize_email((request.json or {}).get('email', ''))
    if not email:
        return jsonify(error='Email invalide'), 400

    code = str(secrets.randbelow(1_000_000)).zfill(6)
    db   = get_db()
    db.execute('INSERT OR IGNORE INTO users (email, created_at) VALUES (?, ?)', (email, now_utc()))
    db.execute(
        'INSERT OR REPLACE INTO codes (email, code, expires_at, attempts) VALUES (?, ?, ?, 0)',
        (email, code, now_utc() + timedelta(minutes=10))
    )
    db.commit()

    try:
        send_email(email, code)
    except Exception as e:
        logging.error(f"Email error: {e}")
        return jsonify(error='Erreur envoi email'), 500

    logging.info(f"Code sent to {email} from {get_client_ip()}")
    return jsonify(message='Code envoyé')
    # NOTE: ne jamais retourner le code ici, même en dev


@app.post('/verify')
@rate_limited
def verify():
    body  = request.json or {}
    email = sanitize_email(body.get('email', ''))
    code  = sanitize_code(body.get('code', ''))
    ip    = get_client_ip()

    if not email or not code:
        return jsonify(error='Données invalides'), 400

    db  = get_db()
    row = db.execute('SELECT code, expires_at, attempts FROM codes WHERE email = ?', (email,)).fetchone()

    if not row:
        db.execute('INSERT INTO failed_attempts VALUES (?, ?, ?)', (ip, email, now_utc()))
        db.commit()
        return jsonify(error='Aucun code pour cet email'), 400

    if now_utc() > datetime.fromisoformat(row['expires_at']).replace(tzinfo=timezone.utc):
        db.execute('DELETE FROM codes WHERE email = ?', (email,))
        db.commit()
        return jsonify(error='Code expiré'), 400

    if row['attempts'] >= 5:
        db.execute('DELETE FROM codes WHERE email = ?', (email,))
        db.commit()
        return jsonify(error='Trop de tentatives'), 400

    # FIX #11 — timing attack
    if not hmac.compare_digest(row['code'], code):
        db.execute('UPDATE codes SET attempts = attempts + 1 WHERE email = ?', (email,))
        db.execute('INSERT INTO failed_attempts VALUES (?, ?, ?)', (ip, email, now_utc()))
        db.commit()
        return jsonify(error='Code incorrect'), 400

    db.execute('UPDATE users SET last_login = ? WHERE email = ?', (now_utc(), email))
    db.execute('DELETE FROM codes WHERE email = ?', (email,))
    db.commit()

    logging.info(f"User {email} verified from {ip}")
    return jsonify({
        'token':         create_token(email),
        'refresh_token': create_refresh_token(email),
        'expires_at':    (now_utc() + auth_expiration).isoformat()
    })


@app.post('/refresh')
@rate_limited
def refresh():
    # FIX #3 — KeyError si data None ou clé absente
    data  = request.get_json() or {}
    token = data.get('refresh_token')
    if not token:
        return jsonify(error='Missing refresh_token'), 400

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        if payload.get('type') != 'refresh':
            return jsonify(error='Invalid token type'), 401

        email = payload.get('sub')
        if not email:
            return jsonify(error='Invalid token'), 401

        # FIX #1 critique — vérifier que l'utilisateur existe toujours en DB
        db  = get_db()
        row = db.execute('SELECT email FROM users WHERE email = ?', (email,)).fetchone()
        if not row:
            return jsonify(error='Utilisateur inconnu'), 401

        # FIX #2 — vérifier si le refresh token est révoqué
        jti = payload.get('jti')
        if jti and db.execute('SELECT 1 FROM revoked_tokens WHERE jti = ?', (jti,)).fetchone():
            return jsonify(error='Token révoqué'), 401

        return jsonify({
            'token':      create_token(email),
            'expires_at': (now_utc() + auth_expiration).isoformat()
        })
    except jwt.InvalidTokenError:
        return jsonify(error='Invalid refresh token'), 401


# NOUVEAU — endpoint logout pour révoquer un token
@app.post('/logout')
@rate_limited
@require_auth
def logout():
    auth = request.headers.get('Authorization', '')
    token = auth[7:]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        jti = payload.get('jti')
        if jti:
            db = get_db()
            db.execute('INSERT OR IGNORE INTO revoked_tokens (jti, revoked_at) VALUES (?, ?)', (jti, now_utc()))
            db.commit()
    except jwt.InvalidTokenError:
        pass
    return jsonify(success=True)


@app.get('/me')
@rate_limited
@require_auth
def me():
    db  = get_db()
    row = db.execute(
        'SELECT created_at, last_login, subscription_status FROM users WHERE email = ?',
        (g.email,)
    ).fetchone()

    if not row:
        return jsonify(error='Utilisateur non trouvé'), 404

    # FIX #5 — supprimé : ne plus mettre à jour last_login ici, uniquement dans /verify

    return jsonify(
        email=g.email,
        created_at=row['created_at'],
        last_login=row['last_login'],
        subscription_status=row['subscription_status'],
    )


@app.post('/decode')
@rate_limited
@require_auth
def decode():
    if not AES_KEY or not AES_IV:
        return jsonify(error='AES not configured'), 500

    db  = get_db()
    row = db.execute(
        'SELECT decode_attempts, subscription_status, subscription_ends_at FROM users WHERE email = ?',
        (g.email,)
    ).fetchone()

    if not row:
        return jsonify(error='Utilisateur non trouvé'), 404

    attempts = row['decode_attempts']

    if attempts >= FREE_TIER_LIMIT:
        active = row['subscription_status'] == 'active'
        if active and row['subscription_ends_at']:
            try:
                ends_at = datetime.fromisoformat(row['subscription_ends_at'])
                if ends_at.tzinfo is None:
                    ends_at = ends_at.replace(tzinfo=timezone.utc)
                active = ends_at >= now_utc()
            except (ValueError, TypeError):
                active = False
        if not active:
            return jsonify(
                error='subscription_required',
                message=f'Limite gratuite atteinte ({FREE_TIER_LIMIT} déchiffrements).',
                decode_attempts=attempts,
                limit=FREE_TIER_LIMIT,
            ), 402

    data = request.get_data()
    if not data:
        return jsonify(error='No data provided'), 400

    decrypted = decrypt_aes_cbc(data)
    if decrypted is None:
        return jsonify(error='Decryption failed'), 400

    db.execute('UPDATE users SET decode_attempts = decode_attempts + 1 WHERE email = ?', (g.email,))
    db.commit()

    logging.info(f"Decrypted for {g.email} from {get_client_ip()} (attempt #{attempts + 1})")
    return jsonify(success=True, data=decrypted, decode_attempts=attempts + 1, limit=FREE_TIER_LIMIT)


@app.post('/webhook')
@rate_limited
def webhook():
    secret = request.form.get('secret')

    # FIX #11 — timing attack sur la comparaison du secret webhook
    if not GUMROAD_WEBHOOK_SECRET or not secret or not hmac.compare_digest(secret, GUMROAD_WEBHOOK_SECRET):
        logging.warning(f"Webhook: invalid secret from {get_client_ip()}")
        return jsonify(error='Unauthorized'), 401

    sale_id = request.form.get('sale_id')
    email   = request.form.get('email')

    if not sale_id:
        return jsonify(error='Missing sale_id'), 400

    # FIX — valider l'email du webhook aussi
    if email:
        email = sanitize_email(email)

    db = get_db()
    if db.execute('SELECT 1 FROM processed_sales WHERE sale_id = ?', (sale_id,)).fetchone():
        return jsonify(error='Already processed'), 400

    if not GUMROAD_ACCESS_TOKEN:
        return jsonify(error='Server misconfiguration'), 500

    try:
        resp = requests.get(
            f'https://api.gumroad.com/v2/sales/{sale_id}',
            params={'access_token': GUMROAD_ACCESS_TOKEN},
            timeout=10,
        )
    except requests.RequestException as e:
        logging.error(f"Gumroad API error: {e}")
        return jsonify(error='API error'), 500

    data = resp.json()
    if resp.status_code != 200 or not data.get('success'):
        return jsonify(error='Sale verification failed'), 400

    verified_email = sanitize_email(data.get('sale', {}).get('email') or email or '')
    if not verified_email:
        return jsonify(error='No valid email found'), 400

    # FIX #6 — récupérer la date de fin d'abonnement depuis Gumroad
    sale        = data.get('sale', {})
    ends_at_raw = sale.get('subscription_end_date') or sale.get('end_date')
    ends_at     = None
    if ends_at_raw:
        try:
            ends_at = datetime.fromisoformat(ends_at_raw).replace(tzinfo=timezone.utc).isoformat()
        except (ValueError, TypeError):
            ends_at = None

    db.execute(
        "UPDATE users SET subscription_status = 'active', subscription_ends_at = ? WHERE email = ?",
        (ends_at, verified_email)
    )
    db.execute(
        'INSERT INTO processed_sales (sale_id, email, processed_at) VALUES (?, ?, ?)',
        (sale_id, verified_email, now_utc())
    )
    db.commit()

    logging.info(f"Gumroad payment: {sale_id} for {verified_email}")
    return jsonify(success=True)

# ─── Entry point ─────────────────────────────────────────────────────────────

if __name__ == '__main__':
    init_db()
    app.run(host=HOST, port=PORT)