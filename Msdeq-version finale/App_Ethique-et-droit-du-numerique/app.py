from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, Response
import sqlite3
import hashlib
import re
import os
import base64
import io
import secrets
import json
import smtplib
import pyotp
import qrcode
import atexit
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from groq import Groq
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from apscheduler.schedulers.background import BackgroundScheduler

load_dotenv()

GROQ_API_KEY        = os.getenv('GROQ_API_KEY', '').strip()
ADMIN_EMAIL         = os.getenv('ADMIN_EMAIL', '').strip()
SMTP_HOST           = os.getenv('SMTP_HOST', 'smtp.gmail.com')
SMTP_PORT           = int(os.getenv('SMTP_PORT', 587))
SMTP_USER           = os.getenv('SMTP_USER', '').strip()
SMTP_PASSWORD       = os.getenv('SMTP_PASSWORD', '').strip()
DATA_RETENTION_DAYS = int(os.getenv('DATA_RETENTION_DAYS', 30))

groq_client = Groq(api_key=GROQ_API_KEY) if GROQ_API_KEY else None

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', secrets.token_hex(32))
app.permanent_session_lifetime = timedelta(hours=2)

DATABASE = 'ensa_ia.db'

# ──────────────────────────────────────────────
# Rate Limiting (Art. 32 RGPD — sécurité)
# ──────────────────────────────────────────────

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[],
    storage_uri="memory://"
)

# ──────────────────────────────────────────────
# Auto-purge (Art. 5(1)(e) RGPD — conservation limitée)
# ──────────────────────────────────────────────

def auto_purge_old_data():
    try:
        conn = sqlite3.connect(DATABASE)
        conn.execute(
            "DELETE FROM history WHERE datetime(timestamp) < datetime('now', ?)",
            (f'-{DATA_RETENTION_DAYS} days',)
        )
        conn.execute(
            "DELETE FROM signalements WHERE statut='traite' "
            "AND datetime(timestamp) < datetime('now', '-90 days')"
        )
        conn.commit()
        conn.close()
    except Exception:
        pass

# Démarrer le scheduler une seule fois (évite le double démarrage en mode debug)
if not os.environ.get('WERKZEUG_RUN_MAIN'):
    _scheduler = BackgroundScheduler(daemon=True)
    _scheduler.add_job(auto_purge_old_data, 'interval', hours=24, id='purge_rgpd')
    _scheduler.start()
    atexit.register(lambda: _scheduler.shutdown(wait=False))

# ──────────────────────────────────────────────
# CSRF Protection
# ──────────────────────────────────────────────

def generate_csrf_token():
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_hex(32)
    return session['_csrf_token']

app.jinja_env.globals['csrf_token'] = generate_csrf_token

_CSRF_EXEMPT = {'api_check_pii'}

@app.before_request
def csrf_protect():
    if request.method == 'POST':
        if request.endpoint in _CSRF_EXEMPT:
            return
        token      = session.get('_csrf_token')
        form_token = request.form.get('_csrf_token')
        if not token or token != form_token:
            flash('Erreur de sécurité (jeton CSRF invalide). Veuillez réessayer.', 'danger')
            return redirect(request.referrer or url_for('login'))

# ──────────────────────────────────────────────
# Vérification consentement + changement mdp forcé
# ──────────────────────────────────────────────

_NO_CHECK_ENDPOINTS = {
    'login', 'logout', 'register', 'static',
    'consent', 'change_password',
    'admin_2fa_setup', 'admin_2fa_verify',
}

@app.before_request
def check_user_requirements():
    if 'user_id' not in session:
        return
    if request.endpoint in _NO_CHECK_ENDPOINTS:
        return
    conn = get_db()
    user = conn.execute(
        "SELECT consent_accepted, force_password_change FROM users WHERE id=?",
        (session['user_id'],)
    ).fetchone()
    conn.close()
    if not user:
        return
    if not user['consent_accepted']:
        return redirect(url_for('consent'))
    if user['force_password_change']:
        return redirect(url_for('change_password'))

# ──────────────────────────────────────────────
# Base de données
# ──────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()

    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        email TEXT,
        role TEXT DEFAULT 'etudiant',
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        last_login TEXT,
        consent_accepted TEXT,
        totp_secret TEXT,
        force_password_change INTEGER DEFAULT 0
    )''')

    # Migrations colonnes manquantes
    for col, defn in [
        ('email',                  'TEXT'),
        ('consent_accepted',       'TEXT'),
        ('totp_secret',            'TEXT'),
        ('force_password_change',  'INTEGER DEFAULT 0'),
    ]:
        try:
            c.execute(f"ALTER TABLE users ADD COLUMN {col} {defn}")
        except Exception:
            pass

    c.execute('''CREATE TABLE IF NOT EXISTS requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        type TEXT NOT NULL,
        query_length INTEGER,
        response_length INTEGER,
        timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        type TEXT NOT NULL,
        query TEXT NOT NULL,
        response TEXT NOT NULL,
        timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        action TEXT NOT NULL,
        details TEXT,
        timestamp TEXT DEFAULT CURRENT_TIMESTAMP
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS signalements (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        history_id INTEGER,
        query TEXT NOT NULL,
        response TEXT NOT NULL,
        raison TEXT NOT NULL,
        commentaire TEXT,
        statut TEXT DEFAULT 'en_attente',
        timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )''')

    # Compte démo
    demo_hash = generate_password_hash('demo1234')
    try:
        c.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                  ('demo', demo_hash, 'etudiant'))
    except sqlite3.IntegrityError:
        pass

    # Compte admin — changement de mot de passe forcé au 1er login
    admin_hash = generate_password_hash('admin2025')
    try:
        c.execute(
            "INSERT INTO users (username, password_hash, role, force_password_change) VALUES (?, ?, ?, 1)",
            ('admin', admin_hash, 'admin')
        )
    except sqlite3.IntegrityError:
        c.execute("UPDATE users SET role='admin' WHERE username='admin'")

    conn.commit()
    conn.close()

# ──────────────────────────────────────────────
# Détection données personnelles (PII)
# ──────────────────────────────────────────────

PII_PATTERNS = [
    (r'\b\d{8,}\b',                                              'Numéro d\'identité potentiel'),
    (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b',   'Adresse email'),
    (r'\b0[567]\d{8}\b',                                         'Numéro de téléphone marocain'),
    (r'\b\+?\d[\d\s\-]{8,}\d\b',                                'Numéro de téléphone'),
    (r'\b(?:\d{4}[\s\-]?){4}\b',                                'Numéro de carte bancaire potentiel'),
    (r'\biban\b.*[A-Z]{2}\d{2}[A-Z0-9]{4,}',                   'IBAN bancaire', re.IGNORECASE),
    (r'\b(mot\s*de\s*passe|password|mdp|passwd|secret)\s*[=:«\"\']?\s*\S+', 'Mot de passe', re.IGNORECASE),
    (r"(?:je\s+m['\u2019]appelle|mon\s+nom\s+est|my\s+name\s+is)\s+[A-Z\u00C0-\u00FF][a-z\u00E0-\u00FF]+", 'Nom personnel', re.IGNORECASE),
    (r'\b\d{1,4}[\s,]+(?:rue|avenue|boulevard|impasse|allée|quartier|résidence)\b', 'Adresse postale', re.IGNORECASE),
    (r'\b[A-Z]{1,2}\d{5,6}\b',                                  'CIN marocaine potentielle'),
]

SENSITIVE_KEYWORDS = [
    ('mot de passe',        'Mot de passe'),
    ('password',            'Mot de passe'),
    ('mon mdp',             'Mot de passe'),
    ('ma carte',            'Données bancaires'),
    ('code secret',         'Code secret'),
    ('code pin',            'Code PIN'),
    ('mon iban',            'IBAN'),
    ('mon cin',             'CIN'),
    ('ma cin',              'CIN'),
    ('mon adresse',         'Adresse personnelle'),
    ('date de naissance',   'Date de naissance'),
    ('numéro de sécurité',  'Numéro de sécurité sociale'),
]

def detect_pii(text):
    text_lower = text.lower()
    for keyword, label in SENSITIVE_KEYWORDS:
        if keyword in text_lower:
            return True, label
    for item in PII_PATTERNS:
        pattern, label = item[0], item[1]
        flags = item[2] if len(item) > 2 else 0
        if re.search(pattern, text, flags):
            return True, label
    return False, None

# ──────────────────────────────────────────────
# Moteur IA — Groq (Llama 3)
# ──────────────────────────────────────────────

GROQ_MODEL    = 'llama-3.1-8b-instant'
SYSTEM_PROMPT = (
    "Tu es un assistant pédagogique de l'ENSA Béni Mellal spécialisé en IA, RGPD et cybersécurité. "
    "Réponds en français, de façon claire et concise."
)

def generate_response(query, mode):
    if not groq_client:
        return "Erreur : clé API Groq non configurée. Ajoutez GROQ_API_KEY dans le fichier .env"
    if mode == 'resume':
        user_content = f"Résume ce texte en français en 2 à 3 phrases :\n\n{query}"
    else:
        user_content = f"Question : {query}"
    try:
        completion = groq_client.chat.completions.create(
            model=GROQ_MODEL,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user",   "content": user_content}
            ],
            temperature=0.7,
            max_tokens=1024,
        )
        return completion.choices[0].message.content
    except Exception as e:
        return f"Erreur Groq : {str(e)}"

# ──────────────────────────────────────────────
# Décorateurs
# ──────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('Veuillez vous connecter pour accéder à cette page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get('role') != 'admin':
            flash('Accès réservé aux administrateurs.', 'danger')
            return redirect(url_for('dashboard'))
        if not session.get('2fa_verified'):
            flash('Vérification 2FA requise.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def log_action(user_id, action, details=''):
    conn = get_db()
    conn.execute("INSERT INTO audit_log (user_id, action, details) VALUES (?, ?, ?)",
                 (user_id, action, details))
    conn.commit()
    conn.close()

# ──────────────────────────────────────────────
# Context processor — badge signalements
# ──────────────────────────────────────────────

@app.context_processor
def inject_admin_notifications():
    if session.get('role') == 'admin':
        conn = get_db()
        count = conn.execute(
            "SELECT COUNT(*) as c FROM signalements WHERE statut='en_attente'"
        ).fetchone()['c']
        conn.close()
        return {'pending_signalements': count}
    return {'pending_signalements': 0}

# ──────────────────────────────────────────────
# Notifications email admin
# ──────────────────────────────────────────────

def notify_admin_signalement(username, raison, commentaire, query, response):
    if not ADMIN_EMAIL or not SMTP_USER or not SMTP_PASSWORD:
        return
    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = f'[ENSA IA] Nouveau signalement de {username}'
        msg['From']    = SMTP_USER
        msg['To']      = ADMIN_EMAIL
        body = (
            f"Nouveau signalement reçu.\n\n"
            f"Utilisateur : {username}\nRaison : {raison}\n"
            f"Commentaire : {commentaire or '(aucun)'}\n"
            f"Date : {datetime.now().strftime('%d/%m/%Y à %H:%M')}\n\n"
            f"--- Question ---\n{query[:500]}\n\n"
            f"--- Réponse ---\n{response[:1000]}\n"
        )
        msg.attach(MIMEText(body, 'plain', 'utf-8'))
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(SMTP_USER, ADMIN_EMAIL, msg.as_string())
    except Exception:
        pass

# ──────────────────────────────────────────────
# Routes — Authentification
# ──────────────────────────────────────────────

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        conn.close()

        if user:
            password_ok   = False
            needs_rehash  = False

            if check_password_hash(user['password_hash'], password):
                password_ok = True
            elif user['password_hash'] == hashlib.sha256(password.encode()).hexdigest():
                password_ok = True
                needs_rehash = True

            if password_ok:
                if needs_rehash:
                    new_hash = generate_password_hash(password)
                    conn2 = get_db()
                    conn2.execute("UPDATE users SET password_hash=? WHERE id=?", (new_hash, user['id']))
                    conn2.commit()
                    conn2.close()

                # Admin → 2FA obligatoire
                if user['role'] == 'admin':
                    session.clear()
                    session['2fa_pending_user_id'] = user['id']
                    if user['totp_secret']:
                        return redirect(url_for('admin_2fa_verify'))
                    else:
                        return redirect(url_for('admin_2fa_setup'))

                # Utilisateur normal
                session.permanent = True
                session['user_id']  = user['id']
                session['username'] = user['username']
                session['role']     = user['role']

                conn = get_db()
                conn.execute("UPDATE users SET last_login=? WHERE id=?",
                             (datetime.now().strftime('%Y-%m-%d %H:%M:%S'), user['id']))
                conn.commit()
                conn.close()

                log_action(user['id'], 'LOGIN', f"Connexion réussie pour {username}")
                return redirect(url_for('dashboard'))

        flash('Nom d\'utilisateur ou mot de passe incorrect.', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email    = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm  = request.form.get('confirm', '')

        email_pattern = r'^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'

        if len(username) < 3:
            flash('Le nom d\'utilisateur doit contenir au moins 3 caractères.', 'danger')
        elif not email or not re.match(email_pattern, email):
            flash('Veuillez saisir une adresse email valide.', 'danger')
        elif len(password) < 6:
            flash('Le mot de passe doit contenir au moins 6 caractères.', 'danger')
        elif password != confirm:
            flash('Les mots de passe ne correspondent pas.', 'danger')
        else:
            password_hash = generate_password_hash(password)
            try:
                conn = get_db()
                conn.execute("INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)",
                             (username, password_hash, email))
                conn.commit()
                conn.close()
                flash('Compte créé avec succès. Vous pouvez vous connecter.', 'success')
                return redirect(url_for('login'))
            except sqlite3.IntegrityError:
                flash('Ce nom d\'utilisateur est déjà pris.', 'danger')

    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    log_action(session['user_id'], 'LOGOUT', '')
    session.clear()
    flash('Vous avez été déconnecté.', 'info')
    return redirect(url_for('login'))

# ──────────────────────────────────────────────
# Routes — 2FA Admin (Art. 32 RGPD)
# ──────────────────────────────────────────────

def _get_2fa_pending_user():
    uid = session.get('2fa_pending_user_id')
    if not uid:
        return None
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id=? AND role='admin'", (uid,)).fetchone()
    conn.close()
    return user

@app.route('/admin/2fa/setup', methods=['GET', 'POST'])
def admin_2fa_setup():
    user = _get_2fa_pending_user()
    if not user:
        return redirect(url_for('login'))

    if request.method == 'POST':
        code   = request.form.get('code', '').strip()
        secret = session.get('totp_setup_secret')
        if not secret:
            return redirect(url_for('admin_2fa_setup'))
        totp = pyotp.TOTP(secret)
        if totp.verify(code, valid_window=1):
            conn = get_db()
            conn.execute("UPDATE users SET totp_secret=?, last_login=? WHERE id=?",
                         (secret, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), user['id']))
            conn.commit()
            conn.close()
            session.pop('totp_setup_secret', None)
            session.pop('2fa_pending_user_id', None)
            session.permanent    = True
            session['user_id']   = user['id']
            session['username']  = user['username']
            session['role']      = user['role']
            session['2fa_verified'] = True
            log_action(user['id'], '2FA_SETUP',  'Configuration 2FA effectuée')
            log_action(user['id'], 'LOGIN', f"Connexion admin 2FA — {user['username']}")
            flash('Authentification à deux facteurs activée avec succès.', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Code invalide. Vérifiez votre application d\'authentification.', 'danger')

    if 'totp_setup_secret' not in session:
        session['totp_setup_secret'] = pyotp.random_base32()

    secret  = session['totp_setup_secret']
    uri     = pyotp.TOTP(secret).provisioning_uri(name=user['username'], issuer_name='ENSA IA RGPD')
    qr_img  = qrcode.make(uri)
    buf     = io.BytesIO()
    qr_img.save(buf, format='PNG')
    qr_b64  = base64.b64encode(buf.getvalue()).decode()

    return render_template('2fa_setup.html', qr_b64=qr_b64, secret=secret, username=user['username'])

@app.route('/admin/2fa/verify', methods=['GET', 'POST'])
def admin_2fa_verify():
    user = _get_2fa_pending_user()
    if not user:
        return redirect(url_for('login'))

    if request.method == 'POST':
        code = request.form.get('code', '').strip()
        totp = pyotp.TOTP(user['totp_secret'])
        if totp.verify(code, valid_window=1):
            conn = get_db()
            conn.execute("UPDATE users SET last_login=? WHERE id=?",
                         (datetime.now().strftime('%Y-%m-%d %H:%M:%S'), user['id']))
            conn.commit()
            conn.close()
            session.pop('2fa_pending_user_id', None)
            session.permanent    = True
            session['user_id']   = user['id']
            session['username']  = user['username']
            session['role']      = user['role']
            session['2fa_verified'] = True
            log_action(user['id'], 'LOGIN', f"Connexion admin 2FA — {user['username']}")
            return redirect(url_for('dashboard'))
        else:
            flash('Code invalide. Réessayez.', 'danger')

    return render_template('2fa_verify.html', username=user['username'])

# ──────────────────────────────────────────────
# Route — Consentement (Art. 7 RGPD)
# ──────────────────────────────────────────────

@app.route('/consent', methods=['GET', 'POST'])
@login_required
def consent():
    if request.method == 'POST':
        if request.form.get('action') == 'accept':
            conn = get_db()
            conn.execute("UPDATE users SET consent_accepted=? WHERE id=?",
                         (datetime.now().strftime('%Y-%m-%d %H:%M:%S'), session['user_id']))
            conn.commit()
            conn.close()
            log_action(session['user_id'], 'CONSENT_ACCEPTED', 'Consentement RGPD accepté')
            return redirect(url_for('dashboard'))
        else:
            log_action(session['user_id'], 'CONSENT_REFUSED', 'Consentement refusé')
            session.clear()
            flash('Vous devez accepter la politique de confidentialité pour utiliser ce système.', 'warning')
            return redirect(url_for('login'))
    return render_template('consent.html')

# ──────────────────────────────────────────────
# Route — Changement de mot de passe forcé
# ──────────────────────────────────────────────

@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current = request.form.get('current_password', '')
        new_pwd = request.form.get('new_password', '')
        confirm = request.form.get('confirm_password', '')

        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE id=?", (session['user_id'],)).fetchone()

        if not check_password_hash(user['password_hash'], current):
            conn.close()
            flash('Mot de passe actuel incorrect.', 'danger')
        elif len(new_pwd) < 8:
            conn.close()
            flash('Le nouveau mot de passe doit contenir au moins 8 caractères.', 'danger')
        elif new_pwd != confirm:
            conn.close()
            flash('Les mots de passe ne correspondent pas.', 'danger')
        elif new_pwd == current:
            conn.close()
            flash('Le nouveau mot de passe doit être différent de l\'ancien.', 'danger')
        else:
            conn.execute(
                "UPDATE users SET password_hash=?, force_password_change=0 WHERE id=?",
                (generate_password_hash(new_pwd), session['user_id'])
            )
            conn.commit()
            conn.close()
            log_action(session['user_id'], 'PASSWORD_CHANGED', 'Mot de passe modifié')
            flash('Mot de passe modifié avec succès.', 'success')
            return redirect(url_for('dashboard'))

    return render_template('change_password.html')

# ──────────────────────────────────────────────
# Routes — Application
# ──────────────────────────────────────────────

@app.route('/dashboard')
@login_required
def dashboard():
    if session.get('role') == 'admin':
        return redirect(url_for('admin'))
    conn = get_db()
    total     = conn.execute("SELECT COUNT(*) as c FROM history WHERE user_id=?", (session['user_id'],)).fetchone()['c']
    questions = conn.execute("SELECT COUNT(*) as c FROM history WHERE user_id=? AND type='question'", (session['user_id'],)).fetchone()['c']
    resumes   = conn.execute("SELECT COUNT(*) as c FROM history WHERE user_id=? AND type='resume'", (session['user_id'],)).fetchone()['c']
    recent    = conn.execute("SELECT * FROM history WHERE user_id=? ORDER BY timestamp DESC LIMIT 5", (session['user_id'],)).fetchall()
    conn.close()
    return render_template('dashboard.html', total=total, questions=questions, resumes=resumes, recent=recent)

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    conn = get_db()
    user = conn.execute("SELECT id, username, email, role, created_at, last_login FROM users WHERE id=?",
                        (session['user_id'],)).fetchone()
    conn.close()

    if request.method == 'POST':
        new_email     = request.form.get('email', '').strip()
        email_pattern = r'^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'
        if not new_email or not re.match(email_pattern, new_email):
            flash('Veuillez saisir une adresse email valide.', 'danger')
        else:
            conn = get_db()
            conn.execute("UPDATE users SET email=? WHERE id=?", (new_email, session['user_id']))
            conn.commit()
            conn.close()
            log_action(session['user_id'], 'UPDATE_EMAIL', 'Adresse email mise à jour')
            flash('Adresse email mise à jour avec succès.', 'success')
            return redirect(url_for('profile'))

    return render_template('profile.html', user=user)

@app.route('/ask', methods=['GET', 'POST'])
@login_required
@limiter.limit("30 per minute")
def ask():
    if request.method == 'POST':
        query = request.form.get('query', '').strip()
        mode  = request.form.get('mode', 'question')

        if len(query) < 3:
            flash('Votre demande est trop courte (minimum 3 caractères).', 'warning')
            return render_template('ask.html', mode=mode)
        if len(query) > 2000:
            flash('Votre demande est trop longue (maximum 2000 caractères).', 'warning')
            return render_template('ask.html', mode=mode)

        has_pii, pii_label = detect_pii(query)
        if has_pii:
            flash(f'Données personnelles détectées ({pii_label}). Retirez tout identifiant avant de soumettre.', 'danger')
            return render_template('ask.html', query=query, mode=mode)

        response = generate_response(query, mode)

        conn = get_db()
        cur = conn.execute("INSERT INTO history (user_id, type, query, response) VALUES (?, ?, ?, ?)",
                     (session['user_id'], mode, query, response))
        history_id = cur.lastrowid
        conn.execute("INSERT INTO requests (user_id, type, query_length, response_length) VALUES (?, ?, ?, ?)",
                     (session['user_id'], mode, len(query), len(response)))
        conn.commit()
        conn.close()

        log_action(session['user_id'], 'SUBMIT_REQUEST', f"type={mode}, longueur={len(query)}")
        return render_template('ask.html', query=query, response=response, mode=mode, history_id=history_id)

    return render_template('ask.html', mode='question')

@app.route('/history')
@login_required
def history():
    page     = request.args.get('page', 1, type=int)
    per_page = 10
    offset   = (page - 1) * per_page

    conn    = get_db()
    total   = conn.execute("SELECT COUNT(*) as c FROM history WHERE user_id=?", (session['user_id'],)).fetchone()['c']
    entries = conn.execute(
        "SELECT * FROM history WHERE user_id=? ORDER BY timestamp DESC LIMIT ? OFFSET ?",
        (session['user_id'], per_page, offset)
    ).fetchall()
    conn.close()

    total_pages = (total + per_page - 1) // per_page
    return render_template('history.html', entries=entries, page=page, total_pages=total_pages, total=total)

@app.route('/history/delete/<int:entry_id>', methods=['POST'])
@login_required
def delete_entry(entry_id):
    conn = get_db()
    conn.execute("DELETE FROM history WHERE id=? AND user_id=?", (entry_id, session['user_id']))
    conn.commit()
    conn.close()
    log_action(session['user_id'], 'DELETE_ENTRY', f"id={entry_id}")
    flash('Entrée supprimée.', 'success')
    return redirect(url_for('history'))

@app.route('/history/clear', methods=['GET'])
@login_required
def clear_history_form():
    return render_template('clear_history.html')

@app.route('/history/clear', methods=['POST'])
@login_required
def clear_history():
    mode      = request.form.get('mode', 'all')
    date_from = request.form.get('date_from', '').strip()
    date_to   = request.form.get('date_to', '').strip()
    uid       = session['user_id']
    conn      = get_db()

    if mode == 'all':
        deleted = conn.execute("SELECT COUNT(*) FROM history WHERE user_id=?", (uid,)).fetchone()[0]
        conn.execute("DELETE FROM history WHERE user_id=?", (uid,))
        message = "Tout votre historique a été supprimé."
        date_from = date_to = None
    elif mode == 'before' and date_to:
        cur = conn.execute("DELETE FROM history WHERE user_id=? AND date(timestamp) <= ?", (uid, date_to))
        deleted = cur.rowcount
        message = f"Entrées supprimées avant le {date_to}."
        date_from = None
    elif mode == 'after' and date_from:
        cur = conn.execute("DELETE FROM history WHERE user_id=? AND date(timestamp) >= ?", (uid, date_from))
        deleted = cur.rowcount
        message = f"Entrées supprimées après le {date_from}."
        date_to = None
    elif mode == 'between' and date_from and date_to:
        cur = conn.execute("DELETE FROM history WHERE user_id=? AND date(timestamp) BETWEEN ? AND ?", (uid, date_from, date_to))
        deleted = cur.rowcount
        message = f"Entrées supprimées entre le {date_from} et le {date_to}."
    else:
        conn.close()
        flash('Veuillez sélectionner une période valide.', 'error')
        return redirect(url_for('clear_history_form'))

    conn.commit()
    conn.close()
    log_action(uid, 'CLEAR_HISTORY', f"mode={mode} from={date_from} to={date_to}")
    now = datetime.now().strftime('%d/%m/%Y à %H:%M')
    return render_template('clear_history_done.html', message=message, deleted=deleted,
                           date_from=date_from, date_to=date_to, now=now)

# ──────────────────────────────────────────────
# Routes — Droits RGPD
# ──────────────────────────────────────────────

@app.route('/droits', methods=['GET', 'POST'])
@login_required
def droits():
    if request.method == 'POST':
        droit   = request.form.get('droit', '')
        message = request.form.get('message', '').strip()
        if droit == 'acces':
            return redirect(url_for('mes_donnees'))
        if droit and message:
            if droit == 'effacement':
                conn = get_db()
                conn.execute("DELETE FROM history WHERE user_id=?", (session['user_id'],))
                conn.commit()
                conn.close()
                log_action(session['user_id'], 'EXERCICE_DROIT_EFFACEMENT', message[:200])
                flash('Votre historique a été supprimé conformément à votre droit à l\'effacement (art. 17 RGPD).', 'success')
            else:
                log_action(session['user_id'], f'EXERCICE_DROIT_{droit.upper()}', message[:200])
                flash(f'Votre demande d\'exercice du droit "{droit}" a été enregistrée. Vous recevrez une réponse sous 30 jours.', 'success')
        else:
            flash('Veuillez remplir tous les champs.', 'warning')
    return render_template('droits.html')

@app.route('/mes-donnees')
@login_required
def mes_donnees():
    conn = get_db()
    user = conn.execute(
        "SELECT id, username, role, created_at, last_login FROM users WHERE id=?",
        (session['user_id'],)
    ).fetchone()
    hist = conn.execute(
        "SELECT type, query, response, timestamp FROM history WHERE user_id=? ORDER BY timestamp DESC",
        (session['user_id'],)
    ).fetchall()
    conn.close()
    log_action(session['user_id'], 'ACCESS_DATA', 'Droit d\'accès art. 15 RGPD')
    now = datetime.now().strftime('%d/%m/%Y à %H:%M')
    return render_template('mes_donnees.html', user=user, history=hist, now=now)

@app.route('/export')
@login_required
def export_data():
    conn = get_db()
    user = conn.execute(
        "SELECT id, username, role, created_at, last_login FROM users WHERE id=?",
        (session['user_id'],)
    ).fetchone()
    hist = conn.execute(
        "SELECT type, query, response, timestamp FROM history WHERE user_id=? ORDER BY timestamp DESC",
        (session['user_id'],)
    ).fetchall()
    conn.close()

    data = {
        'utilisateur': dict(user),
        'historique':  [dict(h) for h in hist],
        'export_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'note_rgpd':   'Export généré conformément au droit à la portabilité (art. 20 RGPD)',
    }

    log_action(session['user_id'], 'EXPORT_DATA', 'Export JSON — droit à la portabilité')
    return Response(
        json.dumps(data, ensure_ascii=False, indent=2),
        mimetype='application/json',
        headers={'Content-Disposition': f'attachment; filename=mes_donnees_{session["username"]}.json'}
    )

# ──────────────────────────────────────────────
# Routes — Signalements
# ──────────────────────────────────────────────

@app.route('/signaler', methods=['POST'])
@login_required
def signaler():
    history_id  = request.form.get('history_id', type=int)
    query       = request.form.get('query', '').strip()
    response    = request.form.get('response', '').strip()
    raison      = request.form.get('raison', '').strip()
    commentaire = request.form.get('commentaire', '').strip()

    if not raison:
        flash('Veuillez sélectionner une raison de signalement.', 'warning')
        return redirect(url_for('ask'))

    conn = get_db()
    conn.execute(
        "INSERT INTO signalements (user_id, history_id, query, response, raison, commentaire) VALUES (?,?,?,?,?,?)",
        (session['user_id'], history_id, query[:2000], response[:4000], raison, commentaire[:500])
    )
    conn.commit()
    conn.close()
    log_action(session['user_id'], 'SIGNALEMENT', f"raison={raison}, history_id={history_id}")
    notify_admin_signalement(session['username'], raison, commentaire, query, response)
    flash('Signalement envoyé. Merci, un administrateur examinera cette réponse.', 'success')
    return redirect(url_for('ask'))

# ──────────────────────────────────────────────
# Routes — Administration
# ──────────────────────────────────────────────

@app.route('/admin')
@login_required
@admin_required
def admin():
    conn = get_db()
    signalements = conn.execute(
        "SELECT s.*, u.username FROM signalements s LEFT JOIN users u ON s.user_id = u.id "
        "ORDER BY s.statut ASC, s.timestamp DESC"
    ).fetchall()
    total_signalements = conn.execute(
        "SELECT COUNT(*) as c FROM signalements WHERE statut='en_attente'"
    ).fetchone()['c']
    total_traites = conn.execute(
        "SELECT COUNT(*) as c FROM signalements WHERE statut='traite'"
    ).fetchone()['c']
    conn.close()
    log_action(session['user_id'], 'ADMIN_VIEW', 'Consultation tableau de bord admin')
    return render_template('admin.html',
                           signalements=signalements,
                           total_signalements=total_signalements,
                           total_traites=total_traites)

@app.route('/admin/signalement/<int:sig_id>/traiter', methods=['POST'])
@login_required
@admin_required
def admin_traiter_signalement(sig_id):
    conn = get_db()
    conn.execute("UPDATE signalements SET statut='traite' WHERE id=?", (sig_id,))
    conn.commit()
    conn.close()
    log_action(session['user_id'], 'TRAITER_SIGNALEMENT', f"id={sig_id}")
    flash('Signalement marqué comme traité.', 'success')
    return redirect(url_for('admin'))

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def admin_delete_user(user_id):
    if user_id == session['user_id']:
        flash('Vous ne pouvez pas supprimer votre propre compte.', 'danger')
        return redirect(url_for('admin'))
    conn = get_db()
    conn.execute("DELETE FROM history WHERE user_id=?",   (user_id,))
    conn.execute("DELETE FROM requests WHERE user_id=?",  (user_id,))
    conn.execute("DELETE FROM audit_log WHERE user_id=?", (user_id,))
    conn.execute("DELETE FROM users WHERE id=?",          (user_id,))
    conn.commit()
    conn.close()
    log_action(session['user_id'], 'ADMIN_DELETE_USER', f"user_id={user_id}")
    flash('Utilisateur supprimé avec toutes ses données.', 'success')
    return redirect(url_for('admin'))

# ──────────────────────────────────────────────
# Route — À propos
# ──────────────────────────────────────────────

@app.route('/a-propos')
@login_required
def a_propos():
    return render_template('a_propos.html')

# ──────────────────────────────────────────────
# API
# ──────────────────────────────────────────────

@app.route('/api/check_pii', methods=['POST'])
@login_required
def api_check_pii():
    data = request.get_json()
    text = data.get('text', '')
    has_pii, label = detect_pii(text)
    return jsonify({'has_pii': has_pii, 'label': label})

init_db()

if __name__ == '__main__':
    debug_mode = os.getenv('FLASK_DEBUG', 'false').lower() == 'true'
    app.run(debug=debug_mode, host='0.0.0.0', port=5000, use_reloader=False)
