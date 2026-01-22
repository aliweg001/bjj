import os
from dotenv import load_dotenv
from functools import wraps
from flask import (
    Flask, render_template, request, redirect, url_for, flash, session, g
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import psycopg2
from psycopg2.extras import RealDictCursor

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'bjj-pro-key-2026')

# Konfiguracja plików wideo
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'mp4', 'mov', 'avi', 'wmv'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

DB_DSN = os.getenv('DATABASE_URL')


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def get_db():
    if 'db' not in g:
        g.db = psycopg2.connect(DB_DSN, cursor_factory=RealDictCursor)
    return g.db


@app.teardown_appcontext
def close_db(e=None):
    db = g.pop('db', None)
    if db is not None: db.close()


# BEZPIECZNE ZAPYTANIA Z ROLLBACKIEM
def db_query(sql, params=None):
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute(sql, params or ())
        rows = cur.fetchall()
        cur.close()
        return rows
    except Exception as e:
        db.rollback()
        cur.close()
        raise e


def db_execute(sql, params=None):
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute(sql, params or ())
        db.commit()
        cur.close()
    except Exception as e:
        db.rollback()
        cur.close()
        raise e


# --- DEKORATORY ---
def login_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if 'user_id' not in session: return redirect(url_for('login'))
        return f(*args, **kwargs)

    return wrapped


def admin_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if 'user_id' not in session: return redirect(url_for('login'))
        user = db_query("SELECT is_admin FROM users WHERE id = %s", (session['user_id'],))
        if not user or not user[0]['is_admin']:
            flash('Brak uprawnień admina.', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)

    return wrapped


def approved_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if 'user_id' not in session: return redirect(url_for('login'))
        user = db_query("SELECT is_approved FROM users WHERE id = %s", (session['user_id'],))
        if not user or not user[0]['is_approved']:
            return redirect(url_for('pending_approval'))
        return f(*args, **kwargs)

    return wrapped


# --- TRASA NAPRAWCZA (USUWA GARDĘ I DODAJE OPIS KOŃCZEŃ) ---
@app.route('/setup-database')
@login_required
@admin_required
def setup_database():
    try:
        # 1. Kolumny dla wideo
        db_execute("ALTER TABLE techniques ADD COLUMN IF NOT EXISTS video_url TEXT")
        db_execute("ALTER TABLE techniques ADD COLUMN IF NOT EXISTS video_filename TEXT")

        # 2. Kolumna dla opisu kategorii
        db_execute("ALTER TABLE categories ADD COLUMN IF NOT EXISTS description TEXT")

        # 3. Porządki w kategoriach
        db_execute("DELETE FROM categories WHERE name = 'Garda'")

        # 4. Dodanie/Aktualizacja kategorii
        db_execute("INSERT INTO categories (name, description) VALUES (%s, %s) ON CONFLICT (name) DO NOTHING",
                   ('Przejścia', 'Techniki omijania gardy przeciwnika.'))

        db_execute(
            "INSERT INTO categories (name, description) VALUES (%s, %s) ON CONFLICT (name) DO UPDATE SET description = EXCLUDED.description",
            ('Kończenia', 'Techniki kończące walkę, takie jak dźwignie i duszenia.'))

        flash('Baza zaktualizowana: Garda usunięta, Kończenia mają opis!', 'success')
    except Exception as e:
        flash(f'Błąd: {e}', 'error')
    return redirect(url_for('dashboard'))


# --- TRASY ---
@app.route('/')
def index():
    return redirect(url_for('dashboard')) if 'user_id' in session else redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = db_query("SELECT * FROM users WHERE username = %s", (request.form.get('username'),))
        if user and check_password_hash(user[0]['password'], request.form.get('password')):
            session.clear()
            session['user_id'] = user[0]['id']
            session['username'] = user[0]['username']
            session['is_admin'] = user[0]['is_admin']
            return redirect(url_for('dashboard'))
        flash('Błędne dane.', 'error')
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        u, e, f = request.form.get('username'), request.form.get('email'), request.form.get('full_name')
        p = generate_password_hash(request.form.get('password'))
        try:
            db_execute("INSERT INTO users (username, email, full_name, password) VALUES (%s, %s, %s, %s)", (u, e, f, p))
            flash('Zarejestrowano!', 'success')
            return redirect(url_for('login'))
        except:
            flash('Błąd rejestracji.', 'error')
    return render_template('register.html')


@app.route('/dashboard')
@login_required
@approved_required
def dashboard():
    stats = {
        'techniques_count': 0, 'categories_count': 0, 'videos_count': 0
    }
    try:
        stats['techniques_count'] = db_query("SELECT COUNT(*) as c FROM techniques")[0]['c']
        stats['categories_count'] = db_query("SELECT COUNT(*) as c FROM categories")[0]['c']
        stats['videos_count'] = db_query("""
                                         SELECT COUNT(*) as c
                                         FROM techniques
                                         WHERE (video_url IS NOT NULL AND video_url != '')
                                            OR (video_filename IS NOT NULL AND video_filename != '')
                                         """)[0]['c']
    except:
        pass

    recent = []
    try:
        recent = db_query("SELECT * FROM techniques ORDER BY id DESC LIMIT 5")
    except:
        pass

    cats = []
    try:
        cats = db_query("SELECT * FROM categories")
    except:
        pass

    return render_template('dashboard.html', stats=stats, recent_techniques=recent, categories=cats)


@app.route('/technique/add', methods=['GET', 'POST'])
@login_required
@approved_required
def add_technique():
    if request.method == 'POST':
        name, cat_id, desc, v_url = request.form.get('name'), request.form.get('category_id'), request.form.get(
            'description'), request.form.get('video_url')
        v_filename = None
        if 'video_file' in request.files:
            file = request.files['video_file']
            if file and file.filename != '' and allowed_file(file.filename):
                v_filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], v_filename))

        db_execute(
            "INSERT INTO techniques (name, category_id, description, video_url, video_filename) VALUES (%s, %s, %s, %s, %s)",
            (name, cat_id, desc, v_url, v_filename))
        flash('Dodano!', 'success')
        return redirect(url_for('techniques'))

    categories = db_query("SELECT * FROM categories")
    return render_template('add_technique.html', categories=categories)


@app.route('/techniques')
@login_required
@approved_required
def techniques():
    t_list = db_query("SELECT * FROM techniques")
    return render_template('techniques.html', techniques=t_list)


@app.route('/admin/dashboard')
@login_required
@admin_required
def admin_dashboard():
    pending = db_query("SELECT id, username, email FROM users WHERE is_approved = 0")
    all_u = db_query("SELECT id, username, email, is_approved, is_admin FROM users")
    return render_template('admin_dashboard.html', pending_users=pending, all_users=all_u)


@app.route('/admin/approve/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def approve_user(user_id):
    db_execute("UPDATE users SET is_approved = 1 WHERE id = %s", (user_id,))
    flash('Zatwierdzono.')
    return redirect(url_for('admin_dashboard'))


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/pending-approval')
def pending_approval():
    return "Czekaj na zatwierdzenie konta."


if __name__ == '__main__':
    app.run(debug=True)