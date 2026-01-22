# python
import os
from dotenv import load_dotenv
load_dotenv()
from functools import wraps
from datetime import datetime
from flask import (
    Flask, render_template, request, redirect, url_for, flash, session,
    jsonify, g, send_from_directory
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

try:
    import psycopg2
    from psycopg2 import IntegrityError
    from psycopg2.extras import RealDictCursor
except Exception as e:
    raise RuntimeError("Zainstaluj psycopg2-binary i ustaw DATABASE_URL") from e

# Konfiguracja
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'change-me-for-dev')
app.config['UPLOAD_FOLDER'] = os.getenv('UPLOAD_FOLDER', 'static/uploads')
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024
ALLOWED_EXTENSIONS = {'mp4', 'avi', 'mov', 'mkv', 'webm'}

DB_DSN = os.getenv('DATABASE_URL')
if not DB_DSN:
    raise RuntimeError("Ustaw zmienną środowiskową DATABASE_URL dla PostgreSQL")

# DB helpers
def get_db():
    if 'db' not in g:
        conn = psycopg2.connect(DB_DSN, cursor_factory=RealDictCursor)
        conn.autocommit = False
        g.db = conn
    return g.db

@app.teardown_appcontext
def close_db(exc=None):
    db = g.pop('db', None)
    if db is not None:
        try:
            if exc:
                db.rollback()
        finally:
            db.close()

def db_query(sql, params=None):
    params = params or ()
    conn = get_db()
    cur = conn.cursor()
    cur.execute(sql, params)
    rows = cur.fetchall()
    cur.close()
    return rows

def db_execute(sql, params=None, returning=False):
    params = params or ()
    conn = get_db()
    cur = conn.cursor()
    cur.execute(sql, params)
    result = None
    if returning:
        result = cur.fetchone()
    conn.commit()
    cur.close()
    return result

def init_db():
    # tworzymy tabele i domyślne dane
    conn = psycopg2.connect(DB_DSN)
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE,
        password TEXT NOT NULL,
        full_name TEXT,
        is_approved INTEGER DEFAULT 0,
        is_admin INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS categories (
        id SERIAL PRIMARY KEY,
        name TEXT UNIQUE NOT NULL,
        description TEXT
    );
    CREATE TABLE IF NOT EXISTS techniques (
        id SERIAL PRIMARY KEY,
        title TEXT NOT NULL,
        description TEXT,
        category_id INTEGER REFERENCES categories(id),
        position TEXT,
        difficulty TEXT,
        added_by INTEGER REFERENCES users(id),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS videos (
        id SERIAL PRIMARY KEY,
        technique_id INTEGER REFERENCES techniques(id),
        filename TEXT NOT NULL,
        original_filename TEXT NOT NULL,
        video_type TEXT,
        uploaded_by INTEGER REFERENCES users(id),
        uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)
    # default categories
    default_categories = [
        ('Pozycje', 'Podstawowe pozycje w BJJ'),
        ('Submisje', 'Techniki poddań'),
        ('Przejścia', 'Przejścia między pozycjami'),
        ('Ucieczki', 'Techniki ucieczek'),
        ('Zarzuty', 'Techniki zarzutów'),
        ('Obrony', 'Techniki obronne'),
        ('Guardy', 'Różne typy guardów'),
        ('Pasowanie', 'Techniki pasowania guardu')
    ]
    for name, desc in default_categories:
        cur.execute("""
            INSERT INTO categories (name, description)
            VALUES (%s, %s)
            ON CONFLICT (name) DO NOTHING
        """, (name, desc))
    # default admin
    admin_hash = generate_password_hash('admin123')
    cur.execute("""
        INSERT INTO users (username, email, password, full_name, is_approved, is_admin)
        VALUES (%s, %s, %s, %s, 1, 1)
        ON CONFLICT (username) DO NOTHING
    """, ('admin', 'admin@bjj.com', admin_hash, 'Administrator'))
    conn.commit()
    cur.close()
    conn.close()

# Utilities
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Decorators
def login_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if 'user_id' not in session:
            flash('Musisz być zalogowany.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapped

def admin_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if 'user_id' not in session:
            flash('Musisz być zalogowany.', 'error')
            return redirect(url_for('login'))
        user = db_query("SELECT is_admin FROM users WHERE id = %s", (session['user_id'],))
        if not user or not user[0].get('is_admin'):
            flash('Brak uprawnień administratora.', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return wrapped

def approved_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        user = db_query("SELECT is_approved FROM users WHERE id = %s", (session['user_id'],))
        if not user or not user[0].get('is_approved'):
            flash('Twoje konto oczekuje zatwierdzenia.', 'warning')
            return redirect(url_for('pending_approval'))
        return f(*args, **kwargs)
    return wrapped

# Routes
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        email = (request.form.get('email') or '').strip()
        password = request.form.get('password') or ''
        full_name = (request.form.get('full_name') or '').strip()
        if not username or not password:
            flash('Nazwa i hasło są wymagane.', 'error')
            return redirect(url_for('register'))
        if len(password) < 6:
            flash('Hasło min 6 znaków.', 'error')
            return redirect(url_for('register'))
        pw_hash = generate_password_hash(password)
        try:
            db_execute("""
                INSERT INTO users (username, email, password, full_name)
                VALUES (%s, %s, %s, %s)
            """, (username, email or None, pw_hash, full_name or None))
        except IntegrityError:
            flash('Nazwa użytkownika lub email już istnieje.', 'error')
            return redirect(url_for('register'))
        flash('Zarejestrowano. Poczekaj na zatwierdzenie.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        password = request.form.get('password') or ''
        row = db_query("SELECT * FROM users WHERE username = %s", (username,))
        user = row[0] if row else None
        if user and check_password_hash(user['password'], password):
            session.clear()
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['is_admin'] = user.get('is_admin', 0)
            session['is_approved'] = user.get('is_approved', 0)
            if not session['is_approved']:
                return redirect(url_for('pending_approval'))
            flash('Zalogowano.', 'success')
            return redirect(url_for('dashboard'))
        flash('Nieprawidłowe dane.', 'error')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Wylogowano.', 'info')
    return redirect(url_for('login'))

@app.route('/pending-approval')
@login_required
def pending_approval():
    return render_template('pending_approval.html')

@app.route('/dashboard')
@login_required
@approved_required
def dashboard():
    total_tech = db_query("SELECT COUNT(*) as count FROM techniques")[0]['count']
    total_vid = db_query("SELECT COUNT(*) as count FROM videos")[0]['count']
    recent = db_query("""
        SELECT t.*, c.name AS category_name, u.username
        FROM techniques t
        LEFT JOIN categories c ON t.category_id = c.id
        LEFT JOIN users u ON t.added_by = u.id
        ORDER BY t.created_at DESC
        LIMIT 6
    """)
    categories = db_query("SELECT * FROM categories ORDER BY name")
    return render_template('dashboard.html', total_techniques=total_tech, total_videos=total_vid,
                           recent_techniques=recent, categories=categories)

@app.route('/techniques')
@login_required
@approved_required
def techniques():
    category = request.args.get('category')
    difficulty = request.args.get('difficulty')
    search = request.args.get('search')
    params = []
    where = []
    sql = """
        SELECT t.*, c.name as category_name, u.username,
               COUNT(v.id) as video_count
        FROM techniques t
        LEFT JOIN categories c ON t.category_id = c.id
        LEFT JOIN users u ON t.added_by = u.id
        LEFT JOIN videos v ON t.id = v.technique_id
    """
    if category:
        where.append("t.category_id = %s"); params.append(category)
    if difficulty:
        where.append("t.difficulty = %s"); params.append(difficulty)
    if search:
        where.append("(t.title ILIKE %s OR t.description ILIKE %s)"); params.extend([f'%{search}%', f'%{search}%'])
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " GROUP BY t.id, c.name, u.username ORDER BY t.created_at DESC"
    techniques_list = db_query(sql, tuple(params))
    categories = db_query("SELECT * FROM categories ORDER BY name")
    return render_template('techniques.html', techniques=techniques_list, categories=categories)

@app.route('/technique/<int:technique_id>')
@login_required
@approved_required
def technique_detail(technique_id):
    t = db_query("""
        SELECT t.*, c.name as category_name, u.username
        FROM techniques t
        LEFT JOIN categories c ON t.category_id = c.id
        LEFT JOIN users u ON t.added_by = u.id
        WHERE t.id = %s
    """, (technique_id,))
    technique = t[0] if t else None
    if not technique:
        flash('Technika nie znaleziona.', 'error')
        return redirect(url_for('techniques'))
    videos = db_query("""
        SELECT v.*, u.username FROM videos v
        LEFT JOIN users u ON v.uploaded_by = u.id
        WHERE v.technique_id = %s ORDER BY v.uploaded_at DESC
    """, (technique_id,))
    return render_template('technique_detail.html', technique=technique, videos=videos)

@app.route('/technique/add', methods=['GET', 'POST'])
@login_required
@approved_required
def add_technique():
    if request.method == 'POST':
        title = (request.form.get('title') or '').strip()
        description = request.form.get('description')
        category_id = request.form.get('category_id') or None
        position = request.form.get('position') or None
        difficulty = request.form.get('difficulty') or None
        if not title:
            flash('Tytuł wymagany.', 'error')
            return redirect(url_for('add_technique'))
        # zwracamy id dodanej techniki
        res = db_execute("""
            INSERT INTO techniques (title, description, category_id, position, difficulty, added_by)
            VALUES (%s, %s, %s, %s, %s, %s) RETURNING id
        """, (title, description, category_id, position, difficulty, session['user_id']), returning=True)
        technique_id = res['id'] if res else None
        flash('Dodano technikę.', 'success')
        return redirect(url_for('technique_detail', technique_id=technique_id))
    categories = db_query("SELECT * FROM categories ORDER BY name")
    return render_template('add_technique.html', categories=categories)

@app.route('/technique/<int:technique_id>/upload-video', methods=['POST'])
@login_required
@approved_required
def upload_video(technique_id):
    if 'video' not in request.files:
        flash('Nie wybrano pliku.', 'error')
        return redirect(url_for('technique_detail', technique_id=technique_id))
    file = request.files['video']
    if file.filename == '':
        flash('Nie wybrano pliku.', 'error')
        return redirect(url_for('technique_detail', technique_id=technique_id))
    if not allowed_file(file.filename):
        flash('Niedozwolony format pliku.', 'error')
        return redirect(url_for('technique_detail', technique_id=technique_id))
    filename = secure_filename(file.filename)
    stamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    stored = f"{stamp}_{filename}"
    path = os.path.join(app.config['UPLOAD_FOLDER'], stored)
    file.save(path)
    db_execute("""
        INSERT INTO videos (technique_id, filename, original_filename, video_type, uploaded_by)
        VALUES (%s, %s, %s, %s, %s)
    """, (technique_id, stored, filename, request.form.get('video_type', 'training'), session['user_id']))
    flash('Film przesłany.', 'success')
    return redirect(url_for('technique_detail', technique_id=technique_id))

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/admin/dashboard')
@login_required
@admin_required
def admin_dashboard():
    pending = db_query("SELECT * FROM users WHERE is_approved = 0 ORDER BY created_at DESC")
    all_users = db_query("SELECT * FROM users ORDER BY created_at DESC")
    return render_template('admin_dashboard.html', pending_users=pending, all_users=all_users)

@app.route('/admin/approve-user/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def approve_user(user_id):
    db_execute("UPDATE users SET is_approved = 1 WHERE id = %s", (user_id,))
    flash('Użytkownik zatwierdzony.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/reject-user/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def reject_user(user_id):
    db_execute("DELETE FROM users WHERE id = %s", (user_id,))
    flash('Użytkownik odrzucony i usunięty.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/search')
@login_required
@approved_required
def search():
    q = request.args.get('q', '').strip()
    if not q:
        return jsonify([])
    rows = db_query("""
        SELECT t.id, t.title, c.name as category_name
        FROM techniques t
        LEFT JOIN categories c ON t.category_id = c.id
        WHERE t.title ILIKE %s OR t.description ILIKE %s
        LIMIT 10
    """, (f'%{q}%', f'%{q}%'))
    return jsonify(rows)

if __name__ == '__main__':
    # init DB once
    try:
        init_db()
    except Exception as e:
        print("init_db error:", e)
    app.run(debug=True)