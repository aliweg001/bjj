import os
import sqlite3
from datetime import datetime
from functools import wraps
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, g
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'change-me-for-prod')
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024
app.config['ALLOWED_EXTENSIONS'] = {'mp4', 'avi', 'mov', 'mkv', 'webm'}
app.config['DATABASE_URL'] = os.getenv('DATABASE_URL', 'sqlite:///bjj_app.db')

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

USE_POSTGRES = app.config['DATABASE_URL'].startswith('postgres')

if USE_POSTGRES:
    import psycopg2
    from psycopg2.extras import RealDictCursor

    # render/old style fix
    if app.config['DATABASE_URL'].startswith('postgres://'):
        app.config['DATABASE_URL'] = app.config['DATABASE_URL'].replace('postgres://', 'postgresql://', 1)


def get_db():
    if hasattr(g, 'db') and g.db is not None:
        return g.db

    if USE_POSTGRES:
        dsn = app.config['DATABASE_URL']
        raw_conn = psycopg2.connect(dsn)

        class PGConn:
            def __init__(self, conn):
                self._conn = conn
                self._last_cur = None

            def _convert(self, query):
                return query.replace('?', '%s')

            def execute(self, query, params=None):
                cur = self._conn.cursor(cursor_factory=RealDictCursor)
                q = self._convert(query) if params else query
                if params:
                    cur.execute(q, params)
                else:
                    cur.execute(q)
                self._last_cur = cur
                return self

            def fetchone(self):
                return self._last_cur.fetchone() if self._last_cur is not None else None

            def fetchall(self):
                return self._last_cur.fetchall() if self._last_cur is not None else []

            def cursor(self):
                return self._conn.cursor(cursor_factory=RealDictCursor)

            def commit(self):
                self._conn.commit()

            def close(self):
                try:
                    self._conn.close()
                except Exception:
                    pass

            @property
            def lastrowid(self):
                return None

        g.db = PGConn(raw_conn)
        return g.db

    db_url = app.config.get('DATABASE_URL', 'sqlite:///bjj_app.db')
    if db_url.startswith('sqlite:///'):
        db_path = db_url.replace('sqlite:///', '', 1)
    else:
        db_path = db_url
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    g.db = conn
    return g.db


def close_db(e=None):
    db = g.pop('db', None)
    if db is None:
        return
    try:
        db.close()
    except Exception:
        pass


app.teardown_appcontext(close_db)


def init_db():
    conn = get_db()
    if USE_POSTGRES:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users
                     (
                         id
                         SERIAL
                         PRIMARY
                         KEY,
                         username
                         TEXT
                         UNIQUE
                         NOT
                         NULL,
                         email
                         TEXT
                         UNIQUE
                         NOT
                         NULL,
                         password
                         TEXT
                         NOT
                         NULL,
                         full_name
                         TEXT
                         NOT
                         NULL,
                         is_approved
                         INTEGER
                         DEFAULT
                         0,
                         is_admin
                         INTEGER
                         DEFAULT
                         0,
                         created_at
                         TIMESTAMP
                         DEFAULT
                         CURRENT_TIMESTAMP
                     )''')
        c.execute('''CREATE TABLE IF NOT EXISTS categories
                     (
                         id
                         SERIAL
                         PRIMARY
                         KEY,
                         name
                         TEXT
                         UNIQUE
                         NOT
                         NULL,
                         description
                         TEXT
                     )''')
        c.execute('''CREATE TABLE IF NOT EXISTS techniques
        (
            id
            SERIAL
            PRIMARY
            KEY,
            title
            TEXT
            NOT
            NULL,
            description
            TEXT,
            category_id
            INTEGER,
            position
            TEXT,
            difficulty
            TEXT,
            added_by
            INTEGER,
            created_at
            TIMESTAMP
            DEFAULT
            CURRENT_TIMESTAMP,
            FOREIGN
            KEY
                     (
            category_id
                     ) REFERENCES categories
                     (
                         id
                     ),
            FOREIGN KEY
                     (
                         added_by
                     ) REFERENCES users
                     (
                         id
                     )
            )''')
        c.execute('''CREATE TABLE IF NOT EXISTS videos
        (
            id
            SERIAL
            PRIMARY
            KEY,
            technique_id
            INTEGER,
            filename
            TEXT
            NOT
            NULL,
            original_filename
            TEXT
            NOT
            NULL,
            video_type
            TEXT,
            uploaded_by
            INTEGER,
            uploaded_at
            TIMESTAMP
            DEFAULT
            CURRENT_TIMESTAMP,
            FOREIGN
            KEY
                     (
            technique_id
                     ) REFERENCES techniques
                     (
                         id
                     ),
            FOREIGN KEY
                     (
                         uploaded_by
                     ) REFERENCES users
                     (
                         id
                     )
            )''')
        default_categories = [
            ('Pozycje', 'Podstawowe pozycje w BJJ'),
            ('Submisje', 'Techniki poddań'),
            ('Przejścia', 'Przejścia pomiędzy pozycjami'),
        ]
        for name, desc in default_categories:
            c.execute('INSERT INTO categories (name, description) VALUES (%s, %s) ON CONFLICT (name) DO NOTHING',
                      (name, desc))
        admin_hash = generate_password_hash('admin123')
        c.execute('''INSERT INTO users (username, email, password, full_name, is_approved, is_admin)
                     VALUES (%s, %s, %s, %s, 1, 1) ON CONFLICT (username) DO NOTHING''',
                  ('admin', 'admin@bjj.com', admin_hash, 'Administrator'))
        conn.commit()
    else:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users
                     (
                         id
                         INTEGER
                         PRIMARY
                         KEY
                         AUTOINCREMENT,
                         username
                         TEXT
                         UNIQUE
                         NOT
                         NULL,
                         email
                         TEXT
                         UNIQUE
                         NOT
                         NULL,
                         password
                         TEXT
                         NOT
                         NULL,
                         full_name
                         TEXT
                         NOT
                         NULL,
                         is_approved
                         INTEGER
                         DEFAULT
                         0,
                         is_admin
                         INTEGER
                         DEFAULT
                         0,
                         created_at
                         TIMESTAMP
                         DEFAULT
                         CURRENT_TIMESTAMP
                     )''')
        c.execute('''CREATE TABLE IF NOT EXISTS categories
                     (
                         id
                         INTEGER
                         PRIMARY
                         KEY
                         AUTOINCREMENT,
                         name
                         TEXT
                         UNIQUE
                         NOT
                         NULL,
                         description
                         TEXT
                     )''')
        c.execute('''CREATE TABLE IF NOT EXISTS techniques
        (
            id
            INTEGER
            PRIMARY
            KEY
            AUTOINCREMENT,
            title
            TEXT
            NOT
            NULL,
            description
            TEXT,
            category_id
            INTEGER,
            position
            TEXT,
            difficulty
            TEXT,
            added_by
            INTEGER,
            created_at
            TIMESTAMP
            DEFAULT
            CURRENT_TIMESTAMP,
            FOREIGN
            KEY
                     (
            category_id
                     ) REFERENCES categories
                     (
                         id
                     ),
            FOREIGN KEY
                     (
                         added_by
                     ) REFERENCES users
                     (
                         id
                     )
            )''')
        c.execute('''CREATE TABLE IF NOT EXISTS videos
        (
            id
            INTEGER
            PRIMARY
            KEY
            AUTOINCREMENT,
            technique_id
            INTEGER,
            filename
            TEXT
            NOT
            NULL,
            original_filename
            TEXT
            NOT
            NULL,
            video_type
            TEXT,
            uploaded_by
            INTEGER,
            uploaded_at
            TIMESTAMP
            DEFAULT
            CURRENT_TIMESTAMP,
            FOREIGN
            KEY
                     (
            technique_id
                     ) REFERENCES techniques
                     (
                         id
                     ),
            FOREIGN KEY
                     (
                         uploaded_by
                     ) REFERENCES users
                     (
                         id
                     )
            )''')
        default_categories = [
            ('Pozycje', 'Podstawowe pozycje w BJJ'),
            ('Submisje', 'Techniki poddań'),
            ('Przejścia', 'Przejścia pomiędzy pozycjami'),
        ]
        for name, desc in default_categories:
            c.execute('INSERT OR IGNORE INTO categories (name, description) VALUES (?, ?)', (name, desc))
        admin_hash = generate_password_hash('admin123')
        c.execute('''INSERT
        OR IGNORE INTO users (username, email, password, full_name, is_approved, is_admin)
                     VALUES (?, ?, ?, ?, 1, 1)''',
                  ('admin', 'admin@bjj.com', admin_hash, 'Administrator'))
        conn.commit()


def execute_query(query, params=None, fetch=True):
    conn = get_db()
    if USE_POSTGRES:
        res = conn.execute(query, params)
        if fetch:
            return res.fetchone() if fetch == 'one' else res.fetchall()
        else:
            conn.commit()
            return getattr(conn, 'lastrowid', None)
    else:
        cur = conn.execute(query, params or ())
        if fetch:
            return cur.fetchone() if fetch == 'one' else cur.fetchall()
        else:
            conn.commit()
            return getattr(cur, 'lastrowid', None)


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Musisz być zalogowany, aby uzyskać dostęp do tej strony.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)

    return decorated_function


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Musisz być zalogowany.', 'error')
            return redirect(url_for('login'))
        conn = get_db()
        # Fix: fetchone() returns a Row/dict, ensure access is safe
        user = conn.execute('SELECT is_admin FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        if not user or not user['is_admin']:
            flash('Brak uprawnień administratora.', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)

    return decorated_function


def approved_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        conn = get_db()
        user = conn.execute('SELECT is_approved FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        if not user or not user['is_approved']:
            flash('Twoje konto oczekuje na zatwierdzenie przez administratora.', 'warning')
            return redirect(url_for('pending_approval'))
        return f(*args, **kwargs)

    return decorated_function


@app.route('/')
def index():
    if 'user_id' in session:
        conn = get_db()
        user = conn.execute('SELECT is_approved FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        if user and not user['is_approved']:
            return redirect(url_for('pending_approval'))
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        full_name = request.form.get('full_name')

        if not all([username, email, password, confirm_password, full_name]):
            flash('Wszystkie pola są wymagane.', 'error')
            return redirect(url_for('register'))

        if password != confirm_password:
            flash('Hasła nie pasują do siebie.', 'error')
            return redirect(url_for('register'))

        if len(password) < 6:
            flash('Hasło musi mieć co najmniej 6 znaków.', 'error')
            return redirect(url_for('register'))

        conn = get_db()
        existing_user = conn.execute('SELECT id FROM users WHERE username = ? OR email = ?',
                                     (username, email)).fetchone()
        if existing_user:
            flash('Nazwa użytkownika lub email już istnieją.', 'error')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)
        conn.execute('INSERT INTO users (username, email, password, full_name) VALUES (?, ?, ?, ?)',
                     (username, email, hashed_password, full_name))
        conn.commit()
        flash('Rejestracja przebiegła pomyślnie! Oczekuj na zatwierdzenie przez administratora.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['is_admin'] = user['is_admin']
            session['is_approved'] = user['is_approved']
            if not user['is_approved']:
                return redirect(url_for('pending_approval'))
            flash(f'Witaj, {user["username"]}!', 'success')
            return redirect(url_for('dashboard'))
        flash('Nieprawidłowa nazwa użytkownika lub hasło.', 'error')
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('Wylogowano pomyślnie.', 'success')
    return redirect(url_for('login'))


@app.route('/pending-approval')
@login_required
def pending_approval():
    return render_template('pending_approval.html')


@app.route('/dashboard')
@login_required
@approved_required
def dashboard():
    conn = get_db()
    total_techniques = conn.execute('SELECT COUNT(*) as count FROM techniques').fetchone()['count']
    total_videos = conn.execute('SELECT COUNT(*) as count FROM videos').fetchone()['count']
    recent_techniques = conn.execute('''
                                     SELECT t.*, c.name as category_name, u.username
                                     FROM techniques t
                                              LEFT JOIN categories c ON t.category_id = c.id
                                              LEFT JOIN users u ON t.added_by = u.id
                                     ORDER BY t.created_at DESC LIMIT 6
                                     ''').fetchall()
    categories = conn.execute('SELECT * FROM categories').fetchall()
    return render_template('dashboard.html',
                           total_techniques=total_techniques,
                           total_videos=total_videos,
                           recent_techniques=recent_techniques,
                           categories=categories)


@app.route('/techniques')
@login_required
@approved_required
def techniques():
    conn = get_db()
    category_id = request.args.get('category')
    difficulty = request.args.get('difficulty')
    search = request.args.get('search')
    query = '''
            SELECT t.*, \
                   c.name      as category_name, \
                   u.username,
                   COUNT(v.id) as video_count
            FROM techniques t
                     LEFT JOIN categories c ON t.category_id = c.id
                     LEFT JOIN users u ON t.added_by = u.id
                     LEFT JOIN videos v ON t.id = v.technique_id
            WHERE 1 = 1 \
            '''
    params = []
    if category_id:
        query += ' AND t.category_id = ?'
        params.append(category_id)
    if difficulty:
        query += ' AND t.difficulty = ?'
        params.append(difficulty)
    if search:
        query += ' AND (t.title LIKE ? OR t.description LIKE ?)'
        params.extend([f'%{search}%', f'%{search}%'])
    query += ' GROUP BY t.id ORDER BY t.created_at DESC'
    techniques_list = conn.execute(query, params).fetchall()
    categories = conn.execute('SELECT * FROM categories').fetchall()
    return render_template('techniques.html', techniques=techniques_list, categories=categories)


@app.route('/technique/<int:technique_id>')
@login_required
@approved_required
def technique_detail(technique_id):
    conn = get_db()
    technique = conn.execute('''
                             SELECT t.*, c.name as category_name, u.username
                             FROM techniques t
                                      LEFT JOIN categories c ON t.category_id = c.id
                                      LEFT JOIN users u ON t.added_by = u.id
                             WHERE t.id = ?
                             ''', (technique_id,)).fetchone()
    if not technique:
        flash('Technika nie została znaleziona.', 'error')
        return redirect(url_for('techniques'))
    videos = conn.execute('''
                          SELECT v.*, u.username
                          FROM videos v
                                   LEFT JOIN users u ON v.uploaded_by = u.id
                          WHERE v.technique_id = ?
                          ORDER BY v.uploaded_at DESC
                          ''', (technique_id,)).fetchall()
    return render_template('technique_detail.html', technique=technique, videos=videos)


@app.route('/technique/add', methods=['GET', 'POST'])
@login_required
@approved_required
def add_technique():
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        category_id = request.form.get('category_id')
        position = request.form.get('position')
        difficulty = request.form.get('difficulty')
        if not title:
            flash('Tytuł jest wymagany.', 'error')
            return redirect(url_for('add_technique'))
        conn = get_db()
        cur = conn.execute('''
                           INSERT INTO techniques (title, description, category_id, position, difficulty, added_by)
                           VALUES (?, ?, ?, ?, ?, ?)
                           ''', (title, description, category_id, position, difficulty, session['user_id']))
        technique_id = getattr(cur, 'lastrowid', None)
        conn.commit()
        # Uwaga: Dla bazy SQLite lastrowid zadziała, dla Postgres zwróci None (wymaga innej obsługi)
        # Jeśli używasz SQLite, to zadziała poprawnie.
        if technique_id:
            return redirect(url_for('technique_detail', technique_id=technique_id))

        flash('Technika została dodana pomyślnie!', 'success')
        return redirect(url_for('techniques'))

    conn = get_db()
    categories = conn.execute('SELECT * FROM categories').fetchall()
    return render_template('add_technique.html', categories=categories)


@app.route('/technique/<int:technique_id>/upload-video', methods=['POST'])
@login_required
@approved_required
def upload_video(technique_id):
    if 'video' not in request.files:
        flash('Nie wybrano pliku.', 'error')
        return redirect(url_for('technique_detail', technique_id=technique_id))
    file = request.files['video']
    video_type = request.form.get('video_type', 'training')
    if file.filename == '':
        flash('Nie wybrano pliku.', 'error')
        return redirect(url_for('technique_detail', technique_id=technique_id))
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{timestamp}_{filename}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        conn = get_db()
        conn.execute('''
                     INSERT INTO videos (technique_id, filename, original_filename, video_type, uploaded_by)
                     VALUES (?, ?, ?, ?, ?)
                     ''', (technique_id, filename, file.filename, video_type, session['user_id']))
        conn.commit()
        flash('Film został przesłany pomyślnie!', 'success')
    else:
        flash('Niedozwolony typ pliku. Dozwolone: mp4, avi, mov, mkv, webm', 'error')
    return redirect(url_for('technique_detail', technique_id=technique_id))


@app.route('/admin/dashboard')
@login_required
@admin_required
def admin_dashboard():
    conn = get_db()
    pending_users = conn.execute('SELECT * FROM users WHERE is_approved = 0 ORDER BY created_at DESC').fetchall()
    all_users = conn.execute('SELECT * FROM users ORDER BY created_at DESC').fetchall()
    return render_template('admin_dashboard.html', pending_users=pending_users, all_users=all_users)


@app.route('/admin/approve-user/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def approve_user(user_id):
    conn = get_db()
    conn.execute('UPDATE users SET is_approved = 1 WHERE id = ?', (user_id,))
    conn.commit()
    flash('Użytkownik został zatwierdzony.', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/reject-user/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def reject_user(user_id):
    conn = get_db()
    conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.commit()
    flash('Użytkownik został odrzucony i usunięty.', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/search')
@login_required
@approved_required
def search():
    q = request.args.get('q', '')
    if not q:
        return jsonify([])
    conn = get_db()
    results = conn.execute('''
                           SELECT t.id, t.title, c.name as category_name
                           FROM techniques t
                                    LEFT JOIN categories c ON t.category_id = c.id
                           WHERE t.title LIKE ?
                              OR t.description LIKE ? LIMIT 10
                           ''', (f'%{q}%', f'%{q}%')).fetchall()
    return jsonify([dict(r) for r in results])


if __name__ == '__main__':
    init_db()
    app.run(debug=True)