from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
import sqlite3
import os
from datetime import datetime
from dotenv import load_dotenv
import urllib.parse

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-change-in-production')
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500MB max file size
app.config['ALLOWED_EXTENSIONS'] = {'mp4', 'avi', 'mov', 'mkv', 'webm'}
app.config['DATABASE_URL'] = os.getenv('DATABASE_URL', 'sqlite:///bjj_app.db')

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Check if using PostgreSQL
USE_POSTGRES = app.config['DATABASE_URL'].startswith('postgres')

if USE_POSTGRES:
    import psycopg2
    from psycopg2.extras import RealDictCursor

    # Fix Render's postgres:// to postgresql://
    if app.config['DATABASE_URL'].startswith('postgres://'):
        app.config['DATABASE_URL'] = app.config['DATABASE_URL'].replace('postgres://', 'postgresql://', 1)

# Database initialization
def init_db():
    if USE_POSTGRES:
        conn = get_db()
        c = conn.cursor()

        # Users table
        c.execute('''CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            full_name TEXT NOT NULL,
            is_approved INTEGER DEFAULT 0,
            is_admin INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')

        # Categories table
        c.execute('''CREATE TABLE IF NOT EXISTS categories (
            id SERIAL PRIMARY KEY,
            name TEXT UNIQUE NOT NULL,
            description TEXT
        )''')

        # Techniques table
        c.execute('''CREATE TABLE IF NOT EXISTS techniques (
            id SERIAL PRIMARY KEY,
            title TEXT NOT NULL,
            description TEXT,
            category_id INTEGER,
            position TEXT,
            difficulty TEXT,
            added_by INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (category_id) REFERENCES categories(id),
            FOREIGN KEY (added_by) REFERENCES users(id)
        )''')

        # Videos table
        c.execute('''CREATE TABLE IF NOT EXISTS videos (
            id SERIAL PRIMARY KEY,
            technique_id INTEGER,
            filename TEXT NOT NULL,
            original_filename TEXT NOT NULL,
            video_type TEXT,
            uploaded_by INTEGER,
            uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (technique_id) REFERENCES techniques(id),
            FOREIGN KEY (uploaded_by) REFERENCES users(id)
        )''')

        # Insert default categories
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

        for cat in default_categories:
            c.execute('INSERT INTO categories (name, description) VALUES (%s, %s) ON CONFLICT (name) DO NOTHING', cat)

        # Create default admin user
        admin_hash = generate_password_hash('admin123')
        c.execute('''INSERT INTO users (username, email, password, full_name, is_approved, is_admin) 
                     VALUES (%s, %s, %s, %s, 1, 1) ON CONFLICT (username) DO NOTHING''', 
                  ('admin', 'admin@bjj.com', admin_hash, 'Administrator'))

        conn.commit()
        conn.close()
    else:
        conn = sqlite3.connect('bjj_app.db')
        c = conn.cursor()

    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        full_name TEXT NOT NULL,
        is_approved INTEGER DEFAULT 0,
        is_admin INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')

    # Categories table
    c.execute('''CREATE TABLE IF NOT EXISTS categories (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        description TEXT
    )''')

    # Techniques table
    c.execute('''CREATE TABLE IF NOT EXISTS techniques (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        description TEXT,
        category_id INTEGER,
        position TEXT,
        difficulty TEXT,
        added_by INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (category_id) REFERENCES categories(id),
        FOREIGN KEY (added_by) REFERENCES users(id)
    )''')

    # Videos table
    c.execute('''CREATE TABLE IF NOT EXISTS videos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        technique_id INTEGER,
        filename TEXT NOT NULL,
        original_filename TEXT NOT NULL,
        video_type TEXT,
        uploaded_by INTEGER,
        uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (technique_id) REFERENCES techniques(id),
        FOREIGN KEY (uploaded_by) REFERENCES users(id)
    )''')

    # Insert default categories
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

    for cat in default_categories:
        c.execute('INSERT OR IGNORE INTO categories (name, description) VALUES (?, ?)', cat)

    # Create default admin user (username: admin, password: admin123)
    admin_hash = generate_password_hash('admin123')
    c.execute('''INSERT OR IGNORE INTO users (username, email, password, full_name, is_approved, is_admin) 
                 VALUES (?, ?, ?, ?, 1, 1)''', 
              ('admin', 'admin@bjj.com', admin_hash, 'Administrator'))

    conn.commit()
    conn.close()

def execute_query(query, params=None, fetch=True):
    """Helper function to execute queries with proper parameter syntax"""
    conn = get_db()
    c = conn.cursor()

    if USE_POSTGRES:
        # Convert ? to %s for PostgreSQL
        query = query.replace('?', '%s')

    if params:
        c.execute(query, params)
    else:
        c.execute(query)

    if fetch:
        if fetch == 'one':
            result = c.fetchone()
        else:
            result = c.fetchall()
        conn.close()
        return result
    else:
        conn.commit()
        lastrowid = c.lastrowid if hasattr(c, 'lastrowid') else None
        conn.close()
        return lastrowid

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# Decorators
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
        user = conn.execute('SELECT is_admin FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        conn.close()

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
        conn.close()

        if not user or not user['is_approved']:
            flash('Twoje konto oczekuje na zatwierdzenie przez administratora.', 'warning')
            return redirect(url_for('pending_approval'))
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
def index():
    if 'user_id' in session:
        conn = get_db()
        user = conn.execute('SELECT is_approved FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        conn.close()

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
            conn.close()
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)
        conn.execute('INSERT INTO users (username, email, password, full_name) VALUES (?, ?, ?, ?)',
                    (username, email, hashed_password, full_name))
        conn.commit()
        conn.close()

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
        conn.close()

        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['is_admin'] = user['is_admin']
            session['is_approved'] = user['is_approved']

            if not user['is_approved']:
                return redirect(url_for('pending_approval'))

            flash(f'Witaj, {user["username"]}!', 'success')
            return redirect(url_for('dashboard'))
        else:
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

    # Get statistics
    total_techniques = conn.execute('SELECT COUNT(*) as count FROM techniques').fetchone()['count']
    total_videos = conn.execute('SELECT COUNT(*) as count FROM videos').fetchone()['count']

    # Get recent techniques
    recent_techniques = conn.execute('''
        SELECT t.*, c.name as category_name, u.username 
        FROM techniques t
        LEFT JOIN categories c ON t.category_id = c.id
        LEFT JOIN users u ON t.added_by = u.id
        ORDER BY t.created_at DESC LIMIT 6
    ''').fetchall()

    # Get categories
    categories = conn.execute('SELECT * FROM categories').fetchall()

    conn.close()

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

    # Get filters
    category_id = request.args.get('category')
    difficulty = request.args.get('difficulty')
    search = request.args.get('search')

    query = '''
        SELECT t.*, c.name as category_name, u.username,
               COUNT(v.id) as video_count
        FROM techniques t
        LEFT JOIN categories c ON t.category_id = c.id
        LEFT JOIN users u ON t.added_by = u.id
        LEFT JOIN videos v ON t.id = v.technique_id
        WHERE 1=1
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

    conn.close()

    return render_template('techniques.html', 
                         techniques=techniques_list,
                         categories=categories)

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
        conn.close()
        return redirect(url_for('techniques'))

    videos = conn.execute('''
        SELECT v.*, u.username 
        FROM videos v
        LEFT JOIN users u ON v.uploaded_by = u.id
        WHERE v.technique_id = ?
        ORDER BY v.uploaded_at DESC
    ''', (technique_id,)).fetchall()

    conn.close()

    return render_template('technique_detail.html', 
                         technique=technique,
                         videos=videos)

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
        cursor = conn.execute('''
            INSERT INTO techniques (title, description, category_id, position, difficulty, added_by)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (title, description, category_id, position, difficulty, session['user_id']))

        technique_id = cursor.lastrowid
        conn.commit()
        conn.close()

        flash('Technika została dodana pomyślnie!', 'success')
        return redirect(url_for('technique_detail', technique_id=technique_id))

    conn = get_db()
    categories = conn.execute('SELECT * FROM categories').fetchall()
    conn.close()

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
        conn.close()

        flash('Film został przesłany pomyślnie!', 'success')
    else:
        flash('Niedozwolony typ pliku. Dozwolone: mp4, avi, mov, mkv, webm', 'error')

    return redirect(url_for('technique_detail', technique_id=technique_id))

@app.route('/admin/dashboard')
@login_required
@admin_required
def admin_dashboard():
    conn = get_db()

    pending_users = conn.execute('''
        SELECT * FROM users WHERE is_approved = 0 ORDER BY created_at DESC
    ''').fetchall()

    all_users = conn.execute('''
        SELECT * FROM users ORDER BY created_at DESC
    ''').fetchall()

    conn.close()

    return render_template('admin_dashboard.html', 
                         pending_users=pending_users,
                         all_users=all_users)

@app.route('/admin/approve-user/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def approve_user(user_id):
    conn = get_db()
    conn.execute('UPDATE users SET is_approved = 1 WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()

    flash('Użytkownik został zatwierdzony.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/reject-user/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def reject_user(user_id):
    conn = get_db()
    conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()

    flash('Użytkownik został odrzucony i usunięty.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/search')
@login_required
@approved_required
def search():
    query = request.args.get('q', '')

    if not query:
        return jsonify([])

    conn = get_db()
    results = conn.execute('''
        SELECT t.id, t.title, c.name as category_name
        FROM techniques t
        LEFT JOIN categories c ON t.category_id = c.id
        WHERE t.title LIKE ? OR t.description LIKE ?
        LIMIT 10
    ''', (f'%{query}%', f'%{query}%')).fetchall()
    conn.close()

    return jsonify([dict(r) for r in results])

if __name__ == '__main__':
    init_db()
    app.run(debug=True)


if __name__ == '__main__':
    app.run()
