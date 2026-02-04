import os
import psycopg2
import psycopg2.extras
from flask import Flask, render_template, request, redirect, url_for, session, flash
from functools import wraps
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import re
from flask import jsonify


load_dotenv()
app = Flask(__name__)
app.secret_key = 'bjj_klucz_ostateczny'

# --- 1. OMIJANIE BŁĘDU "ł" W ŚCIEŻCE WINDOWS ---
os.environ["PGPASSFILE"] = "NUL"
os.environ["PGSSLMODE"] = "disable"

# --- 2. KONFIGURACJA ŚCIEŻEK ---
app.config['UPLOAD_FOLDER'] = 'static/uploads'
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])


# --- 3. POŁĄCZENIE Z BAZĄ DANYCH ---
def get_db_connection():
    conn = psycopg2.connect(
        host="localhost",
        database="bjj_db",
        user="postgres",
        password="admin",
        port=5433,
        client_encoding='utf8'
    )
    return conn


# --- FUNKCJE POMOCNICZE ---
def extract_youtube_id(url):
    """Wyodrębnia ID filmu z URL YouTube"""
    patterns = [
        r'(?:youtube\.com\/watch\?v=)([\w-]{11})',
        r'(?:youtu\.be\/)([\w-]{11})',
        r'(?:youtube\.com\/embed\/)([\w-]{11})'
    ]

    for pattern in patterns:
        match = re.search(pattern, url)
        if match:
            return match.group(1)
    return None

@app.template_filter('youtube_id')
def youtube_id_filter(url):
    """Wyodrębnia ID filmu YouTube z URL."""
    # Przykładowe formaty URL:
    # https://www.youtube.com/watch?v=7byWDodfgvE
    # https://youtu.be/7byWDodfgvE
    patterns = [
        r'(?:youtube\.com\/watch\?v=)([\w-]+)',
        r'(?:youtu\.be\/)([\w-]+)'
    ]
    for pattern in patterns:
        match = re.search(pattern, url)
        if match:
            return match.group(1)
    return None

@app.context_processor
def utility_processor():
    return dict(extract_youtube_id=extract_youtube_id)


def allowed_file(filename):
    """Sprawdza czy plik ma dozwolone rozszerzenie"""
    ALLOWED_EXTENSIONS = {'mp4', 'avi', 'mov', 'mkv', 'webm', 'wmv', 'flv', 'MP4', 'AVI', 'MOV', 'MKV'}

    if not filename or '.' not in filename:
        print(f"DEBUG allowed_file: Brak kropki w '{filename}'")
        return False

    extension = filename.rsplit('.', 1)[1].lower()
    result = extension in ALLOWED_EXTENSIONS

    print(f"DEBUG allowed_file: '{filename}' -> rozszerzenie: '{extension}' -> dozwolone: {result}")

    return result


# --- 4. BLOKADA LOGOWANIA ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)

    return decorated_function


def is_admin():
    """Sprawdza czy zalogowany użytkownik jest administratorem"""
    if 'user_id' not in session:
        return False

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT is_admin FROM users WHERE id = %s", (session['user_id'],))
    result = cur.fetchone()
    cur.close()
    conn.close()

    return result and result[0]


def admin_required(f):
    """Dekorator wymagający uprawnień administratora"""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not is_admin():
            flash('Brak uprawnień administratora.', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)

    return decorated_function


# --- 5. TRASY ---

@app.route('/')
@app.route('/dashboard')
@login_required
def dashboard():
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        # Podstawowe statystyki
        cur.execute("SELECT COUNT(*) as count FROM techniques")
        total_techniques = cur.fetchone()['count']

        total_videos = 0
        pending_videos_count = 0  # NOWE
        recent_videos = []
        try:
            cur.execute("SELECT COUNT(*) as count FROM videos")
            total_videos = cur.fetchone()['count']

            # Pobierz liczbę filmów oczekujących na akceptację
            cur.execute("SELECT COUNT(*) as count FROM videos WHERE is_approved = FALSE")
            pending_videos_count = cur.fetchone()['count']

            # Zapisz w sesji dla badge w menu
            session['pending_videos_count'] = pending_videos_count

            # Pobierz 3 ostatnio dodane filmy
            cur.execute("""
                        SELECT v.*,
                               t.name     as technique_name,
                               u.username as uploaded_by_name
                        FROM videos v
                                 LEFT JOIN techniques t ON v.technique_id = t.id
                                 LEFT JOIN users u ON v.uploaded_by = u.id
                        WHERE v.is_approved = TRUE
                        ORDER BY v.uploaded_at DESC LIMIT 3
                        """)
            recent_videos = cur.fetchall()
        except Exception as e:
            print(f"Błąd przy pobieraniu video: {e}")
            pass

        # Kategorie
        categories = []
        try:
            cur.execute("SELECT * FROM categories ORDER BY name")
            categories = cur.fetchall()
        except:
            pass

        total_categories = len(categories)

        # Ostatnie techniki
        recent_techniques = []
        try:
            cur.execute("""
                        SELECT t.*, c.name as category_name
                        FROM techniques t
                                 LEFT JOIN categories c ON t.category_id = c.id
                        ORDER BY t.created_at DESC LIMIT 3
                        """)
            recent_techniques = cur.fetchall()
        except:
            try:
                cur.execute("""
                            SELECT t.id, t.name, t.description, c.name as category_name
                            FROM techniques t
                                     LEFT JOIN categories c ON t.category_id = c.id
                            ORDER BY t.id DESC LIMIT 6
                            """)
                recent_techniques = cur.fetchall()
            except:
                pass

        cur.close()
        conn.close()

        return render_template('dashboard.html',
                               total_techniques=total_techniques,
                               total_videos=total_videos,
                               total_categories=total_categories,
                               pending_videos_count=pending_videos_count,  # NOWE
                               categories=categories,
                               recent_techniques=recent_techniques,
                               recent_videos=recent_videos)

    except Exception as e:
        print(f"Błąd dashboard: {e}")
        return render_template('dashboard.html',
                               total_techniques=0,
                               total_videos=0,
                               total_categories=0,
                               pending_videos_count=0,
                               categories=[],
                               recent_techniques=[],
                               recent_videos=[])
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        u = request.form.get('username')
        p = request.form.get('password')

        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        # Pobierz użytkownika z zahashowanym hasłem
        cur.execute("""
                    SELECT id, username, password, is_admin, is_approved
                    FROM users
                    WHERE username = %s
                    """, (u,))
        user = cur.fetchone()

        cur.close()
        conn.close()

        if user and check_password_hash(user['password'], p):
            # Sprawdź czy konto jest zatwierdzone
            if not user['is_approved']:
                flash('Twoje konto oczekuje na zatwierdzenie przez administratora.', 'warning')
                return render_template('login.html')

            # Zaloguj użytkownika
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['is_admin'] = user['is_admin']

            flash('Zalogowano pomyślnie!', 'success')
            return redirect(url_for('dashboard'))

        flash('Błędne dane logowania', 'error')

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        u = request.form.get('username')
        p = request.form.get('password')

        # Hashowanie hasła przed zapisaniem do bazy
        hashed_password = generate_password_hash(p)

        conn = get_db_connection()
        cur = conn.cursor()
        try:
            # Sprawdź czy użytkownik już istnieje
            cur.execute("SELECT id FROM users WHERE username = %s", (u,))
            if cur.fetchone():
                flash('Użytkownik już istnieje!', 'error')
                return render_template('register.html')

            # Dodaj nowego użytkownika (domyślnie niezatwierdzony, nie admin)
            cur.execute("""
                        INSERT INTO users (username, password, is_admin, is_approved, created_at)
                        VALUES (%s, %s, FALSE, FALSE, NOW())
                        """, (u, hashed_password))

            conn.commit()

            flash('Konto zostało utworzone! Oczekuje na zatwierdzenie przez administratora.', 'info')
            return redirect(url_for('login'))

        except Exception as e:
            conn.rollback()
            print(f"Błąd rejestracji: {e}")
            flash('Wystąpił błąd podczas rejestracji.', 'error')
        finally:
            cur.close()
            conn.close()

    return render_template('register.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/techniques')
@login_required
def techniques():
    # Pobierz parametry z URL
    search_query = request.args.get('search', '').strip()
    category = request.args.get('category', '').strip()
    difficulty = request.args.get('difficulty', '').strip()

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    # Buduj zapytanie dynamicznie
    # Dla zwykłych użytkowników: pokazuj tylko techniki z co najmniej jednym zaakceptowanym filmem
    # Dla adminów: pokazuj wszystkie techniki
    if not session.get('is_admin'):
        # Zwykli użytkownicy - tylko techniki z zaakceptowanymi filmami
        query = """
                SELECT t.*,
                       c.name                                                                                 as category_name,
                       (SELECT COUNT(*) \
                        FROM videos v \
                        WHERE v.technique_id = t.id \
                          AND v.is_approved = TRUE)                                                           as video_count,
                       EXISTS(SELECT 1 \
                              FROM videos v2 \
                              WHERE v2.technique_id = t.id \
                                AND v2.is_approved = TRUE)                                                    as has_approved_videos
                FROM techniques t
                         LEFT JOIN categories c ON t.category_id = c.id
                WHERE EXISTS(SELECT 1 FROM videos v WHERE v.technique_id = t.id AND v.is_approved = TRUE)
                """
    else:
        # Admini - wszystkie techniki
        query = """
                SELECT t.*,
                       c.name                                                                               as category_name,
                       (SELECT COUNT(*) \
                        FROM videos v \
                        WHERE v.technique_id = t.id \
                          AND v.is_approved = TRUE)                                                         as video_count,
                       TRUE                                                                                 as has_approved_videos
                FROM techniques t
                         LEFT JOIN categories c ON t.category_id = c.id
                WHERE 1 = 1
                """

    params = []

    # Filtry
    if search_query:
        query += " AND (LOWER(t.name) LIKE LOWER(%s) OR LOWER(t.description) LIKE LOWER(%s))"
        search_pattern = f"%{search_query}%"
        params.extend([search_pattern, search_pattern])

    if category:
        query += " AND t.category_id = %s"
        params.append(int(category))

    if difficulty:
        query += " AND t.difficulty = %s"
        params.append(difficulty)

    query += " ORDER BY t.created_at DESC, t.id DESC"

    cur.execute(query, params)
    techniques_list = cur.fetchall()

    # Pobierz miniatury filmów i username dla każdej techniki
    for technique in techniques_list:
        # Dla zwykłych użytkowników: tylko zaakceptowane filmy
        # Dla adminów: wszystkie filmy
        if not session.get('is_admin'):
            cur.execute("""
                        SELECT v.*, u.username
                        FROM videos v
                                 LEFT JOIN users u ON v.uploaded_by = u.id
                        WHERE v.technique_id = %s
                          AND v.is_approved = TRUE
                        ORDER BY CASE
                                     WHEN v.video_type = 'training' THEN 1
                                     WHEN v.video_type = 'youtube' THEN 2
                                     ELSE 3
                                     END,
                                 v.uploaded_at DESC LIMIT 1
                        """, (technique['id'],))
        else:
            cur.execute("""
                        SELECT v.*, u.username
                        FROM videos v
                                 LEFT JOIN users u ON v.uploaded_by = u.id
                        WHERE v.technique_id = %s
                        ORDER BY CASE
                                     WHEN v.video_type = 'training' THEN 1
                                     WHEN v.video_type = 'youtube' THEN 2
                                     ELSE 3
                                     END,
                                 v.uploaded_at DESC LIMIT 1
                        """, (technique['id'],))

        result = cur.fetchone()
        if result:
            video_data = {k: v for k, v in result.items() if k != 'username'}
            technique['thumbnail_video'] = video_data
            technique['username'] = result['username']

            if video_data['video_type'] == 'youtube':
                yt_match = None
                if video_data['filename']:
                    patterns = [
                        r'(?:youtube\.com\/watch\?v=|youtu\.be\/|youtube\.com\/embed\/|youtube\.com\/v\/)([\w-]{11})',
                        r'v=([\w-]{11})'
                    ]
                    for pattern in patterns:
                        match = re.search(pattern, video_data['filename'])
                        if match:
                            yt_match = match
                            break

                if yt_match:
                    technique['thumbnail_yt_id'] = yt_match.group(1)
                else:
                    technique['thumbnail_yt_id'] = None
            else:
                technique['thumbnail_yt_id'] = None
        else:
            technique['thumbnail_video'] = None
            technique['username'] = None
            technique['thumbnail_yt_id'] = None

    # Pobierz wszystkie kategorie dla filtrowania
    cur.execute("SELECT * FROM categories ORDER BY name")
    categories = cur.fetchall()

    cur.close()
    conn.close()

    return render_template('techniques.html',
                           techniques=techniques_list,
                           categories=categories,
                           search_query=search_query,
                           selected_category=category,
                           selected_difficulty=difficulty)


@app.route('/trainings')
@login_required
def trainings():
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    cur.execute("""
        SELECT t.*,
               COUNT(r.id) as participants
        FROM trainings t
        LEFT JOIN training_registrations r
               ON t.id = r.training_id
        GROUP BY t.id
        ORDER BY t.training_date, t.training_time
    """)

    trainings = cur.fetchall()

    # 🔽 SPRAWDZENIE CZY UŻYTKOWNIK JEST ZAPISANY
    user_id = session['user_id']

    for t in trainings:
        cur.execute("""
            SELECT 1
            FROM training_registrations
            WHERE training_id = %s AND user_id = %s
        """, (t['id'], user_id))

        t['is_registered'] = cur.fetchone() is not None

    cur.close()
    conn.close()

    return render_template("trainings.html", trainings=trainings)

@app.route('/trainings/add', methods=['GET', 'POST'])
@login_required
@admin_required
def add_training():
    if request.method == 'POST':
        title = request.form.get('title')
        training_date = request.form.get('training_date')
        training_time = request.form.get('training_time')
        coach = request.form.get('coach')
        max_participants = request.form.get('max_participants')

        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute("""
            INSERT INTO trainings
            (title, training_date, training_time, coach, max_participants)
            VALUES (%s, %s, %s, %s, %s)
        """, (title, training_date, training_time, coach, max_participants))

        conn.commit()
        cur.close()
        conn.close()

        flash("Trening dodany!", "success")
        return redirect(url_for('trainings'))

    return render_template("add_training.html")



@app.route('/my-trainings')
@login_required
def my_trainings():
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    user_id = session['user_id']

    cur.execute("""
        SELECT t.*
        FROM trainings t
        JOIN training_registrations r
            ON t.id = r.training_id
        WHERE r.user_id = %s
        ORDER BY t.training_date, t.training_time
    """, (user_id,))

    trainings = cur.fetchall()

    cur.close()
    conn.close()

    return render_template("my_trainings.html", trainings=trainings)


@app.route('/trainings/delete/<int:training_id>')
@login_required
@admin_required
def delete_training(training_id):
    conn = get_db_connection()
    cur = conn.cursor()

    # usuń najpierw zapisy użytkowników
    cur.execute(
        "DELETE FROM training_registrations WHERE training_id = %s",
        (training_id,)
    )

    # usuń trening
    cur.execute(
        "DELETE FROM trainings WHERE id = %s",
        (training_id,)
    )

    conn.commit()
    cur.close()
    conn.close()

    flash("Trening usunięty.", "success")
    return redirect(url_for('trainings'))



@app.route('/api/trainings')
@login_required
def api_trainings():
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    cur.execute("""
        SELECT t.*,
               COUNT(r.id) as participants
        FROM trainings t
        LEFT JOIN training_registrations r
               ON t.id = r.training_id
        GROUP BY t.id
        ORDER BY t.training_date, t.training_time
    """)

    trainings = cur.fetchall()

    # ✅ Konwersja daty i czasu na tekst
    result = []
    for t in trainings:
        t = dict(t)
        t["training_date"] = str(t["training_date"])
        t["training_time"] = str(t["training_time"])
        result.append(t)

    cur.close()
    conn.close()

    return jsonify(result)

@app.route('/api/trainings/register/<int:training_id>', methods=['POST'])
@login_required
def api_register_training(training_id):
    conn = get_db_connection()
    cur = conn.cursor()

    user_id = session['user_id']

    try:
        cur.execute("""
            INSERT INTO training_registrations (training_id, user_id)
            VALUES (%s, %s)
        """, (training_id, user_id))

        conn.commit()

        response = {"status": "ok", "message": "Zapisano na trening"}

    except Exception:
        conn.rollback()
        response = {"status": "error", "message": "Już zapisany"}

    cur.close()
    conn.close()

    return jsonify(response)


@app.route('/api/my-trainings')
@login_required
def api_my_trainings():
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    user_id = session['user_id']

    cur.execute("""
        SELECT t.*,
               COUNT(r2.id) as participants
        FROM trainings t
        JOIN training_registrations r
             ON t.id = r.training_id
        LEFT JOIN training_registrations r2
             ON t.id = r2.training_id
        WHERE r.user_id = %s
        GROUP BY t.id
        ORDER BY t.training_date, t.training_time
    """, (user_id,))

    trainings = cur.fetchall()

    result = []
    for t in trainings:
        t = dict(t)
        t["training_date"] = str(t["training_date"])
        t["training_time"] = str(t["training_time"])
        result.append(t)

    cur.close()
    conn.close()

    return jsonify(result)



@app.route('/trainings/register/<int:training_id>')
@login_required
def register_training(training_id):
    conn = get_db_connection()
    cur = conn.cursor()

    user_id = session['user_id']

    try:
        cur.execute("""
            INSERT INTO training_registrations (training_id, user_id)
            VALUES (%s, %s)
        """, (training_id, user_id))

        conn.commit()
        flash("Zapisano na trening!", "success")

    except Exception:
        conn.rollback()
        flash("Już jesteś zapisany lub brak miejsc.", "warning")

    cur.close()
    conn.close()

    return redirect(url_for('trainings'))


@app.route('/trainings/unregister/<int:training_id>')
@login_required
def unregister_training(training_id):
    conn = get_db_connection()
    cur = conn.cursor()

    user_id = session['user_id']

    cur.execute("""
        DELETE FROM training_registrations
        WHERE training_id = %s AND user_id = %s
    """, (training_id, user_id))

    conn.commit()

    cur.close()
    conn.close()

    flash("Wypisano z treningu.", "info")
    return redirect(url_for('trainings'))





@app.route('/technique/add', methods=['GET', 'POST'])
@login_required
def add_technique():
    if request.method == 'POST':
        name = request.form.get('name')
        category_id = request.form.get('category_id')
        description = request.form.get('description')
        difficulty = request.form.get('difficulty', 'Sredniozaawansowany')  # POPRAWIONE
        position = request.form.get('position', '')
        video_url = request.form.get('video_url', '').strip()

        # Pobierz aktualnego użytkownika
        current_user_id = session.get('user_id')
        is_admin_user = session.get('is_admin', False)

        conn = get_db_connection()
        cur = conn.cursor()

        try:
            # 1. Dodaj technikę
            cur.execute("""
                        INSERT INTO techniques (name, category_id, description, difficulty, position)
                        VALUES (%s, %s, %s, %s, %s) RETURNING id
                        """, (name, category_id, description, difficulty, position))

            technique_id = cur.fetchone()[0]

            # 2. Obsługa pliku wideo
            video_file = request.files.get('video_file')
            video_filename = None
            original_filename = None

            if video_file and video_file.filename:
                # Sprawdź rozszerzenie
                allowed_extensions = {'mp4', 'avi', 'mov', 'mkv', 'webm'}
                file_ext = video_file.filename.rsplit('.', 1)[1].lower() if '.' in video_file.filename else ''

                if file_ext in allowed_extensions:
                    # Zabezpiecz nazwę pliku
                    original_filename = video_file.filename
                    video_filename = f"video_{technique_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{file_ext}"

                    # Ścieżka zapisu
                    upload_folder = 'static/uploads'
                    os.makedirs(upload_folder, exist_ok=True)
                    file_path = os.path.join(upload_folder, video_filename)

                    # Zapis pliku
                    video_file.save(file_path)

                    # DODANO: Status akceptacji (admin = auto-zaakceptowany)
                    is_approved = is_admin_user

                    # Dodaj rekord do tabeli videos
                    cur.execute("""
                                INSERT INTO videos (technique_id, filename, original_filename, video_type, uploaded_by,
                                                    is_approved)
                                VALUES (%s, %s, %s, %s, %s, %s)
                                """, (technique_id, video_filename, original_filename, 'training', current_user_id,
                                      is_approved))

            # 3. Obsługa linku YouTube (jeśli nie ma pliku)
            elif video_url and not video_file:
                # DODANO: Status akceptacji
                is_approved = is_admin_user

                # Jeśli to link YouTube
                if 'youtube.com' in video_url or 'youtu.be' in video_url:
                    cur.execute("""
                                INSERT INTO videos (technique_id, filename, original_filename, video_type, uploaded_by,
                                                    is_approved)
                                VALUES (%s, %s, %s, %s, %s, %s)
                                """, (technique_id, video_url, video_url, 'youtube', current_user_id, is_approved))
                else:
                    # Dla innych linków
                    cur.execute("""
                                INSERT INTO videos (technique_id, filename, original_filename, video_type, uploaded_by,
                                                    is_approved)
                                VALUES (%s, %s, %s, %s, %s, %s)
                                """, (technique_id, video_url, video_url, 'external', current_user_id, is_approved))

            conn.commit()

            if is_admin_user:
                flash('Technika została dodana! Film jest już dostępny.', 'success')
            else:
                if video_file or video_url:
                    flash('Technika została dodana! Film oczekuje na akceptację przez administratora.', 'info')
                else:
                    flash('Technika została dodana!', 'success')

        except Exception as e:
            conn.rollback()
            flash(f'Wystąpił błąd: {str(e)}', 'error')
            return redirect(url_for('add_technique'))

        finally:
            cur.close()
            conn.close()

        return redirect(url_for('technique_detail', technique_id=technique_id))

    # GET - pokaż formularz
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM categories ORDER BY name")
    categories = cur.fetchall()
    cur.close()
    conn.close()

    return render_template('add_technique.html', categories=categories)

# --- DODAJ TE ENDPOINTY DO PANELU ADMINA ---

@app.route('/admin/videos')
@login_required
@admin_required
def admin_videos():
    """Lista filmów oczekujących na akceptację"""
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    # Pobierz filmy oczekujące na akceptację
    cur.execute("""
                SELECT v.*,
                       t.name as technique_name,
                       u.username as uploaded_by_name
                FROM videos v
                         LEFT JOIN techniques t ON v.technique_id = t.id
                         LEFT JOIN users u ON v.uploaded_by = u.id
                WHERE v.is_approved = FALSE
                ORDER BY v.uploaded_at DESC
                """)
    pending_videos = cur.fetchall()

    # Pobierz ostatnio zaakceptowane filmy
    cur.execute("""
                SELECT v.*,
                       t.name as technique_name,
                       u.username as uploaded_by_name
                FROM videos v
                         LEFT JOIN techniques t ON v.technique_id = t.id
                         LEFT JOIN users u ON v.uploaded_by = u.id
                WHERE v.is_approved = TRUE
                ORDER BY v.uploaded_at DESC
                LIMIT 20
                """)
    approved_videos = cur.fetchall()

    cur.close()
    conn.close()

    return render_template('admin_videos.html',
                           pending_videos=pending_videos,
                           approved_videos=approved_videos)


@app.route('/admin/approve_video/<int:video_id>')
@login_required
@admin_required
def approve_video(video_id):
    """Zaakceptuj film"""
    conn = get_db_connection()
    cur = conn.cursor()

    try:
        cur.execute("""
                    UPDATE videos
                    SET is_approved = TRUE,
                        approved_at = NOW()
                    WHERE id = %s
                    """, (video_id,))

        conn.commit()

        if cur.rowcount > 0:
            flash('Film został zaakceptowany.', 'success')
        else:
            flash('Film nie został znaleziony.', 'warning')

    except Exception as e:
        conn.rollback()
        flash(f'Błąd: {str(e)}', 'error')
    finally:
        cur.close()
        conn.close()

    return redirect(url_for('admin_videos'))


@app.route('/admin/reject_video/<int:video_id>')
@login_required
@admin_required
def reject_video(video_id):
    """Odrzuć i usuń film"""
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    try:
        # Najpierw pobierz informacje o filmie aby usunąć plik
        cur.execute("""
                    SELECT filename, video_type
                    FROM videos
                    WHERE id = %s
                    """, (video_id,))

        video = cur.fetchone()

        # Usuń rekord z bazy
        cur.execute("DELETE FROM videos WHERE id = %s", (video_id,))

        # Jeśli to plik lokalny, usuń go też z dysku
        if video and video['video_type'] != 'youtube' and video['filename']:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], video['filename'])
            if os.path.exists(file_path):
                os.remove(file_path)
                print(f"DEBUG: Usunięto plik {file_path}")

        conn.commit()

        if cur.rowcount > 0:
            flash('Film został odrzucony i usunięty.', 'success')
        else:
            flash('Film nie został znaleziony.', 'warning')

    except Exception as e:
        conn.rollback()
        flash(f'Błąd: {str(e)}', 'error')
    finally:
        cur.close()
        conn.close()

    return redirect(url_for('admin_videos'))



# ... istniejący kod ...

@app.route('/technique/<int:technique_id>')
@login_required
def technique_detail(technique_id):
    print(f"\n=== DEBUG: Rozpoczynam technique_detail dla ID {technique_id} ===")

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    # 1. Sprawdź technikę
    cur.execute('''
                SELECT t.*, c.name as category_name
                FROM techniques t
                         LEFT JOIN categories c ON t.category_id = c.id
                WHERE t.id = %s
                ''', (technique_id,))

    technique = cur.fetchone()
    print(f"1. Technika: {technique['name'] if technique else 'NIE ZNALEZIONA'}")

    if not technique:
        flash('Technika nie została znaleziona.', 'error')
        cur.close()
        conn.close()
        return redirect(url_for('techniques'))

    # 2. Sprawdź filmy - TYLKO ZAAKCEPTOWANE
    # Pokaż wszystkie filmy adminowi, tylko zaakceptowane zwykłym użytkownikom
    if session.get('is_admin'):
        cur.execute('''
                    SELECT v.*,
                           u.username as uploaded_by_username
                    FROM videos v
                             LEFT JOIN users u ON v.uploaded_by = u.id
                    WHERE v.technique_id = %s
                    ORDER BY v.is_approved DESC, v.uploaded_at DESC
                    ''', (technique_id,))
    else:
        cur.execute('''
                    SELECT v.*,
                           u.username as uploaded_by_username
                    FROM videos v
                             LEFT JOIN users u ON v.uploaded_by = u.id
                    WHERE v.technique_id = %s AND v.is_approved = TRUE
                    ORDER BY v.uploaded_at DESC
                    ''', (technique_id,))

    videos = cur.fetchall()
    print(f"2. Liczba filmów w bazie: {len(videos)}")

    # Debug: sprawdź czy mamy username
    for i, video in enumerate(videos):
        print(f"   Film #{i + 1}: uploaded_by={video.get('uploaded_by')}, username={video.get('uploaded_by_username')}, approved={video.get('is_approved')}")

    # 3. Sprawdź każdy film szczegółowo
    import os
    upload_folder = app.config.get('UPLOAD_FOLDER', 'static/uploads')

    for i, video in enumerate(videos):
        print(f"\n   Film #{i + 1}:")
        print(f"   - ID: {video['id']}")
        print(f"   - Filename: {video['filename']}")
        print(f"   - Approved: {video['is_approved']}")
        print(f"   - uploaded_by (ID): {video['uploaded_by']}")
        print(f"   - uploaded_by_username: {video.get('uploaded_by_username', 'BRAK')}")

        # Sprawdź fizyczny plik (tylko dla plików lokalnych)
        if video['video_type'] != 'youtube':
            filepath = os.path.join(upload_folder, video['filename'])
            file_exists = os.path.exists(filepath)
            file_size = os.path.getsize(filepath) if file_exists else 0

            print(f"   - Plik istnieje: {file_exists}")
            print(f"   - Ścieżka: {filepath}")
            print(f"   - Rozmiar: {file_size} bajtów")

            # Sprawdź URL
            video_url = f"/static/uploads/{video['filename']}"
            print(f"   - URL: {video_url}")

    # Formatuj daty dla techniki
    if technique.get('created_at'):
        technique['created_at_formatted'] = technique['created_at'].strftime('%Y-%m-%d')
    else:
        technique['created_at_formatted'] = 'Brak daty'

    # Formatuj daty dla filmów i upewnij się, że username jest dostępny
    for video in videos:
        if video.get('uploaded_at'):
            video['uploaded_at_formatted'] = video['uploaded_at'].strftime('%Y-%m-%d')
        else:
            video['uploaded_at_formatted'] = 'Brak daty'

        # Ustaw username dla łatwiejszego dostępu w szablonie
        if 'uploaded_by_username' in video:
            video['username'] = video['uploaded_by_username']
        else:
            # Jeśli JOIN nie zwrócił username, pobierz go osobno
            cur.execute('SELECT username FROM users WHERE id = %s', (video['uploaded_by'],))
            user_result = cur.fetchone()
            video['username'] = user_result['username'] if user_result else 'Nieznany'

    cur.close()
    conn.close()

    print(f"\n=== DEBUG: Przekazuję do szablonu ===")
    print(f"Technika: {technique['name']}")
    for i, video in enumerate(videos):
        print(f"Film {i + 1}: username={video.get('username')}, approved={video.get('is_approved')}")

    return render_template('technique_detail.html',
                           technique=technique,
                           videos=videos)


@app.route('/technique/<int:technique_id>/upload-video', methods=['POST'])
@login_required
def upload_video(technique_id):
    print(f"\n=== DEBUG UPLOAD: Rozpoczynam ===")
    print(f"Technique ID: {technique_id}")
    print(f"Metoda: {request.method}")
    print(f"Form data: {request.form}")
    print(f"Files: {request.files}")

    if 'video' not in request.files:
        print("DEBUG: 'video' nie ma w request.files")
        flash('Nie wybrano pliku.', 'error')
        return redirect(url_for('technique_detail', technique_id=technique_id))

    file = request.files['video']
    print(f"DEBUG: Plik otrzymany: {file.filename}")
    print(f"DEBUG: Content type: {file.content_type}")

    video_type = request.form.get('video_type', 'training')
    print(f"DEBUG: Typ filmu z formularza: {video_type}")

    if file.filename == '':
        print("DEBUG: Pusty filename")
        flash('Nie wybrano pliku.', 'error')
        return redirect(url_for('technique_detail', technique_id=technique_id))

    # Sprawdź allowed_file
    print(f"DEBUG: Sprawdzam allowed_file dla: {file.filename}")
    is_allowed = allowed_file(file.filename)
    print(f"DEBUG: allowed_file zwrócił: {is_allowed}")

    if file and is_allowed:
        filename = secure_filename(file.filename)
        print(f"DEBUG: Po secure_filename: {filename}")

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{timestamp}_{filename}"
        print(f"DEBUG: Ostateczna nazwa pliku: {filename}")

        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        print(f"DEBUG: Ścieżka zapisu: {filepath}")

        # Upewnij się że folder istnieje
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

        # Spróbuj zapisać plik
        try:
            file.save(filepath)
            file_size = os.path.getsize(filepath) if os.path.exists(filepath) else 0
            print(f"DEBUG: Plik zapisany, rozmiar: {file_size} bajtów")
        except Exception as e:
            print(f"DEBUG: Błąd zapisu pliku: {e}")
            flash(f'Błąd zapisu pliku: {e}', 'error')
            return redirect(url_for('technique_detail', technique_id=technique_id))

        # Połączenie z bazą
        try:
            conn = get_db_connection()
            cur = conn.cursor()

            user_id = session.get('user_id', 1)

            # USTAW STATUS ZAAKCEPTOWANIA
            # Admin - automatycznie zaakceptowane
            # Zwykły użytkownik - wymaga akceptacji
            is_admin_user = session.get('is_admin', False)
            is_approved = is_admin_user  # True dla admina, False dla zwykłych użytkowników

            print(f"DEBUG: Wstawiam do bazy:")
            print(f"  technique_id: {technique_id}")
            print(f"  filename: {filename}")
            print(f"  original_filename: {file.filename}")
            print(f"  video_type: {video_type}")
            print(f"  uploaded_by: {user_id}")
            print(f"  is_approved: {is_approved} (admin: {is_admin_user})")

            cur.execute('''
                        INSERT INTO videos (technique_id, filename, original_filename, video_type, uploaded_by,
                                            is_approved)
                        VALUES (%s, %s, %s, %s, %s, %s) RETURNING id
                        ''', (technique_id, filename, file.filename, video_type, user_id, is_approved))

            new_id = cur.fetchone()[0]
            print(f"DEBUG: Wstawiono rekord z ID: {new_id}")

            conn.commit()
            print(f"DEBUG: Commit wykonany")

            cur.execute('SELECT COUNT(*) as count FROM videos WHERE id = %s', (new_id,))
            count = cur.fetchone()[0]
            print(f"DEBUG: Potwierdzenie - rekordów z ID {new_id}: {count}")

            cur.close()
            conn.close()

            if is_approved:
                flash('Film został przesłany pomyślnie i jest już dostępny!', 'success')
            else:
                flash('Film został przesłany pomyślnie! Oczekuje na akceptację przez administratora.', 'info')

            print(f"=== DEBUG UPLOAD: Sukces ===")

        except Exception as e:
            print(f"DEBUG: Błąd bazy danych: {e}")
            import traceback
            traceback.print_exc()

            if os.path.exists(filepath):
                os.remove(filepath)
                print(f"DEBUG: Usunięto plik {filepath} po błędzie bazy")

            flash(f'Błąd bazy danych: {str(e)}', 'error')

    else:
        print(f"DEBUG: Plik nie przeszedł walidacji")
        flash('Niedozwolony typ pliku. Dozwolone: mp4, avi, mov, mkv, webm', 'error')

    return redirect(url_for('technique_detail', technique_id=technique_id))
# --- PANEL ADMINISTRATORA ---

@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    """Lista użytkowników oczekujących na zatwierdzenie"""
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    # Pobierz użytkowników oczekujących na zatwierdzenie
    cur.execute("""
                SELECT id, username, created_at
                FROM users
                WHERE is_approved = FALSE
                ORDER BY created_at DESC
                """)
    pending_users = cur.fetchall()

    # Pobierz wszystkich użytkowników
    cur.execute("""
                SELECT u.id,
                       u.username,
                       u.is_admin,
                       u.is_approved,
                       u.created_at,
                       u.approved_at,
                       a.username as approved_by_name
                FROM users u
                         LEFT JOIN users a ON u.approved_by = a.id
                ORDER BY u.created_at DESC
                """)
    all_users = cur.fetchall()

    cur.close()
    conn.close()

    return render_template('admin_users.html',
                           pending_users=pending_users,
                           all_users=all_users)


@app.route('/admin/approve_user/<int:user_id>')
@login_required
@admin_required
def approve_user(user_id):
    """Zatwierdź użytkownika"""
    conn = get_db_connection()
    cur = conn.cursor()

    try:
        cur.execute("""
                    UPDATE users
                    SET is_approved = TRUE,
                        approved_at = NOW(),
                        approved_by = %s
                    WHERE id = %s
                      AND is_approved = FALSE
                    """, (session['user_id'], user_id))

        conn.commit()

        if cur.rowcount > 0:
            flash('Użytkownik został zatwierdzony.', 'success')
        else:
            flash('Użytkownik nie znaleziony lub już zatwierdzony.', 'warning')

    except Exception as e:
        conn.rollback()
        flash(f'Błąd: {str(e)}', 'error')
    finally:
        cur.close()
        conn.close()

    return redirect(url_for('admin_users'))


@app.route('/admin/reject_user/<int:user_id>')
@login_required
@admin_required
def reject_user(user_id):
    """Odrzuć użytkownika (usuń konto)"""
    conn = get_db_connection()
    cur = conn.cursor()

    try:
        # Najpierw sprawdź czy to nie admin
        cur.execute("SELECT is_admin FROM users WHERE id = %s", (user_id,))
        user = cur.fetchone()

        if user and user[0]:
            flash('Nie można usunąć konta administratora.', 'error')
            return redirect(url_for('admin_users'))

        # Usuń użytkownika
        cur.execute("DELETE FROM users WHERE id = %s AND is_approved = FALSE", (user_id,))

        conn.commit()

        if cur.rowcount > 0:
            flash('Konto użytkownika zostało usunięte.', 'success')
        else:
            flash('Użytkownik nie znaleziony lub już zatwierdzony.', 'warning')

    except Exception as e:
        conn.rollback()
        flash(f'Błąd: {str(e)}', 'error')
    finally:
        cur.close()
        conn.close()

    return redirect(url_for('admin_users'))


@app.route('/admin/make_admin/<int:user_id>')
@login_required
@admin_required
def make_admin(user_id):
    """Ustaw użytkownika jako administratora"""
    conn = get_db_connection()
    cur = conn.cursor()

    try:
        # Sprawdź czy użytkownik istnieje i jest zatwierdzony
        cur.execute("""
                    UPDATE users
                    SET is_admin = TRUE
                    WHERE id = %s
                      AND is_approved = TRUE
                    """, (user_id,))

        conn.commit()

        if cur.rowcount > 0:
            flash('Użytkownik został ustawiony jako administrator.', 'success')
        else:
            flash('Użytkownik nie znaleziony lub niezatwierdzony.', 'warning')

    except Exception as e:
        conn.rollback()
        flash(f'Błąd: {str(e)}', 'error')
    finally:
        cur.close()
        conn.close()

    return redirect(url_for('admin_users'))


@app.route('/admin/remove_admin/<int:user_id>')
@login_required
@admin_required
def remove_admin(user_id):
    """Usuń uprawnienia administratora"""
    conn = get_db_connection()
    cur = conn.cursor()

    try:
        # Nie można usunąć uprawnień samemu sobie
        if user_id == session['user_id']:
            flash('Nie możesz usunąć swoich własnych uprawnień administratora.', 'error')
            return redirect(url_for('admin_users'))

        cur.execute("""
                    UPDATE users
                    SET is_admin = FALSE
                    WHERE id = %s
                    """, (user_id,))

        conn.commit()

        if cur.rowcount > 0:
            flash('Uprawnienia administratora zostały usunięte.', 'success')
        else:
            flash('Użytkownik nie znaleziony.', 'warning')

    except Exception as e:
        conn.rollback()
        flash(f'Błąd: {str(e)}', 'error')
    finally:
        cur.close()
        conn.close()

    return redirect(url_for('admin_users'))


if __name__ == '__main__':
    app.run(debug=True)