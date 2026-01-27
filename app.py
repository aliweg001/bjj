import os
import psycopg2
import psycopg2.extras
from flask import Flask, render_template, request, redirect, url_for, session, flash
from functools import wraps
from werkzeug.utils import secure_filename
# Na początku pliku, z innymi importami
from datetime import datetime  # dla datetime.now()
from werkzeug.utils import secure_filename  # dla secure_filename()
import os  # dla os.path.join() (jeśli jeszcze nie masz)
app = Flask(__name__)
app.secret_key = 'bjj_klucz_ostateczny'

# --- 1. OMIJANIE BŁĘDU "ł" W ŚCIEŻCE WINDOWS ---
# To jest najważniejsza część. Mówimy bibliotece: "Nie szukaj plików w folderze użytkownika!"
os.environ["PGPASSFILE"] = "NUL"  # Windowsowy "śmietnik", żeby nie szukał w folderze z 'ł'
os.environ["PGSSLMODE"] = "disable"  # Wyłączamy szukanie certyfikatów SSL

# --- 2. KONFIGURACJA ŚCIEŻEK ---
app.config['UPLOAD_FOLDER'] = 'static/uploads'
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])


# --- 3. POŁĄCZENIE PRZEZ URI (Jeden string) ---
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


# Funkcja do wyodrębnienia ID z linku YouTube
import re


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


# Dodaj funkcję do kontekstu szablonów
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


# --- 5. TRASY ---

@app.route('/')
@login_required
def index():
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""
                SELECT t.*, c.name as category_name
                FROM techniques t
                         LEFT JOIN categories c ON t.category_id = c.id
                ORDER BY t.id DESC
                """)
    techniques = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('techniques.html', techniques=techniques)


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
        recent_videos = []
        try:
            cur.execute("SELECT COUNT(*) as count FROM videos")
            total_videos = cur.fetchone()['count']

            # Pobierz 3 ostatnio dodane filmy
            cur.execute("""
                        SELECT v.*,
                               t.name     as technique_name,
                               u.username as uploaded_by_name
                        FROM videos v
                                 LEFT JOIN techniques t ON v.technique_id = t.id
                                 LEFT JOIN users u ON v.uploaded_by = u.id
                        ORDER BY v.uploaded_at DESC LIMIT 3
                        """)
            recent_videos = cur.fetchall()
        except Exception as e:
            print(f"Błąd przy pobieraniu video: {e}")
            pass  # Tabela videos może nie istnieć

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
            # Spróbuj po created_at
            cur.execute("""
                        SELECT t.*, c.name as category_name
                        FROM techniques t
                                 LEFT JOIN categories c ON t.category_id = c.id
                        ORDER BY t.created_at DESC LIMIT 3
                        """)
            recent_techniques = cur.fetchall()
        except:
            # Jeśli nie działa, spróbuj po id
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
                               categories=categories,
                               recent_techniques=recent_techniques,
                               recent_videos=recent_videos)

    except Exception as e:
        print(f"Błąd dashboard: {e}")
        return render_template('dashboard.html',
                               total_techniques=0,
                               total_videos=0,
                               total_categories=0,
                               categories=[],
                               recent_techniques=[],
                               recent_videos=[])
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        u = request.form.get('username')
        p = request.form.get('password')

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT id, username FROM users WHERE username = %s AND password = %s", (u, p))
        user = cur.fetchone()

        cur.close()
        conn.close()

        if user:
            session['user_id'] = user[0]
            session['username'] = user[1]
            return redirect(url_for('dashboard'))
        flash('Bledne dane logowania')
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        u = request.form.get('username')
        p = request.form.get('password')
        conn = get_db_connection()
        cur = conn.cursor()
        try:
            cur.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (u, p))
            conn.commit()
            flash('Konto utworzone! Zaloguj się.')
            return redirect(url_for('login'))
        except:
            flash('Użytkownik już istnieje!')
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
    # Pobierz parametr category z URL (jeśli istnieje)
    category_id = request.args.get('category', type=int)

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    # Jeśli podano kategorię, filtruj
    if category_id:
        cur.execute("""
                    SELECT t.*, c.name as category_name
                    FROM techniques t
                             LEFT JOIN categories c ON t.category_id = c.id
                    WHERE t.category_id = %s
                    ORDER BY t.id DESC
                    """, (category_id,))
    else:
        # Wszystkie techniki
        cur.execute("""
                    SELECT t.*, c.name as category_name
                    FROM techniques t
                             LEFT JOIN categories c ON t.category_id = c.id
                    ORDER BY t.id DESC
                    """)

    techniques_list = cur.fetchall()

    # Pobierz wszystkie kategorie dla filtrowania
    cur.execute("SELECT * FROM categories ORDER BY name")
    categories = cur.fetchall()

    cur.close()
    conn.close()

    return render_template('techniques.html',
                           techniques=techniques_list,
                           categories=categories,
                           selected_category=category_id)


@app.route('/technique/add', methods=['GET', 'POST'])
@login_required
def add_technique():
    if request.method == 'POST':
        name = request.form.get('name')
        category_id = request.form.get('category_id')
        description = request.form.get('description')
        difficulty = request.form.get('difficulty', 'intermediate')
        position = request.form.get('position', '')
        video_url = request.form.get('video_url', '').strip()

        # Pobierz aktualnego użytkownika
        current_user_id = session.get('user_id')

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

                    # Zapisz plik (przykładowa ścieżka - dostosuj do swojej struktury)
                    upload_folder = 'static/uploads/videos'
                    os.makedirs(upload_folder, exist_ok=True)
                    file_path = os.path.join(upload_folder, video_filename)
                    video_file.save(file_path)

                    # Dodaj rekord do tabeli videos
                    cur.execute("""
                                INSERT INTO videos (technique_id, filename, original_filename, video_type, uploaded_by,
                                                    uploaded_at)
                                VALUES (%s, %s, %s, %s, %s, NOW())
                                """, (technique_id, video_filename, original_filename, 'training', current_user_id))

            # 3. Obsługa linku YouTube (jeśli nie ma pliku)
            elif video_url and not video_file:
                # Jeśli to link YouTube
                if 'youtube.com' in video_url or 'youtu.be' in video_url:
                    cur.execute("""
                                INSERT INTO videos (technique_id, filename, original_filename, video_type, uploaded_by,
                                                    uploaded_at)
                                VALUES (%s, %s, %s, %s, %s, NOW())
                                """, (technique_id, video_url, video_url, 'youtube', current_user_id))
                else:
                    # Dla innych linków
                    cur.execute("""
                                INSERT INTO videos (technique_id, filename, original_filename, video_type, uploaded_by,
                                                    uploaded_at)
                                VALUES (%s, %s, %s, %s, %s, NOW())
                                """, (technique_id, video_url, video_url, 'external', current_user_id))

            conn.commit()
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

    # 2. Sprawdź filmy
    cur.execute('''
                SELECT v.*
                FROM videos v
                WHERE v.technique_id = %s
                ORDER BY v.uploaded_at DESC
                ''', (technique_id,))

    videos = cur.fetchall()
    print(f"2. Liczba filmów w bazie: {len(videos)}")

    # 3. Sprawdź każdy film szczegółowo
    import os
    upload_folder = app.config.get('UPLOAD_FOLDER', 'static/uploads')

    for i, video in enumerate(videos):
        print(f"\n   Film #{i + 1}:")
        print(f"   - ID: {video['id']}")
        print(f"   - Filename: {video['filename']}")
        print(f"   - Original: {video['original_filename']}")

        # Sprawdź fizyczny plik
        filepath = os.path.join(upload_folder, video['filename'])
        file_exists = os.path.exists(filepath)
        file_size = os.path.getsize(filepath) if file_exists else 0

        print(f"   - Plik istnieje: {file_exists}")
        print(f"   - Ścieżka: {filepath}")
        print(f"   - Rozmiar: {file_size} bajtów")

        # Sprawdź URL
        video_url = f"/static/uploads/{video['filename']}"
        print(f"   - URL: {video_url}")

    # Formatuj daty
    if technique.get('created_at'):
        technique['created_at_formatted'] = technique['created_at'].strftime('%Y-%m-%d')
    else:
        technique['created_at_formatted'] = 'Brak daty'

    for video in videos:
        if video.get('uploaded_at'):
            video['uploaded_at_formatted'] = video['uploaded_at'].strftime('%Y-%m-%d')
        else:
            video['uploaded_at_formatted'] = 'Brak daty'

    cur.close()
    conn.close()

    print(f"=== DEBUG: Koniec ===")

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

            # SPRAWDŹ: czy masz kolumnę uploaded_by?
            user_id = session.get('user_id', 1)  # tymczasowo 1 jeśli brak

            print(f"DEBUG: Wstawiam do bazy:")
            print(f"  technique_id: {technique_id}")
            print(f"  filename: {filename}")
            print(f"  original_filename: {file.filename}")
            print(f"  video_type: {video_type}")
            print(f"  uploaded_by: {user_id}")

            # Wersja 1: Z uploaded_by
            cur.execute('''
                        INSERT INTO videos (technique_id, filename, original_filename, video_type, uploaded_by)
                        VALUES (%s, %s, %s, %s, %s) RETURNING id
                        ''', (technique_id, filename, file.filename, video_type, user_id))

            # Wersja 2: BEZ uploaded_by (jeśli nie masz kolumny)
            # cur.execute('''
            #     INSERT INTO videos (technique_id, filename, original_filename, video_type)
            #     VALUES (%s, %s, %s, %s)
            #     RETURNING id
            # ''', (technique_id, filename, file.filename, video_type))

            # Pobierz ID nowego rekordu
            new_id = cur.fetchone()[0]
            print(f"DEBUG: Wstawiono rekord z ID: {new_id}")

            conn.commit()
            print(f"DEBUG: Commit wykonany")

            # Sprawdź czy rekord został dodany
            cur.execute('SELECT COUNT(*) as count FROM videos WHERE id = %s', (new_id,))
            count = cur.fetchone()[0]
            print(f"DEBUG: Potwierdzenie - rekordów z ID {new_id}: {count}")

            cur.close()
            conn.close()

            flash('Film został przesłany pomyślnie!', 'success')
            print(f"=== DEBUG UPLOAD: Sukces ===")

        except Exception as e:
            print(f"DEBUG: Błąd bazy danych: {e}")
            import traceback
            traceback.print_exc()

            # Usuń plik jeśli błąd bazy
            if os.path.exists(filepath):
                os.remove(filepath)
                print(f"DEBUG: Usunięto plik {filepath} po błędzie bazy")

            flash(f'Błąd bazy danych: {str(e)}', 'error')

    else:
        print(f"DEBUG: Plik nie przeszedł walidacji")
        flash('Niedozwolony typ pliku. Dozwolone: mp4, avi, mov, mkv, webm', 'error')

    return redirect(url_for('technique_detail', technique_id=technique_id))

if __name__ == '__main__':
    app.run(debug=True)