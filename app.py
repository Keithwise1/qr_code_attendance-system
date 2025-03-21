from flask import Flask, render_template, request, redirect, url_for, jsonify, session, flash
import sqlite3
import os
import qrcode
import datetime
import cv2
import uuid 
from cv2 import QRCodeDetector
from werkzeug.security import generate_password_hash, check_password_hash
from flask import send_file

app = Flask(__name__, template_folder="templates/templates")
app.secret_key = 'your_secret_key'
app.config['DATABASE'] = 'attendance.db'
qr_code_folder = "static/qr_codes"
os.makedirs(qr_code_folder, exist_ok=True)

def get_db_connection():
    try:
        conn = sqlite3.connect(app.config['DATABASE'])
        conn.row_factory = sqlite3.Row
        print("Database connection successful")
        return conn
    except sqlite3.Error as e:
        print(f"Database connection error: {e}")
        return None


def init_db():
    try:
        with app.app_context():
            db = get_db_connection()
            db.executescript('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    role TEXT NOT NULL CHECK(role IN ('admin', 'lecturer', 'student'))
                );
                CREATE TABLE IF NOT EXISTS sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    lecturer_id INTEGER NOT NULL,
                    session_code TEXT UNIQUE NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (lecturer_id) REFERENCES users(id) ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS attendance (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    student_id INTEGER NOT NULL,
                    session_id INTEGER NOT NULL,
                    timestamp TEXT NOT NULL,
                    status TEXT NOT NULL,
                    FOREIGN KEY(student_id) REFERENCES users(id) ON DELETE CASCADE,
                    FOREIGN KEY(session_id) REFERENCES sessions(id) ON DELETE CASCADE
                );
            ''')
            db.commit()
            print("Database initialized successfully")
    except sqlite3.Error as e:
        print(f"Database initialization error: {e}")
@app.route('/download_qr/<filename>')
def download_qr(filename):
    qr_code_folder = os.path.join(app.static_folder, "qr_codes")
    filepath = os.path.join(qr_code_folder, filename)
    if os.path.exists(filepath):
        return send_file(filepath, as_attachment=True)
    flash("QR Code not found!", "danger")
    return redirect(url_for('admin_dashboard'))


@app.route('/')
def index():
    return render_template('index.html')
@app.route('/about')
def about():
    return render_template('about.html')
@app.route('/help')
def help():
    return render_template('help.html')
@app.route('/manage_timetable')
def manage_timetable():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM timetable")
    sessions = cur.fetchall()
    conn.close()
    return render_template('manage_timetable.html', sessions=sessions)


@app.route('/add_timetable_entry', methods=['POST'])
def add_timetable_entry():
    course_name = request.form['course_name']
    lecturer_id = request.form['lecturer_id']
    session_time = request.form['session_time']
    session_date = request.form['session_date']

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("INSERT INTO timetable (course_name, lecturer_id, session_time, session_date) VALUES (?, ?, ?, ?)",
                (course_name, lecturer_id, session_time, session_date))
    conn.commit()
    conn.close()
    
    return redirect(url_for('manage_timetable'))


@app.route('/delete_timetable_entry/<int:session_id>', methods=['POST'])
def delete_timetable_entry(session_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM timetable WHERE id=?", (session_id,))
    conn.commit()
    conn.close()

    return redirect(url_for('manage_timetable'))


@app.route('/admin_dashboard')
def admin_dashboard():
    return render_template('admin_dashboard.html')
@app.route('/view_attendance')
def view_attendance():
    if 'user_id' not in session or 'role' not in session:
        return redirect(url_for('login'))

    role = session['role']
    
    conn = sqlite3.connect('attendance.db')
    cur = conn.cursor()

    if role == 'admin':
        
        cur.execute("""
            SELECT attendance.id, attendance.student_id, attendance.timestamp, attendance.status, 
                   timetable.course_name, timetable.lecturer_id
            FROM attendance
            LEFT JOIN timetable ON attendance.session_id = timetable.session_id
        """)
    elif role == 'lecturer':
        
        lecturer_id = session['user_id']
        cur.execute("""
            SELECT attendance.id, attendance.student_id, attendance.timestamp, attendance.status, 
                   timetable.course_name
            FROM attendance
            LEFT JOIN timetable ON attendance.session_id = timetable.session_id
            WHERE timetable.lecturer_id = ?
        """, (lecturer_id,))
    else:
        
        flash("Access Denied")
        return redirect(url_for('dashboard'))  

    attendance_records = cur.fetchall()
    conn.close()

    return render_template('view_attendance.html', attendance=attendance_records, role=role)


@app.route('/lecturer_dashboard')
def lecturer_dashboard():
    return render_template('lecturer_dashboard.html')
@app.route('/student_dashboard')
def student_dashboard():
    return render_template('student_dashboard.html')
@app.route('/delete_attendance/<int:record_id>', methods=['POST'])
def delete_attendance(record_id):
    conn = get_db_connection()
    conn.execute('DELETE FROM attendance WHERE id = ?', (record_id,))
    conn.commit()
    conn.close()
    
    flash('Attendance record deleted!', 'success')
    return redirect(url_for('view_attendance'))




@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()

        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['role'] = user['role']
            flash('Login successful!', 'success')

            if user['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif user['role'] == 'lecturer':
                return redirect(url_for('lecturer_dashboard'))
            else:
                return redirect(url_for('student_dashboard'))
        else:
            flash('Invalid username or password', 'danger')

    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']

        hashed_password = generate_password_hash(password)
        conn = get_db_connection()
        
        try:
            conn.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', 
                         (username, hashed_password, role))
            conn.commit()
            flash('Account created successfully! Please login.', 'success')
        except sqlite3.IntegrityError:
            flash('Username already taken. Choose a different one.', 'danger')

        conn.close()
        return redirect(url_for('login'))

    return render_template('signup.html')
@app.route('/generate_sessions', methods=['GET', 'POST'])
def generate_sessions():
    if request.method == 'POST':
        lecturer_id = request.form.get('lecturer_id')
        session_code = f"SESSION-{uuid.uuid4().hex[:6].upper()}"
        created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        conn = sqlite3.connect('attendance.db')
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO sessions (lecturer_id, session_code, created_at) VALUES (?, ?, ?)",
            (lecturer_id, session_code, created_at)
        )
        conn.commit()
        conn.close()

        flash("Session generated successfully!", "success")

    conn = sqlite3.connect('attendance.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM sessions")
    sessions = cursor.fetchall()
    conn.close()

    return render_template('manage_timetable.html', sessions=sessions)


@app.route('/admin/manage_users')
def manage_users():
    if 'user_id' not in session or session['role'] != 'admin':
        flash('Unauthorized access!', 'danger')
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    users = conn.execute('SELECT id, username, role FROM users').fetchall()
    conn.close()
    
    return render_template('manage_users.html', users=users)

@app.route('/add_user', methods=['POST'])
def add_user():
    if 'user_id' not in session or session['role'] != 'admin':
        flash('Unauthorized access!', 'danger')
        return redirect(url_for('login'))

    username = request.form.get('username')
    password = request.form.get('password')
    role = request.form.get('role')

    if not username or not password or not role:
        flash('All fields are required!', 'danger')
        return redirect(url_for('manage_users'))

    hashed_password = generate_password_hash(password)
    
    conn = get_db_connection()
    try:
        conn.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
                     (username, hashed_password, role))
        conn.commit()
        flash('User added successfully!', 'success')
    except sqlite3.IntegrityError:
        flash('Username already exists. Please choose another.', 'danger')
    finally:
        conn.close()

    return redirect(url_for('manage_users'))



@app.route('/generate_qr_lecturer', methods=['GET','POST'])
def generate_qr_lecturer():
    """Lecturer generates a QR code for the current session"""
    if 'user_id' not in session or session['role'] != 'lecturer':
        flash('Unauthorized access!', 'danger')
        return redirect(url_for('login'))

    lecturer_id = session['user_id']
    session_code = f"{lecturer_id}_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}"  # Unique session code
    created_at = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = get_db_connection()
    conn.execute("INSERT INTO sessions (lecturer_id, session_code, created_at) VALUES (?, ?, ?)",
                 (lecturer_id, session_code, created_at))
    conn.commit()
    conn.close()

    img_path = os.path.join(qr_code_folder, f"session_{session_code}.png")

    qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=10, border=4)
    qr.add_data(session_code)  
    qr.make(fit=True)
    img = qr.make_image(fill='black', back_color='white')
    img.save(img_path)

    flash("Session QR Code generated successfully!", "success")
    return render_template('lecturer_dashboard.html', qr_image=f"qr_codes/session_{session_code}.png", session_code=session_code)
    

@app.route('/scan_qr')
def scan_qr():
    """Student scans a lecturer's session QR code to mark attendance"""
    if 'user_id' not in session or session['role'] != 'student':
        flash('Unauthorized access!', 'danger')
        return redirect(url_for('login'))

    cap = cv2.VideoCapture(0)
    qr_decoder = QRCodeDetector()

    while True:
        success, frame = cap.read()
        if not success:
            break

        decoded_text, points, _ = qr_decoder.detectAndDecode(frame)
        if decoded_text:
            session_id = decoded_text.strip()  # Ensure it's just the session ID

            mark_attendance(session['user_id'], session_id)
            flash("Attendance marked successfully!", "success")
            break

    cap.release()
    cv2.destroyAllWindows()
    return redirect(url_for('student_dashboard'))


def mark_attendance(student_id, session_id):
    """Records the attendance of a student for a given session"""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = get_db_connection()
    session_exists = conn.execute("SELECT id FROM sessions WHERE session_code = ?", (session_id,)).fetchone()

    if session_exists:
        conn.execute('''
            INSERT INTO attendance (student_id, session_id, timestamp, status)
            VALUES (?, ?, ?, ?)
        ''', (student_id, session_id, timestamp, 'Present'))
        conn.commit()
    else:
        flash("Invalid session QR code!", "danger")

    conn.close()
    
@app.route('/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if 'user_id' not in session or session['role'] != 'admin':
        flash('Unauthorized access!', 'danger')
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()

    flash('User deleted successfully!', 'success')
    return redirect(url_for('manage_users'))


@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully.', 'info')
    return redirect(url_for('index'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
