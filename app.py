from flask import Flask, render_template, request, redirect, url_for, jsonify, session, flash,Response
import sqlite3
import os
import qrcode
import datetime
import cv2
import time 
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
@app.route('/manage_timetable', methods=['GET', 'POST'])
def manage_timetable():
    conn = get_db_connection()
    cursor = conn.cursor()

    if request.method == 'POST':
        course_name = request.form.get('course_name')
        course_code = request.form.get('course_code')
        lecturer_id = request.form.get('lecturer_id')
        day = request.form.get('day')
        start_time = request.form.get('start_time')
        end_time = request.form.get('end_time')
        room = request.form.get('room')

        cursor.execute(
            "INSERT INTO timetable (course_name, course_code, lecturer_id, day, start_time, end_time, room) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (course_name, course_code, lecturer_id, day, start_time, end_time, room),
        )
        conn.commit()
        flash("Timetable session added successfully!", "success")

    
    cursor.execute("SELECT id, course_name, course_code, lecturer_id, day, start_time, end_time, room FROM timetable ORDER BY day, start_time")
    timetable = cursor.fetchall() 
    conn.close()

    return render_template('manage_timetable.html', timetable=timetable)





@app.route('/add_timetable_entry', methods=['POST'])
def add_timetable_entry():
    course_code = request.form['course_code']
    course_name = request.form['course_name']
    lecturer_id = request.form['lecturer_id']
    day = request.form['day'] 
    start_time = request.form['start_time']  
    end_time = request.form['end_time'] 
    room = request.form['room']  
    
    conn = get_db_connection()
    cur = conn.cursor()
    
    try:
        cur.execute("""
            INSERT INTO timetable (course_code, course_name, lecturer_id, day, start_time, end_time, room)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (course_code, course_name, lecturer_id, day, start_time, end_time, room))
        
        conn.commit()
        print("Timetable entry added successfully")
    
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    
    finally:
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
    user_id = session['user_id']
    
    conn = get_db_connection()
    cur = conn.cursor()

    if role == 'admin':
        cur.execute("""
            SELECT a.id, s.name AS student_name, a.timestamp, 
                   CASE WHEN a.status IN ('Late', 'Early') THEN 'Absent' ELSE a.status END AS status,
                   t.course_name, l.name AS lecturer_name
            FROM attendance a
            LEFT JOIN sessions sess ON a.session_id = sess.id
            LEFT JOIN students s ON a.student_id = s.id
            LEFT JOIN lecturers l ON sess.lecturer_id = l.id
            LEFT JOIN timetable t ON sess.course_id = t.id
        """)

    elif role == 'lecturer':
        cur.execute("""
            SELECT a.id, s.name AS student_name, a.timestamp, 
                   CASE WHEN a.status IN ('Late', 'Early') THEN 'Absent' ELSE a.status END AS status,
                   t.course_name
            FROM attendance a
            LEFT JOIN sessions sess ON a.session_id = sess.id
            LEFT JOIN students s ON a.student_id = s.id
            LEFT JOIN timetable t ON sess.course_id = t.id
            WHERE sess.lecturer_id = ?
        """, (user_id,))

    elif role == 'student':
        cur.execute("""
            SELECT a.id, a.timestamp, 
                   CASE WHEN a.status IN ('Late', 'Early') THEN 'Absent' ELSE a.status END AS status,
                   t.course_name
            FROM attendance a
            LEFT JOIN sessions sess ON a.session_id = sess.id
            LEFT JOIN timetable t ON sess.course_id = t.id
            WHERE a.student_id = ?
        """, (user_id,))

    else:
        flash("Access Denied", "danger")
        return redirect(url_for('student_dashboard'))

    attendance_records = cur.fetchall()
    conn.close()

    return render_template('view_attendance.html', attendance=attendance_records, role=role)
def get_lecturer_attendance(lecturer_id):
    """Fetch all attendance records for a specific lecturer."""
    conn = get_db_connection()
    cur = conn.cursor()

    # Query to fetch attendance details along with session info, filtered by lecturer's sessions
    cur.execute("""
        SELECT t.session_id, t.session_date, a.timestamp, st.student_id, st.first_name, st.last_name
        FROM attendance a
        JOIN timetable t ON a.session_id = t.session_id
        JOIN students st ON a.student_id = st.id
        WHERE t.lecturer_id = ?
        ORDER BY a.timestamp DESC
    """, (lecturer_id,))

    attendance = cur.fetchall()
    conn.close()

    return attendance



@app.route('/lecturer_dashboard')
def lecturer_dashboard():
    # Retrieve the lecturer's ID from the session (assuming the lecturer is logged in)
    lecturer_id = session.get('user_id')

    if not lecturer_id:
        flash("Please log in to view your attendance.", "danger")
        return redirect(url_for('login'))  # Redirect to login page if not logged in

    # Get all attendance records
    attendance = get_lecturer_attendance(lecturer_id)

    # Render the lecturer dashboard template and pass the attendance data
    return render_template('lecturer_dashboard.html', attendance=attendance)


def get_student_attendance(student_id):
    """Fetch attendance records for a specific student."""
    conn = get_db_connection()
    cur = conn.cursor()

    # Fetch the attendance records, joining the timetable to get session information
    cur.execute("""
        SELECT t.session_id, a.timestamp
        FROM attendance a
        JOIN timetable t ON a.session_id = t.id
        WHERE a.student_id = ?
        ORDER BY a.timestamp DESC
    """, (student_id,))

    # Fetch all attendance records for the student
    attendance = cur.fetchall()
    conn.close()

    return attendance

@app.route('/student_dashboard')
def student_dashboard():
    # Retrieve the student's ID from the session (assuming the student is logged in)
    student_id = session.get('user_id')

    if not student_id:
        flash("Please log in to view your attendance.", "danger")
        return redirect(url_for('login'))  # Redirect to login page if not logged in

    # Get attendance data for the student
    attendance = get_student_attendance(student_id)

    # Render the student dashboard template and pass the attendance data
    return render_template('student_dashboard.html', attendance=attendance)






@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()

        if user and check_password_hash(user['password'], password):
            
            session.clear()  

            
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
    if 'user_id' not in session or session['role'] != 'admin':
        flash("Unauthorized access!", "danger")
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor()

    if request.method == 'POST':
        lecturer_id = request.form.get('lecturer_id', '').strip()

        
        if not lecturer_id.isdigit():
            flash("Invalid Lecturer ID format!", "danger")
            return redirect(url_for('generate_sessions'))

        lecturer_id = int(lecturer_id)

        
        cursor.execute("SELECT id FROM users WHERE id = ? AND role = 'lecturer'", (lecturer_id,))
        lecturer = cursor.fetchone()
        if not lecturer:
            flash(f"Lecturer ID {lecturer_id} not found!", "danger")
            return redirect(url_for('generate_sessions'))

        
        session_code = f"S{int(time.time())}"

    
        cursor.execute(
            "INSERT INTO sessions (lecturer_id, session_code, created_at) VALUES (?, ?, datetime('now'))",
            (lecturer_id, session_code),
        )
        conn.commit()
        flash("Session generated successfully!", "success")


    cursor.execute("""
        SELECT s.id, s.lecturer_id, s.session_code, s.created_at, u.username AS lecturer_name
        FROM sessions s
        JOIN users u ON s.lecturer_id = u.id
        ORDER BY s.created_at DESC
    """)
    sessions = cursor.fetchall()


    cursor.execute("SELECT id, username FROM users WHERE role = 'lecturer'")
    lecturers = cursor.fetchall()

    conn.close()
    return render_template('manage_sessions.html', sessions=sessions, lecturers=lecturers)


@app.route('/delete_session/<int:session_id>', methods=['POST'])
def delete_session(session_id):
    if 'user_id' not in session or session['role'] != 'admin':
        flash("Unauthorized access!", "danger")
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor()

    
    cursor.execute("SELECT id FROM sessions WHERE id = ?", (session_id,))
    session_exists = cursor.fetchone()

    if session_exists:
        cursor.execute("DELETE FROM sessions WHERE id = ?", (session_id,))
        conn.commit()
        flash("Session deleted successfully!", "success")
    else:
        flash("Session not found!", "danger")

    conn.close()
    return redirect(url_for('generate_sessions'))






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
    session_code = f"{lecturer_id}_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}" 
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
    if not cap.isOpened():
        flash("Error: Could not open the webcam. Try again.", "danger")
        return redirect(url_for('student_dashboard'))  

    qr_decoder = QRCodeDetector()
    session_id = None  

    while True:
        success, frame = cap.read()
        if not success:
            flash("Error: Could not capture a frame. Try again.", "danger")
            break  

        decoded_text, points, _ = qr_decoder.detectAndDecode(frame)
        if decoded_text:
            session_id = decoded_text.strip()
            result = mark_attendance(session['user_id'], session_id)

            if result == "success":
                flash("Attendance marked successfully!", "success")
            elif result == "duplicate":
                flash("You have already marked attendance for this session.", "warning")
            elif result == "invalid":
                flash("Invalid session code. Please try again.", "danger")

            break  

        cv2.imshow("QR Code Scanner", frame)
        if cv2.waitKey(1) & 0xFF == ord('q'): 
            break

    cap.release()
    cv2.destroyAllWindows()
    return redirect(url_for('student_dashboard'))


def mark_attendance(student_id, session_code):
    """Marks attendance if session is valid and student has not already marked attendance."""
    conn = get_db_connection()
    cur = conn.cursor()

    
    cur.execute("SELECT id FROM timetable WHERE session_id=?", (session_code,))

    session = cur.fetchone()

    if not session:
        conn.close()
        return "invalid" 

    session_id = session[0]  

    
    cur.execute("SELECT id FROM attendance WHERE student_id=? AND session_id=?", (student_id, session_id))
    existing_attendance = cur.fetchone()

    if existing_attendance:
        conn.close()
        return "duplicate"  

    
    cur.execute("INSERT INTO attendance (student_id, session_id, timestamp) VALUES (?, ?, datetime('now'))",
                (student_id, session_id))
    conn.commit()
    conn.close()

    return "success"  


    
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
@app.route('/delete_timetable_entry/<int:session_id>', methods=['POST'])
def delete_timetable_entry(session_id):
    conn = get_db_connection()
    cur = conn.cursor()
    
    
    cur.execute("SELECT id FROM timetable WHERE id=?", (session_id,))
    if not cur.fetchone():
        flash("Timetable entry not found!", "danger")
        return redirect(url_for('manage_timetable'))

    cur.execute("DELETE FROM timetable WHERE id=?", (session_id,))
    conn.commit()
    conn.close()

    flash("Timetable entry deleted!", "success")
    return redirect(url_for('manage_timetable'))



@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully.', 'info')
    return redirect(url_for('index'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
