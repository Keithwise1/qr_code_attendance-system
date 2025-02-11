from flask import Flask, render_template, request, redirect, url_for, jsonify, session, flash
import cv2
from cv2 import QRCodeDetector
from datetime import datetime
import sqlite3
import qrcode
import os
from werkzeug.security import generate_password_hash, check_password_hash

# Initialize Flask App
app = Flask(__name__, template_folder="templates/templates")
app.secret_key = 'your_secret_key'  # Change to a secure key

app.config['DATABASE'] = 'attendance.db'

# Ensure QR code folder exists
qr_code_folder = "static/qr_codes"
if not os.path.exists(qr_code_folder):
    os.makedirs(qr_code_folder)

# Function to Connect to Database
def get_db_connection():
    conn = sqlite3.connect(app.config['DATABASE'])
    conn.row_factory = sqlite3.Row
    return conn

# Initialize Database
def init_db():
    with app.app_context():
        db = get_db_connection()
        db.executescript('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS attendance (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                student_id INTEGER NOT NULL,
                timestamp TEXT NOT NULL,
                status TEXT NOT NULL,
                FOREIGN KEY(student_id) REFERENCES users(id)
            );
        ''')
        db.commit()

# Homepage
@app.route('/')
def index():
    return render_template('index.html')

# Login Route
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
            else:
                return redirect(url_for('student_dashboard'))
        else:
            flash('Invalid username or password', 'danger')

    return render_template('login.html')

# Signup Route
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

# Admin Dashboard
@app.route('/admin/dashboard')
def admin_dashboard():
    if 'user_id' not in session or session['role'] != 'admin':
        flash('Unauthorized access!', 'danger')
        return redirect(url_for('login'))
    return render_template('admin_dashboard.html')

# Student Dashboard
@app.route('/student/dashboard')
def student_dashboard():
    if 'user_id' not in session or session['role'] != 'student':
        flash('Unauthorized access!', 'danger')
        return redirect(url_for('login'))
    return render_template('student_dashboard.html')

# Generate QR Code
@app.route('/generate_qr/<int:student_id>')
def generate_qr(student_id):
    if 'user_id' not in session or session['role'] != 'admin':
        flash('Unauthorized access!', 'danger')
        return redirect(url_for('login'))
    
    qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=10, border=4)
    qr.add_data(str(student_id))
    qr.make(fit=True)

    img = qr.make_image(fill='black', back_color='white')
    
    img_path = os.path.join(qr_code_folder, f"student_{student_id}_qr.png")
    img.save(img_path)

    return render_template('qr_generated.html', qr_image=f"qr_codes/student_{student_id}_qr.png", student_id=student_id)

# Scan QR Code via Webcam
@app.route('/scan_webcam')
def scan_webcam():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('scan_webcam.html')

# Scan and Mark Attendance
@app.route('/scan')
def scan():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    cap = cv2.VideoCapture(0)
    qr_decoder = QRCodeDetector()

    while True:
        success, frame = cap.read()
        if not success:
            break

        decoded_text, points, _ = qr_decoder.detectAndDecode(frame)
        if decoded_text:
            print(f"Scanned: {decoded_text}")
            mark_attendance(decoded_text)
            cv2.putText(frame, f"Marked: {decoded_text}", (50, 50), cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 255, 0), 2)

        cv2.imshow("QR Code Scanner", frame)
        if cv2.waitKey(1) & 0xFF == ord('q'):
            break

    cap.release()
    cv2.destroyAllWindows()
    return jsonify({'status': 'success'})

# Mark Attendance
def mark_attendance(student_id):
    conn = get_db_connection()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    status = "On Time" if datetime.now().hour < 9 else "Late"
    conn.execute("INSERT INTO attendance (student_id, timestamp, status) VALUES (?, ?, ?)",
                 (student_id, timestamp, status))
    conn.commit()
    conn.close()
    print(f"Student {student_id} marked as {status}")

# Attendance Records
@app.route('/attendance')
def attendance():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    attendance_records = conn.execute('SELECT * FROM attendance').fetchall()
    conn.close()
    return render_template('attendance.html', attendance_records=attendance_records)

# Dashboard Statistics
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    stats = get_attendance_stats()
    return render_template('dashboard.html', stats=stats)

def get_attendance_stats():
    conn = get_db_connection()
    total = conn.execute("SELECT COUNT(*) FROM attendance").fetchone()[0]
    on_time = conn.execute("SELECT COUNT(*) FROM attendance WHERE status = 'On Time'").fetchone()[0]
    late = conn.execute("SELECT COUNT(*) FROM attendance WHERE status = 'Late'").fetchone()[0]
    conn.close()
    return {"total": total, "on_time": on_time, "late": late}

# About and Help Pages
@app.route('/help')
def help():
    return render_template('help.html')

@app.route('/about')
def about():
    return render_template('about.html')

# Logout
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('role', None)
    flash('Logged out successfully.', 'info')
    return redirect(url_for('index'))

# Run Flask App
if __name__ == '__main__':
    init_db()
    app.run(debug=True)
