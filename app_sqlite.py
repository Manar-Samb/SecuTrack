"""
SecuTrack - Version SQLite pour tests et démonstration
Author: Ndeye Manar SAMB
Description: Version simplifiée avec SQLite pour éviter les problèmes de configuration MySQL
"""

import os
import hashlib
import secrets
import sqlite3
from datetime import datetime, timedelta
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import logging

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# Configuration
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ALLOWED_EXTENSIONS'] = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'zip', 'rar'}
app.config['DATABASE'] = 'secutrack.db'

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('secutrack.log'),
        logging.StreamHandler()
    ]
)

def get_db_connection():
    """Establish SQLite database connection"""
    try:
        conn = sqlite3.connect(app.config['DATABASE'])
        conn.row_factory = sqlite3.Row
        return conn
    except Exception as e:
        logging.error(f"Database connection failed: {str(e)}")
        return None

def init_database():
    """Initialize database tables"""
    conn = get_db_connection()
    if not conn:
        return False
    
    try:
        cursor = conn.cursor()
        
        # Users table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK (role IN ('student', 'teacher', 'admin')),
                group_id INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                is_active BOOLEAN DEFAULT 1
            )
        """)
        
        # Groups table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS groups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT,
                teacher_id INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (teacher_id) REFERENCES users(id)
            )
        """)
        
        # Projects table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS projects (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT,
                filename TEXT NOT NULL,
                encrypted_filename TEXT NOT NULL,
                file_hash TEXT NOT NULL,
                group_id INTEGER NOT NULL,
                submitted_by INTEGER NOT NULL,
                status TEXT DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected')),
                teacher_comment TEXT,
                submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                reviewed_at TIMESTAMP,
                FOREIGN KEY (group_id) REFERENCES groups(id),
                FOREIGN KEY (submitted_by) REFERENCES users(id)
            )
        """)
        
        # Audit logs table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action TEXT NOT NULL,
                resource_type TEXT,
                resource_id INTEGER,
                details TEXT,
                ip_address TEXT,
                user_agent TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        
        conn.commit()
        logging.info("Database tables initialized successfully")
        return True
        
    except Exception as e:
        logging.error(f"Database initialization failed: {str(e)}")
        return False
    finally:
        conn.close()

def create_default_users():
    """Create default users for testing"""
    conn = get_db_connection()
    if not conn:
        return False
    
    try:
        cursor = conn.cursor()
        
        # Check if admin user already exists
        cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'")
        admin_count = cursor.fetchone()[0]
        
        if admin_count == 0:
            # Create default admin user
            admin_hash = generate_password_hash('admin123')
            cursor.execute("""
                INSERT INTO users (username, email, password_hash, role)
                VALUES ('admin', 'admin@secutrack.local', ?, 'admin')
            """, (admin_hash,))
            
            # Create default teacher user
            teacher_hash = generate_password_hash('teacher123')
            cursor.execute("""
                INSERT INTO users (username, email, password_hash, role)
                VALUES ('teacher', 'teacher@secutrack.local', ?, 'teacher')
            """, (teacher_hash,))
            
            # Create default group
            cursor.execute("""
                INSERT INTO groups (name, description, teacher_id)
                VALUES ('Groupe Test', 'Groupe de démonstration', 2)
            """)
            
            # Create default student user
            student_hash = generate_password_hash('student123')
            cursor.execute("""
                INSERT INTO users (username, email, password_hash, role, group_id)
                VALUES ('student', 'student@secutrack.local', ?, 'student', 1)
            """, (student_hash,))
            
            conn.commit()
            logging.info("Default users created successfully")
        
        return True
        
    except Exception as e:
        logging.error(f"Error creating default users: {str(e)}")
        return False
    finally:
        conn.close()

def log_action(user_id, action, resource_type=None, resource_id=None, details=None):
    """Log user actions for audit trail"""
    conn = get_db_connection()
    if not conn:
        return
    
    try:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO audit_logs (user_id, action, resource_type, resource_id, details, ip_address, user_agent)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (user_id, action, resource_type, resource_id, details, 
              request.remote_addr, request.headers.get('User-Agent')))
        conn.commit()
    except Exception as e:
        logging.error(f"Failed to log action: {str(e)}")
    finally:
        conn.close()

def login_required(f):
    """Decorator to require login for protected routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Vous devez être connecté pour accéder à cette page.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def role_required(required_role):
    """Decorator to require specific role"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_role' not in session or session['user_role'] != required_role:
                flash('Accès non autorisé.', 'error')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def encrypt_file(file_data, key):
    """Encrypt file data using AES encryption"""
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(file_data)
    return cipher.nonce + tag + ciphertext

def get_file_hash(file_data):
    """Generate SHA-256 hash of file data"""
    return hashlib.sha256(file_data).hexdigest()

@app.route('/')
def index():
    """Home page"""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        if not username or not password:
            flash('Nom d\'utilisateur et mot de passe requis.', 'error')
            return render_template('login.html')
        
        conn = get_db_connection()
        if not conn:
            flash('Erreur de connexion à la base de données.', 'error')
            return render_template('login.html')
        
        try:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, username, password_hash, role, group_id, is_active 
                FROM users WHERE username = ?
            """, (username,))
            user = cursor.fetchone()
            
            if user and user['is_active'] and check_password_hash(user['password_hash'], password):
                # Update last login
                cursor.execute("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?", (user['id'],))
                conn.commit()
                
                # Set session
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['user_role'] = user['role']
                session['group_id'] = user['group_id']
                
                # Log successful login
                log_action(user['id'], 'LOGIN_SUCCESS')
                
                flash(f'Bienvenue, {user["username"]} !', 'success')
                return redirect(url_for('dashboard'))
            else:
                # Log failed login attempt
                if user:
                    log_action(user['id'], 'LOGIN_FAILED', details='Invalid password')
                else:
                    log_action(None, 'LOGIN_FAILED', details=f'Unknown user: {username}')
                
                flash('Nom d\'utilisateur ou mot de passe incorrect.', 'error')
                
        except Exception as e:
            logging.error(f"Login error: {str(e)}")
            flash('Erreur lors de la connexion.', 'error')
        finally:
            conn.close()
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    """User logout"""
    user_id = session.get('user_id')
    log_action(user_id, 'LOGOUT')
    session.clear()
    flash('Vous avez été déconnecté avec succès.', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    """User dashboard"""
    user_role = session.get('user_role')
    
    if user_role == 'student':
        return redirect(url_for('student_dashboard'))
    elif user_role == 'teacher':
        return redirect(url_for('teacher_dashboard'))
    elif user_role == 'admin':
        return redirect(url_for('admin_dashboard'))
    else:
        flash('Rôle utilisateur non reconnu.', 'error')
        return redirect(url_for('logout'))

@app.route('/student_dashboard')
@login_required
@role_required('student')
def student_dashboard():
    """Student dashboard"""
    conn = get_db_connection()
    if not conn:
        flash('Erreur de connexion à la base de données.', 'error')
        return redirect(url_for('index'))
    
    try:
        cursor = conn.cursor()
        
        # Get student's group info
        cursor.execute("""
            SELECT g.name, g.description, u.username as teacher_name
            FROM groups g
            LEFT JOIN users u ON g.teacher_id = u.id
            WHERE g.id = ?
        """, (session.get('group_id'),))
        group_info = cursor.fetchone()
        
        # Get student's projects
        cursor.execute("""
            SELECT id, title, description, status, submitted_at, teacher_comment
            FROM projects 
            WHERE submitted_by = ? 
            ORDER BY submitted_at DESC
        """, (session['user_id'],))
        projects = cursor.fetchall()
        
        # Get recent group activity
        cursor.execute("""
            SELECT p.title, u.username, p.submitted_at, p.status
            FROM projects p
            JOIN users u ON p.submitted_by = u.id
            WHERE p.group_id = ?
            ORDER BY p.submitted_at DESC
            LIMIT 10
        """, (session.get('group_id'),))
        recent_activity = cursor.fetchall()
        
        return render_template('student_dashboard.html', 
                             group_info=group_info,
                             projects=projects,
                             recent_activity=recent_activity)
        
    except Exception as e:
        logging.error(f"Student dashboard error: {str(e)}")
        flash('Erreur lors du chargement du tableau de bord.', 'error')
        return redirect(url_for('index'))
    finally:
        conn.close()

@app.route('/teacher_dashboard')
@login_required
@role_required('teacher')
def teacher_dashboard():
    """Teacher dashboard"""
    conn = get_db_connection()
    if not conn:
        flash('Erreur de connexion à la base de données.', 'error')
        return redirect(url_for('index'))
    
    try:
        cursor = conn.cursor()
        
        # Get teacher's assigned groups
        cursor.execute("""
            SELECT id, name, description
            FROM groups 
            WHERE teacher_id = ?
        """, (session['user_id'],))
        groups = cursor.fetchall()
        
        # Get pending projects for review
        cursor.execute("""
            SELECT p.id, p.title, p.description, p.submitted_at, u.username, g.name as group_name
            FROM projects p
            JOIN users u ON p.submitted_by = u.id
            JOIN groups g ON p.group_id = g.id
            WHERE g.teacher_id = ? AND p.status = 'pending'
            ORDER BY p.submitted_at ASC
        """, (session['user_id'],))
        pending_projects = cursor.fetchall()
        
        # Get statistics
        cursor.execute("""
            SELECT 
                COUNT(*) as total_projects,
                SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pending_count,
                SUM(CASE WHEN status = 'approved' THEN 1 ELSE 0 END) as approved_count,
                SUM(CASE WHEN status = 'rejected' THEN 1 ELSE 0 END) as rejected_count
            FROM projects p
            JOIN groups g ON p.group_id = g.id
            WHERE g.teacher_id = ?
        """, (session['user_id'],))
        stats = cursor.fetchone()
        
        return render_template('teacher_dashboard.html',
                             groups=groups,
                             pending_projects=pending_projects,
                             stats=stats)
        
    except Exception as e:
        logging.error(f"Teacher dashboard error: {str(e)}")
        flash('Erreur lors du chargement du tableau de bord.', 'error')
        return redirect(url_for('index'))
    finally:
        conn.close()

@app.route('/admin_dashboard')
@login_required
@role_required('admin')
def admin_dashboard():
    """Admin dashboard"""
    conn = get_db_connection()
    if not conn:
        flash('Erreur de connexion à la base de données.', 'error')
        return redirect(url_for('index'))
    
    try:
        cursor = conn.cursor()
        
        # Get system statistics
        cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'student'")
        student_count = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'teacher'")
        teacher_count = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM groups")
        group_count = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM projects")
        project_count = cursor.fetchone()[0]
        
        # Get recent activity
        cursor.execute("""
            SELECT action, details, timestamp, u.username
            FROM audit_logs a
            LEFT JOIN users u ON a.user_id = u.id
            ORDER BY timestamp DESC
            LIMIT 20
        """)
        recent_logs = cursor.fetchall()
        
        # Get users without groups
        cursor.execute("""
            SELECT id, username, email, role
            FROM users 
            WHERE role = 'student' AND (group_id IS NULL OR group_id = 0)
        """)
        unassigned_students = cursor.fetchall()
        
        stats = {
            'students': student_count,
            'teachers': teacher_count,
            'groups': group_count,
            'projects': project_count
        }
        
        return render_template('admin_dashboard.html',
                             stats=stats,
                             recent_logs=recent_logs,
                             unassigned_students=unassigned_students)
        
    except Exception as e:
        logging.error(f"Admin dashboard error: {str(e)}")
        flash('Erreur lors du chargement du tableau de bord.', 'error')
        return redirect(url_for('index'))
    finally:
        conn.close()

@app.route('/submit_project', methods=['GET', 'POST'])
@login_required
@role_required('student')
def submit_project():
    """Submit a new project"""
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        
        if not title or not description:
            flash('Titre et description sont requis.', 'error')
            return render_template('submit_project.html')
        
        if 'file' not in request.files:
            flash('Aucun fichier sélectionné.', 'error')
            return render_template('submit_project.html')
        
        file = request.files['file']
        if file.filename == '':
            flash('Aucun fichier sélectionné.', 'error')
            return render_template('submit_project.html')
        
        if not allowed_file(file.filename):
            flash('Type de fichier non autorisé.', 'error')
            return render_template('submit_project.html')
        
        try:
            # Read file data
            file_data = file.read()
            
            # Generate file hash for integrity
            file_hash = get_file_hash(file_data)
            
            # Encrypt file (using a simple key for demo)
            encryption_key = b'0123456789abcdef0123456789abcdef'  # 32 bytes key
            encrypted_data = encrypt_file(file_data, encryption_key)
            
            # Generate secure filename
            secure_name = secure_filename(file.filename)
            encrypted_filename = f"{secrets.token_hex(16)}_{secure_name}"
            
            # Save encrypted file
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], encrypted_filename)
            with open(file_path, 'wb') as f:
                f.write(encrypted_data)
            
            # Save to database
            conn = get_db_connection()
            if conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO projects (title, description, filename, encrypted_filename, 
                                        file_hash, group_id, submitted_by)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (title, description, secure_name, encrypted_filename, 
                      file_hash, session.get('group_id'), session['user_id']))
                
                project_id = cursor.lastrowid
                conn.commit()
                conn.close()
                
                # Log the action
                log_action(session['user_id'], 'PROJECT_SUBMITTED', 'project', project_id, 
                          f'Project: {title}')
                
                flash('Projet soumis avec succès !', 'success')
                return redirect(url_for('student_dashboard'))
            else:
                flash('Erreur lors de la sauvegarde.', 'error')
                
        except Exception as e:
            logging.error(f"Project submission error: {str(e)}")
            flash('Erreur lors de la soumission du projet.', 'error')
    
    return render_template('submit_project.html')

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    """Change user password"""
    if request.method == 'POST':
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        if not all([current_password, new_password, confirm_password]):
            flash('Tous les champs sont requis.', 'error')
            return render_template('change_password.html')
        
        if new_password != confirm_password:
            flash('Les nouveaux mots de passe ne correspondent pas.', 'error')
            return render_template('change_password.html')
        
        if len(new_password) < 8:
            flash('Le nouveau mot de passe doit contenir au moins 8 caractères.', 'error')
            return render_template('change_password.html')
        
        conn = get_db_connection()
        if not conn:
            flash('Erreur de connexion à la base de données.', 'error')
            return render_template('change_password.html')
        
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT password_hash FROM users WHERE id = ?", (session['user_id'],))
            user = cursor.fetchone()
            
            if user and check_password_hash(user['password_hash'], current_password):
                new_hash = generate_password_hash(new_password)
                cursor.execute("UPDATE users SET password_hash = ? WHERE id = ?", 
                             (new_hash, session['user_id']))
                conn.commit()
                
                log_action(session['user_id'], 'PASSWORD_CHANGED')
                flash('Mot de passe modifié avec succès !', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Mot de passe actuel incorrect.', 'error')
                
        except Exception as e:
            logging.error(f"Password change error: {str(e)}")
            flash('Erreur lors du changement de mot de passe.', 'error')
        finally:
            conn.close()
    
    return render_template('change_password.html')

# Placeholder routes for remaining functionality
@app.route('/project_history')
@login_required
@role_required('student')
def project_history():
    return render_template('project_history.html')

@app.route('/review_projects')
@login_required
@role_required('teacher')
def review_projects():
    return render_template('review_projects.html')

@app.route('/manage_users')
@login_required
@role_required('admin')
def manage_users():
    return render_template('manage_users.html')

@app.route('/manage_groups')
@login_required
@role_required('admin')
def manage_groups():
    return render_template('manage_groups.html')

if __name__ == '__main__':
    # Create upload directory
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    
    # Initialize database
    if init_database():
        create_default_users()
        logging.info("SecuTrack application starting with SQLite...")
        app.run(debug=True, host='127.0.0.1', port=5000)
    else:
        logging.error("Failed to initialize database. Application cannot start.")
