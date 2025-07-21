"""
SecuTrack Database Setup Script
This script creates the MySQL database and initializes it with the required tables.
"""

import pymysql
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Database configuration
DB_CONFIG = {
    'host': os.environ.get('DB_HOST', 'localhost'),
    'user': os.environ.get('DB_USER', 'root'),
    'password': os.environ.get('DB_PASSWORD', ''),
    'charset': 'utf8mb4'
}

DB_NAME = os.environ.get('DB_NAME', 'secutrackdb')

def create_database():
    """Create the SecuTrack database if it doesn't exist"""
    try:
        connection = pymysql.connect(**DB_CONFIG)
        cursor = connection.cursor()
        
        # Create database
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS {DB_NAME} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")
        print(f"✓ Database '{DB_NAME}' created successfully")
        
        connection.close()
        return True
        
    except Exception as e:
        print(f"✗ Error creating database: {str(e)}")
        return False

def setup_tables():
    """Create all required tables"""
    # Add database name to config
    db_config = DB_CONFIG.copy()
    db_config['database'] = DB_NAME
    
    try:
        connection = pymysql.connect(**db_config)
        cursor = connection.cursor()
        
        # Users table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                email VARCHAR(100) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                role ENUM('student', 'teacher', 'admin') NOT NULL,
                group_id INT DEFAULT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP NULL,
                is_active BOOLEAN DEFAULT TRUE,
                INDEX idx_username (username),
                INDEX idx_email (email),
                INDEX idx_role (role)
            ) ENGINE=InnoDB
        """)
        print("✓ Users table created")
        
        # Groups table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS `groups` (
                id INT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(100) NOT NULL,
                description TEXT,
                teacher_id INT DEFAULT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_teacher (teacher_id),
                FOREIGN KEY (teacher_id) REFERENCES users(id) ON DELETE SET NULL
            ) ENGINE=InnoDB
        """)
        print("✓ Groups table created")
        
        # Projects table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS projects (
                id INT AUTO_INCREMENT PRIMARY KEY,
                title VARCHAR(200) NOT NULL,
                description TEXT,
                filename VARCHAR(255) NOT NULL,
                encrypted_filename VARCHAR(255) NOT NULL,
                file_hash VARCHAR(64) NOT NULL,
                group_id INT NOT NULL,
                submitted_by INT NOT NULL,
                status ENUM('pending', 'approved', 'rejected') DEFAULT 'pending',
                teacher_comment TEXT,
                submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                reviewed_at TIMESTAMP NULL,
                INDEX idx_group (group_id),
                INDEX idx_submitted_by (submitted_by),
                INDEX idx_status (status),
                INDEX idx_submitted_at (submitted_at),
                FOREIGN KEY (group_id) REFERENCES `groups`(id) ON DELETE CASCADE,
                FOREIGN KEY (submitted_by) REFERENCES users(id) ON DELETE CASCADE
            ) ENGINE=InnoDB
        """)
        print("✓ Projects table created")
        
        # Audit logs table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT DEFAULT NULL,
                action VARCHAR(100) NOT NULL,
                resource_type VARCHAR(50) DEFAULT NULL,
                resource_id INT DEFAULT NULL,
                details TEXT,
                ip_address VARCHAR(45),
                user_agent TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_user (user_id),
                INDEX idx_action (action),
                INDEX idx_timestamp (timestamp),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
            ) ENGINE=InnoDB
        """)
        print("✓ Audit logs table created")
        
        # Sessions table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_sessions (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                session_token VARCHAR(255) UNIQUE NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_user (user_id),
                INDEX idx_token (session_token),
                INDEX idx_expires (expires_at),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            ) ENGINE=InnoDB
        """)
        print("✓ User sessions table created")
        
        connection.commit()
        connection.close()
        return True
        
    except Exception as e:
        print(f"✗ Error creating tables: {str(e)}")
        return False

def create_default_data():
    """Create default admin user and sample data"""
    from werkzeug.security import generate_password_hash
    
    db_config = DB_CONFIG.copy()
    db_config['database'] = DB_NAME
    
    try:
        connection = pymysql.connect(**db_config)
        cursor = connection.cursor()
        
        # Check if admin user already exists
        cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'")
        admin_count = cursor.fetchone()[0]
        
        if admin_count == 0:
            # Create default admin user
            admin_hash = generate_password_hash('admin123')
            cursor.execute("""
                INSERT INTO users (username, email, password_hash, role)
                VALUES ('admin', 'admin@secutrack.local', %s, 'admin')
            """, (admin_hash,))
            print("✓ Default admin user created (admin/admin123)")
            
            # Create default teacher user
            teacher_hash = generate_password_hash('teacher123')
            cursor.execute("""
                INSERT INTO users (username, email, password_hash, role)
                VALUES ('teacher', 'teacher@secutrack.local', %s, 'teacher')
            """, (teacher_hash,))
            print("✓ Default teacher user created (teacher/teacher123)")
            
            # Create default group
            cursor.execute("""
                INSERT INTO `groups` (name, description, teacher_id)
                VALUES ('Groupe Test', 'Groupe de démonstration', 2)
            """)
            print("✓ Default group created")
            
            # Create default student user
            student_hash = generate_password_hash('student123')
            cursor.execute("""
                INSERT INTO users (username, email, password_hash, role, group_id)
                VALUES ('student', 'student@secutrack.local', %s, 'student', 1)
            """, (student_hash,))
            print("✓ Default student user created (student/student123)")
            
            # Log initial setup
            cursor.execute("""
                INSERT INTO audit_logs (action, details, ip_address)
                VALUES ('SYSTEM_SETUP', 'Initial database setup completed', '127.0.0.1')
            """)
            
            connection.commit()
        else:
            print("✓ Default users already exist")
        
        connection.close()
        return True
        
    except Exception as e:
        print(f"✗ Error creating default data: {str(e)}")
        return False

def main():
    """Main setup function"""
    print("=" * 50)
    print("SecuTrack Database Setup")
    print("=" * 50)
    
    print("\n1. Creating database...")
    if not create_database():
        return False
    
    print("\n2. Creating tables...")
    if not setup_tables():
        return False
    
    print("\n3. Creating default data...")
    if not create_default_data():
        return False
    
    print("\n" + "=" * 50)
    print("✓ Database setup completed successfully!")
    print("=" * 50)
    print("\nDefault accounts created:")
    print("- Admin: admin / admin123")
    print("- Teacher: teacher / teacher123") 
    print("- Student: student / student123")
    print("\nYou can now run the application with: python app.py")
    
    return True

if __name__ == "__main__":
    main()
