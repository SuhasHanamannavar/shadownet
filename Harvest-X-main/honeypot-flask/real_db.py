import sqlite3
import os
from werkzeug.security import generate_password_hash, check_password_hash

DB_FILE = 'real_users.db'

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL
        )
    ''')
    
    # Check if admin exists
    c.execute('SELECT * FROM users WHERE username = ?', ('admin',))
    if not c.fetchone():
        admin_hash = generate_password_hash('admin')
        c.execute('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)', 
                  ('admin', admin_hash, 'administrator'))
                  
    # Add a standard user for demo
    c.execute('SELECT * FROM users WHERE username = ?', ('employee',))
    if not c.fetchone():
        emp_hash = generate_password_hash('1234')
        c.execute('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)', 
                  ('employee', emp_hash, 'standard'))
                  
    conn.commit()
    conn.close()

def verify_user(username, password):
    """Returns user dict if valid, else None"""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE username = ?', (username,))
    user = c.fetchone()
    conn.close()
    
    if user and check_password_hash(user['password_hash'], password):
        return dict(user)
    return None

def get_user_by_username(username):
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT username, role FROM users WHERE username = ?', (username,))
    user = c.fetchone()
    conn.close()
    return dict(user) if user else None
