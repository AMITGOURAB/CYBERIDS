import pickle
import sqlite3
import os
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from datetime import datetime, timedelta
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
import logging
import re
import time  # Added to fix NameError for time.sleep

app = Flask(__name__, static_folder='static')
CORS(app)

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Database setup
def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS attacks
                 (id INTEGER PRIMARY KEY, type TEXT, ip TEXT, location_lat REAL, location_lng REAL, timestamp TEXT, details TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS blocked_ips
                 (ip TEXT PRIMARY KEY)''')
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (username TEXT PRIMARY KEY, password TEXT)''')
    c.execute('INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)', ('admin', 'password123'))
    conn.commit()
    conn.close()

init_db()

# Load ML models and vectorizer with fallback
sql_model = None
malware_model = None
brute_model = None
ddos_model = None
vectorizer = None
try:
    os.makedirs('models', exist_ok=True)
    with open('models/sql_model.pkl', 'rb') as f:
        sql_model = pickle.load(f)
    with open('models/malware_model.pkl', 'rb') as f:
        malware_model = pickle.load(f)
    with open('models/brute_model.pkl', 'rb') as f:
        brute_model = pickle.load(f)
    with open('models/ddos_model.pkl', 'rb') as f:
        ddos_model = pickle.load(f)
    with open('models/vectorizer.pkl', 'rb') as f:
        vectorizer = pickle.load(f)
    logger.info("ML models and vectorizer loaded successfully")
except Exception as e:
    logger.error(f"Failed to load ML models: {e}")
    logger.warning("Falling back to default behavior as models are unavailable")

# Track brute force and DDoS attempts
brute_attempts = {}
ddos_requests = {}
BRUTE_THRESHOLD = 5
DDOS_THRESHOLD = 10

@app.route('/')
@app.route('/<path:path>')
def serve_static(path='welcome.html'):
    return send_from_directory('static', path)

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.json
        username = data.get('username')
        password = data.get('password')
        ip = request.remote_addr or '192.168.1.' + str(np.random.randint(0, 255))

        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('SELECT ip FROM blocked_ips WHERE ip = ?', (ip,))
        if c.fetchone():
            conn.close()
            return jsonify({'success': False, 'message': 'IP blocked'})
        c.execute('SELECT password FROM users WHERE username = ?', (username,))
        result = c.fetchone()
        conn.close()

        if result and result[0] == password:
            if ip in brute_attempts:
                brute_attempts[ip] = {'count': 0, 'time': datetime.now()}
            return jsonify({'success': True})
        else:
            if ip not in brute_attempts:
                brute_attempts[ip] = {'count': 0, 'time': datetime.now()}
            brute_attempts[ip]['count'] += 1
            if brute_attempts[ip]['count'] > BRUTE_THRESHOLD and (datetime.now() - brute_attempts[ip]['time']).seconds < 60:
                log_attack('brute', ip, None, f"Failed login: {username}", prompt_block=True)
                brute_attempts[ip] = {'count': 0, 'time': datetime.now()}
                return jsonify({'success': False, 'message': 'Brute force detected'})
            return jsonify({'success': False, 'message': 'Invalid credentials'})
    except Exception as e:
        logger.error(f"Login error: {e}")
        return jsonify({'success': False, 'message': 'Server error'}), 500

@app.route('/api/sql_injection', methods=['POST'])
def sql_injection():
    try:
        data = request.json
        query = data.get('query', '')
        ip = request.remote_addr or '192.168.1.' + str(np.random.randint(0, 255))

        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('SELECT ip FROM blocked_ips WHERE ip = ?', (ip,))
        if c.fetchone():
            conn.close()
            return jsonify({'is_injection': False, 'message': 'IP blocked'})
        conn.close()

        if vectorizer and sql_model:
            X = vectorizer.transform([query])
            prediction = sql_model.predict(X)[0]
            if prediction == 1:
                log_attack('sql', ip, data.get('location'), query)
                return jsonify({'is_injection': True, 'message': 'SQL Injection detected'})
        return jsonify({'is_injection': False, 'message': 'No SQL Injection detected'})
    except Exception as e:
        logger.error(f"SQL injection error: {e}")
        return jsonify({'error': 'Server error'}), 500

@app.route('/api/malware', methods=['POST'])
def malware():
    try:
        data = request.form
        ip = request.remote_addr or '192.168.1.' + str(np.random.randint(0, 255))

        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('SELECT ip FROM blocked_ips WHERE ip = ?', (ip,))
        if c.fetchone():
            conn.close()
            return jsonify({'is_malware': False, 'message': 'IP blocked'})
        conn.close()

        file = request.files.get('file')
        if not file:
            return jsonify({'is_malware': False, 'message': 'No file provided'})

        filename = file.filename.lower()
        filesize = len(file.read()) / 1024  # Size in KB
        features = np.array([[len(filename), filesize, 1 if any(kw in filename for kw in ['malware', 'virus', 'trojan', 'ransom']) else 0]])
        if malware_model:
            prediction = malware_model.predict(features)[0]
            if prediction == 1:
                log_attack('malware', ip, data.get('location'), filename)
                return jsonify({'is_malware': True, 'message': 'Malware detected'})
        return jsonify({'is_malware': False, 'message': 'No malware detected'})
    except Exception as e:
        logger.error(f"Malware detection error: {e}")
        return jsonify({'error': 'Server error'}), 500

@app.route('/api/brute_force', methods=['POST'])
def brute_force():
    try:
        data = request.json
        username = data.get('username', '')
        password = data.get('password', '')
        ip = request.remote_addr or data.get('ip', '192.168.1.' + str(np.random.randint(0, 255)))

        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('SELECT ip FROM blocked_ips WHERE ip = ?', (ip,))
        if c.fetchone():
            conn.close()
            return jsonify({'is_brute': False, 'message': 'IP blocked'})
        c.execute('SELECT password FROM users WHERE username = ?', (username,))
        result = c.fetchone()
        conn.close()

        if ip not in brute_attempts:
            brute_attempts[ip] = {'count': 0, 'time': datetime.now()}
        brute_attempts[ip]['count'] += 1
        features = np.array([[brute_attempts[ip]['count'], (datetime.now() - brute_attempts[ip]['time']).seconds]])
        if brute_model:
            prediction = brute_model.predict(features)[0]
            if prediction == 1 and brute_attempts[ip]['count'] > BRUTE_THRESHOLD:
                log_attack('brute', ip, data.get('location'), f"Attempt: {username}/{password}", prompt_block=True)
                brute_attempts[ip] = {'count': 0, 'time': datetime.now()}
                return jsonify({'is_brute': True, 'message': 'Brute force detected'})
        if result and result[0] == password:
            brute_attempts[ip] = {'count': 0, 'time': datetime.now()}
            return jsonify({'is_brute': False, 'message': 'Login successful'})
        return jsonify({'is_brute': False, 'message': 'Invalid credentials'})
    except Exception as e:
        logger.error(f"Brute force error: {e}")
        return jsonify({'error': 'Server error'}), 500

@app.route('/api/ddos', methods=['POST'])
def ddos():
    try:
        data = request.json
        ip = request.remote_addr or data.get('ip', '192.168.1.' + str(np.random.randint(0, 255)))

        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('SELECT ip FROM blocked_ips WHERE ip = ?', (ip,))
        if c.fetchone():
            conn.close()
            return jsonify({'is_ddos': False, 'message': 'IP blocked'})
        conn.close()

        if ip not in ddos_requests:
            ddos_requests[ip] = {'count': 0, 'time': datetime.now()}
        ddos_requests[ip]['count'] += 1
        time.sleep(0.5)  # Simulate resource-intensive processing
        features = np.array([[ddos_requests[ip]['count'], (datetime.now() - ddos_requests[ip]['time']).seconds]])  # Fixed to use ddos_requests
        if ddos_model:
            prediction = ddos_model.predict(features)[0]
            if prediction == 1 and ddos_requests[ip]['count'] > DDOS_THRESHOLD:
                log_attack('ddos', ip, data.get('location'), f"Requests: {ddos_requests[ip]['count']}", prompt_block=True)
                ddos_requests[ip] = {'count': 0, 'time': datetime.now()}
                return jsonify({'is_ddos': True, 'message': 'DDoS detected'})
        return jsonify({'is_ddos': False, 'message': 'Request processed'})
    except Exception as e:
        logger.error(f"DDoS error: {e}")
        return jsonify({'error': 'Server error'}), 500

@app.route('/api/block_ip', methods=['POST'])
def block_ip():
    try:
        data = request.json
        ip = data.get('ip')
        logger.info(f"Attempting to block IP: {ip}")

        # Validate IP using Python's re module
        if not ip or not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ip):
            logger.warning(f"Invalid IP address format: {ip}")
            return jsonify({'success': False, 'message': 'Invalid IP address'}), 400

        # Validate each octet of the IP address
        octets = ip.split('.')
        for octet in octets:
            if not (0 <= int(octet) <= 255):
                logger.warning(f"IP octet out of range: {ip}")
                return jsonify({'success': False, 'message': 'IP address octets must be between 0 and 255'}), 400

        # Attempt to connect to the database and insert the IP
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('INSERT OR IGNORE INTO blocked_ips (ip) VALUES (?)', (ip,))
        conn.commit()
        affected_rows = c.rowcount
        conn.close()

        if affected_rows == 0:
            logger.info(f"IP already blocked: {ip}")
            return jsonify({'success': True, 'message': f'IP {ip} is already blocked'})

        logger.info(f"Blocked IP: {ip}")
        return jsonify({'success': True, 'message': f'IP {ip} blocked'})
    except sqlite3.Error as e:
        logger.error(f"Database error while blocking IP {ip}: {e}")
        return jsonify({'success': False, 'message': f'Database error: {str(e)}'}), 500
    except Exception as e:
        logger.error(f"Unexpected error while blocking IP {ip}: {e}")
        return jsonify({'success': False, 'message': f'Server error: {str(e)}'}), 500

@app.route('/api/unblock_ip', methods=['POST'])
def unblock_ip():
    try:
        data = request.json
        ip = data.get('ip')
        logger.info(f"Attempting to unblock IP: {ip}")

        # Validate IP using Python's re module
        if not ip or not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ip):
            logger.warning(f"Invalid IP address format: {ip}")
            return jsonify({'success': False, 'message': 'Invalid IP address'}), 400

        # Validate each octet of the IP address
        octets = ip.split('.')
        for octet in octets:
            if not (0 <= int(octet) <= 255):
                logger.warning(f"IP octet out of range: {ip}")
                return jsonify({'success': False, 'message': 'IP address octets must be between 0 and 255'}), 400

        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('DELETE FROM blocked_ips WHERE ip = ?', (ip,))
        conn.commit()
        # Verify the IP is removed
        c.execute('SELECT ip FROM blocked_ips WHERE ip = ?', (ip,))
        if c.fetchone():
            logger.error(f"IP {ip} still exists in blocked_ips after unblock attempt")
            conn.close()
            return jsonify({'success': False, 'message': f'Failed to unblock IP {ip}'}), 500
        # Fetch updated list of blocked IPs
        c.execute('SELECT ip FROM blocked_ips')
        updated_ips = [row[0] for row in c.fetchall()]
        conn.close()

        logger.info(f"Unblocked IP: {ip}")
        return jsonify({'success': True, 'message': f'IP {ip} unblocked', 'updated_ips': updated_ips})
    except sqlite3.Error as e:
        logger.error(f"Database error while unblocking IP {ip}: {e}")
        return jsonify({'success': False, 'message': f'Database error: {str(e)}'}), 500
    except Exception as e:
        logger.error(f"Unexpected error while unblocking IP {ip}: {e}")
        return jsonify({'success': False, 'message': f'Server error: {str(e)}'}), 500

@app.route('/api/blocked_ips', methods=['GET'])
def get_blocked_ips():
    try:
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('SELECT ip FROM blocked_ips')
        ips = [row[0] for row in c.fetchall()]
        conn.close()
        return jsonify({'ips': ips})
    except Exception as e:
        logger.error(f"Get blocked IPs error: {e}")
        return jsonify({'error': 'Server error'}), 500

@app.route('/api/attacks', methods=['GET'])
def get_attacks():
    try:
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('SELECT type, ip, location_lat, location_lng, timestamp, details FROM attacks ORDER BY timestamp DESC')
        attacks = [{'type': row[0], 'ip': row[1], 'location': {'lat': row[2], 'lng': row[3]} if row[2] and row[3] else None, 'timestamp': row[4], 'details': row[5]} for row in c.fetchall()]
        conn.close()
        counts = {'sql': 0, 'malware': 0, 'ddos': 0, 'brute': 0}
        for attack in attacks:
            counts[attack['type']] += 1
        return jsonify({'attacks': attacks, 'counts': counts})
    except Exception as e:
        logger.error(f"Get attacks error: {e}")
        return jsonify({'error': 'Server error'}), 500

def log_attack(attack_type, ip, location, details, prompt_block=False):
    try:
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        location_lat = location['lat'] if location else None
        location_lng = location['lng'] if location else None
        c.execute('INSERT INTO attacks (type, ip, location_lat, location_lng, timestamp, details) VALUES (?, ?, ?, ?, ?, ?)',
                  (attack_type, ip, location_lat, location_lng, datetime.now().isoformat(), details))
        conn.commit()
        conn.close()
        logger.info(f"Logged {attack_type} attack from IP {ip}: {details}")
        if prompt_block:
            logger.info(f"Prompting to block IP {ip} for {attack_type} attack")
    except Exception as e:
        logger.error(f"Log attack error: {e}")

if __name__ == '__main__':
    os.makedirs('models', exist_ok=True)
    os.makedirs('static', exist_ok=True)
    port = int(os.environ.get('PORT', 5000))  # Use Render's port or default to 5000
    app.run(host='0.0.0.0', port=port, debug=False)