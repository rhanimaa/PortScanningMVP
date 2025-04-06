from flask import Flask, request, jsonify
import logging
import os
import sqlite3
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
receiver_logger = logging.getLogger('PortReceiver')

app = Flask(__name__)

def init_db():
    """Initialize the SQLite database"""
    db_path = os.getenv('DB_PATH', 'port_scans.db')
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS port_scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        host_identifier TEXT NOT NULL,
        scan_timestamp INTEGER NOT NULL,
        protocol TEXT NOT NULL,
        port INTEGER NOT NULL,
        recorded_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    conn.commit()
    conn.close()
    receiver_logger.info(f"Database initialized at {db_path}")

def store_scan_results(host_identifier: str, timestamp: int, open_ports: dict):
    """Store scan results in the database"""
    db_path = os.getenv('DB_PATH', 'port_scans.db')
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    try:
        for protocol, ports in open_ports.items():
            for port in ports:
                cursor.execute('''
                INSERT INTO port_scans (host_identifier, scan_timestamp, protocol, port)
                VALUES (?, ?, ?, ?)
                ''', (host_identifier, timestamp, protocol, port))
        
        conn.commit()
        receiver_logger.info(f"Stored scan results for {host_identifier}")
    except Exception as e:
        receiver_logger.error(f"Failed to store results: {str(e)}")
        raise
    finally:
        conn.close()

@app.route('/receive', methods=['POST'])
def receive_scan():
    """Endpoint to receive scan results"""
    if not request.is_json:
        receiver_logger.warning("Received non-JSON payload")
        return jsonify({'error': 'Request must be JSON'}), 400
    
    data = request.get_json()
    required_fields = ['host_identifier', 'timestamp', 'open_ports']
    
    if not all(field in data for field in required_fields):
        receiver_logger.warning("Received incomplete payload")
        return jsonify({'error': 'Missing required fields'}), 400
    
    try:
        store_scan_results(data['host_identifier'], data['timestamp'], data['open_ports'])
        return jsonify({'status': 'success'}), 200
    except Exception as e:
        receiver_logger.error(f"Error processing scan: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/scans', methods=['GET'])
def get_scans():
    """Endpoint to retrieve scan history"""
    db_path = os.getenv('DB_PATH', 'port_scans.db')
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
        SELECT host_identifier, scan_timestamp, protocol, port, recorded_at
        FROM port_scans
        ORDER BY scan_timestamp DESC
        LIMIT 100
        ''')
        
        results = []
        for row in cursor.fetchall():
            results.append({
                'host': row[0],
                'scan_time': datetime.fromtimestamp(row[1]).isoformat(),
                'protocol': row[2],
                'port': row[3],
                'recorded_at': row[4]
            })
        
        return jsonify({'scans': results}), 200
    except Exception as e:
        receiver_logger.error(f"Error retrieving scans: {str(e)}")
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

if __name__ == '__main__':
    init_db()
    port = int(os.getenv('RECEIVER_PORT', '5000'))
    receiver_logger.info(f"Starting receiver on port {port}")
    app.run(host='0.0.0.0', port=port)
