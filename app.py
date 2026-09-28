import os
import time
import sqlite3
import threading
from flask import Flask, render_template, jsonify, request

app = Flask(__name__)
DB_NAME = 'samba_audit.db'
LOG_FILE = '/var/log/syslog'

def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            user TEXT,
            ip TEXT,
            share TEXT,
            operation TEXT,
            status TEXT,
            file_path TEXT
        )
    ''')
    conn.commit()
    conn.close()

def tail_log():
    try:
        with open(LOG_FILE, 'r') as f:
            f.seek(0, os.SEEK_END)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.5)
                    continue
                if 'smbd_audit:' in line:
                    parse_and_insert(line)
    except PermissionError:
        print(f"ERRO: Sem permissão para ler {LOG_FILE}.")

def parse_and_insert(line):
    try:
        timestamp = line.split(' ')[0]
        data_part = line.split('smbd_audit:')[1].strip()
        parts = data_part.split('|')
        
        if len(parts) >= 6:
            user = parts[0].strip().replace('AFM\\', '') # Limpa o domínio do usuário
            ip = parts[1].strip()
            share = parts[2].strip()
            operation = parts[3].strip()
            status = parts[4].strip()
            file_path = parts[5].strip()

            conn = sqlite3.connect(DB_NAME)
            c = conn.cursor()
            c.execute('''
                INSERT INTO audit_log (timestamp, user, ip, share, operation, status, file_path)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (timestamp, user, ip, share, operation, status, file_path))
            conn.commit()
            conn.close()
    except Exception as e:
        pass

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/dashboard')
def api_dashboard():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    
    # Top Usuários
    c.execute("SELECT user, COUNT(*) as qtd FROM audit_log GROUP BY user ORDER BY qtd DESC LIMIT 5")
    top_users = [{"user": row[0], "count": row[1]} for row in c.fetchall()]

    # Arquivos mais acessados/modificados (ignorando pastas genéricas)
    c.execute("SELECT file_path, COUNT(*) as qtd FROM audit_log WHERE operation != 'unlinkat' GROUP BY file_path ORDER BY qtd DESC LIMIT 5")
    top_files = [{"file": row[0].split('/')[-1], "count": row[1]} for row in c.fetchall()]

    # Apagados
    c.execute("SELECT user, COUNT(*) as qtd FROM audit_log WHERE operation = 'unlinkat' GROUP BY user ORDER BY qtd DESC LIMIT 5")
    top_deletes = [{"user": row[0], "count": row[1]} for row in c.fetchall()]

    conn.close()
    return jsonify({
        "top_users": top_users,
        "top_files": top_files,
        "top_deletes": top_deletes
    })

@app.route('/api/logs')
def api_logs():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    
    query = "SELECT timestamp, user, ip, operation, file_path FROM audit_log WHERE 1=1"
    params = []

    # Filtros de Pesquisa Avançada
    user_filter = request.args.get('user')
    ip_filter = request.args.get('ip')
    file_filter = request.args.get('file')
    date_from = request.args.get('date_from')
    date_to = request.args.get('date_to')
    op_filter = request.args.get('operation')
    limit = request.args.get('limit', 50)

    if user_filter:
        query += " AND user LIKE ?"
        params.append(f"%{user_filter}%")
    if ip_filter:
        query += " AND ip LIKE ?"
        params.append(f"%{ip_filter}%")
    if file_filter:
        query += " AND file_path LIKE ?"
        params.append(f"%{file_filter}%")
    if date_from:
        query += " AND timestamp >= ?"
        params.append(date_from)
    if date_to:
        query += " AND timestamp <= ?"
        params.append(date_to + "T23:59:59")
    if op_filter:
        query += " AND operation = ?"
        params.append(op_filter)

    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)

    c.execute(query, params)
    logs = [{"timestamp": r[0], "user": r[1], "ip": r[2], "op": r[3], "file": r[4]} for r in c.fetchall()]
    conn.close()
    
    return jsonify(logs)

if __name__ == '__main__':
    init_db()
    t = threading.Thread(target=tail_log, daemon=True)
    t.start()
    app.run(host='0.0.0.0', port=3000, debug=False)


