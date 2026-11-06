import os
import time
import sqlite3
import threading
from flask import Flask, render_template, jsonify, request, Response

app = Flask(__name__)
DB_NAME = os.environ.get('SAMBA_AUDIT_DB', 'samba_audit.db')
LOG_FILE = os.environ.get('SAMBA_AUDIT_LOG', '/var/log/syslog')
BASE_DIR = os.environ.get('SAMBA_AUDIT_BASE_DIR', '/dados')
HOST = os.environ.get('SAMBA_AUDIT_HOST', '0.0.0.0')
PORT = int(os.environ.get('SAMBA_AUDIT_PORT', '3000'))

ACTION_LABELS = {
    'openat': 'Lendo',
    'renameat': 'Renomeando',
    'unlinkat': 'Apagando',
    'mkdirat': 'Criando pasta',
    'pwrite': 'Gravando',
    'pread': 'Lendo',
    'write': 'Gravando'
}

# 1. Inicialização do Banco de Dados
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

# 2. Leitor de Log em Tempo Real (Background Thread)
def tail_log():
    try:
        with open(LOG_FILE, 'r', errors='ignore') as f:
            f.seek(0, os.SEEK_END)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.3)
                    continue
                if 'smbd_audit:' in line:
                    parse_and_insert(line)
    except PermissionError:
        print(f"ERRO: Sem permissão para ler {LOG_FILE}. Execute o script como root (sudo).")

# 3. Processamento e Inserção no Banco
def parse_and_insert(line):
    try:
        timestamp = line.split(' ')[0]
        data_part = line.split('smbd_audit:')[1].strip()
        parts = data_part.split('|')
        
        if len(parts) >= 6:
            user = parts[0].strip()
            ip = parts[1].strip()
            share = parts[2].strip()
            operation = parts[3].strip()
            status = parts[4].strip()
            # Correção: quando há 7 colunas (ex: openat|ok|r|/dados/...), o caminho está no índice 6
            file_path = parts[6].strip() if len(parts) >= 7 else parts[5].strip()

            conn = sqlite3.connect(DB_NAME)
            c = conn.cursor()
            c.execute('''
                INSERT INTO audit_log (timestamp, user, ip, share, operation, status, file_path)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (timestamp, user, ip, share, operation, status, file_path))
            conn.commit()
            conn.close()
    except Exception as e:
        print(f"Erro ao processar linha: {e}")

# ================= ROTAS WEB ORIGINAIS ================= #

@app.route('/')
def index():
    return render_template('index.html')

_dash = {"data": {"top_users": [], "top_files": [], "top_deletes": []}}

def _calc_dashboard():
    # Roda em segundo plano: recalcula a cada 5 minutos, olhando só os últimos 2 milhões de registros
    while True:
        try:
            conn = sqlite3.connect(DB_NAME, timeout=60)
            c = conn.cursor()
            c.execute("SELECT MAX(id) FROM audit_log")
            min_id = (c.fetchone()[0] or 0) - 2000000

            c.execute("SELECT user, COUNT(*) q FROM audit_log WHERE id > ? GROUP BY user ORDER BY q DESC LIMIT 5", (min_id,))
            top_users = [{"user": r[0], "count": r[1]} for r in c.fetchall()]

            c.execute("SELECT file_path, COUNT(*) q FROM audit_log WHERE id > ? AND operation != 'unlinkat' AND file_path LIKE '/%' GROUP BY file_path ORDER BY q DESC LIMIT 5", (min_id,))
            top_files = [{"file": r[0], "count": r[1]} for r in c.fetchall()]

            c.execute("SELECT user, COUNT(*) q FROM audit_log WHERE id > ? AND operation = 'unlinkat' GROUP BY user ORDER BY q DESC LIMIT 5", (min_id,))
            top_deletes = [{"user": r[0], "count": r[1]} for r in c.fetchall()]
            conn.close()

            _dash["data"] = {"top_users": top_users, "top_files": top_files, "top_deletes": top_deletes}
        except Exception as e:
            print(f"Erro ao calcular dashboard: {e}")
        time.sleep(300)

@app.route('/api/dashboard')
def api_dashboard():
    # Responde na hora com o último resultado calculado
    return jsonify(_dash["data"])

@app.route('/api/logs')
def api_logs():
    limit = request.args.get('limit', 50)
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT timestamp, user, ip, operation, file_path FROM audit_log ORDER BY id DESC LIMIT ?", (limit,))
    logs = [{"timestamp": r[0], "user": r[1], "ip": r[2], "op": r[3], "file": r[4]} for r in c.fetchall()]
    conn.close()
    return jsonify(logs)

# ================= NOVAS ROTAS DO CONECTOGRAMA 2D/3D ================= #

@app.route('/api/radar/dirs')
def api_radar_dirs():
    """Lista apenas os diretórios solicitados para evitar poluição visual."""
    setor_filtro = request.args.get('setor', '')
    caminhos = []
    setores = []

    if os.path.exists(BASE_DIR):
        try:
            for nome in sorted(os.listdir(BASE_DIR)):
                if nome.startswith('.'):
                    continue
                full_setor = os.path.join(BASE_DIR, nome)
                if os.path.isdir(full_setor):
                    setores.append(nome)
                    if not setor_filtro or setor_filtro == nome:
                        caminhos.append(full_setor)
                        # Só carrega subpastas iniciais se o usuário filtrou um setor específico
                        if setor_filtro == nome:
                            try:
                                subs = [
                                    d for d in sorted(os.listdir(full_setor))
                                    if not d.startswith('.') and os.path.isdir(os.path.join(full_setor, d))
                                ]
                                for s in subs[:25]:
                                    caminhos.append(os.path.join(full_setor, s))
                            except PermissionError:
                                pass
        except Exception:
            pass
    return jsonify({"setores": setores, "caminhos": caminhos})

@app.route('/api/radar/events')
def api_radar_events():
    """Retorna os novos eventos do banco SQLite a partir do último ID lido pelo navegador."""
    after_id = request.args.get('after_id', 0, type=int)
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()

    if after_id == 0:
        c.execute("SELECT MAX(id) FROM audit_log")
        row = c.fetchone()
        max_id = row[0] if row and row[0] else 0
        conn.close()
        return jsonify({"last_id": max_id, "events": []})

    c.execute('''
        SELECT id, user, ip, operation, file_path
        FROM audit_log
        WHERE id > ? AND file_path LIKE '/dados%'
        ORDER BY id ASC LIMIT 40
    ''', (after_id,))
    rows = c.fetchall()
    conn.close()

    eventos = []
    last_id = after_id
    for r in rows:
        last_id = r[0]
        caminho = r[4]
        partes = caminho.split('/')
        if len(partes) > 3 and '.' in partes[-1]:
            caminho = '/'.join(partes[:-1])

        eventos.append({
            "id": r[0],
            "usuario": r[1],
            "ip": r[2],
            "acao": ACTION_LABELS.get(r[3], r[3]),
            "caminho": caminho
        })

    return jsonify({"last_id": last_id, "events": eventos})

@app.route('/radar')
def radar_view():
    return Response(RADAR_HTML, mimetype='text/html', headers={'Cache-Control': 'no-store'})

RADAR_HTML = """<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Samba Audit - Conectograma 2D/3D</title>
    <style>
        * { box-sizing: border-box; }
        body {
            margin: 0; overflow: hidden;
            background-color: #050811;
            font-family: 'Segoe UI', system-ui, sans-serif;
            color: #e2e8f0;
        }
        #canvas-container { width: 100vw; height: 100vh; display: block; }
        #ui-overlay {
            position: absolute; top: 14px; left: 14px; z-index: 10;
            width: 350px; pointer-events: none;
        }
        .hud-panel {
            background: rgba(9, 14, 28, 0.9);
            border: 1px solid rgba(0, 243, 255, 0.3);
            border-radius: 10px; padding: 15px;
            backdrop-filter: blur(10px);
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.65);
            pointer-events: auto;
        }
        .top-bar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }
        h1 { margin: 0; font-size: 15px; color: #00f3ff; text-transform: uppercase; letter-spacing: 0.7px; }
        .btn-group { display: flex; gap: 6px; }
        .btn {
            background: rgba(0, 243, 255, 0.12);
            border: 1px solid #00f3ff; color: #00f3ff;
            padding: 5px 10px; border-radius: 6px;
            font-size: 11px; font-weight: 600; cursor: pointer;
            text-decoration: none;
        }
        .btn:hover { background: #00f3ff; color: #050811; }
        .filters {
            display: grid; grid-template-columns: 1fr 1fr; gap: 8px;
            margin-bottom: 10px; padding: 8px;
            background: rgba(255,255,255,0.03); border-radius: 6px;
        }
        .filters label { font-size: 10px; color: #94a3b8; display: block; margin-bottom: 3px; }
        .filters select {
            width: 100%; background: #0f172a; color: #f8fafc;
            border: 1px solid #334155; border-radius: 4px;
            padding: 4px 6px; font-size: 11px;
        }
        .legend {
            display: flex; justify-content: space-between;
            font-size: 11px; margin-bottom: 10px; padding-bottom: 8px;
            border-bottom: 1px solid rgba(255,255,255,0.08);
        }
        .legend span { display: flex; align-items: center; gap: 5px; }
        .dot-leg { width: 8px; height: 8px; border-radius: 50%; display: inline-block; }
        #activity-log {
            max-height: 210px; overflow-y: auto;
            font-family: Consolas, monospace; font-size: 11px;
            display: flex; flex-direction: column; gap: 5px;
        }
        .log-item {
            background: rgba(255, 255, 255, 0.04);
            padding: 6px 8px; border-left: 3px solid #00f3ff; border-radius: 3px;
            word-break: break-all; cursor: pointer;
        }
        .log-item:hover { background: rgba(0, 243, 255, 0.1); }
        .log-user { color: #f472b6; font-weight: bold; }
        .log-action { color: #34d399; }
        #controls-hint {
            position: absolute; bottom: 14px; right: 14px;
            background: rgba(9, 14, 28, 0.88); padding: 8px 12px;
            border-radius: 8px; font-size: 11px;
            border: 1px solid rgba(255, 255, 255, 0.12); pointer-events: none;
        }
    </style>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/three@0.128.0/examples/js/controls/OrbitControls.js"></script>
</head>
<body>
    <div id="ui-overlay">
        <div class="hud-panel">
            <div class="top-bar">
                <h1>Conectograma Samba</h1>
                <div class="btn-group">
                    <button id="toggle-view" class="btn">Modo: 2D</button>
                    <a href="/" class="btn">⬅ Painel</a>
                </div>
            </div>

            <div class="filters">
                <div>
                    <label>Filtrar Setor (/dados):</label>
                    <select id="sector-filter">
                        <option value="">Todos (Visão Geral)</option>
                    </select>
                </div>
                <div>
                    <label>Nível Máx. de Pastas:</label>
                    <select id="depth-filter">
                        <option value="1">Apenas Setores (Limpo)</option>
                        <option value="2" selected>Setores + 1 Subnível</option>
                        <option value="3">Até 3 Níveis</option>
                    </select>
                </div>
            </div>

            <div class="legend">
                <span><i class="dot-leg" style="background:#00f3ff"></i> /dados</span>
                <span><i class="dot-leg" style="background:#3b82f6"></i> Setores</span>
                <span><i class="dot-leg" style="background:#f59e0b"></i> Subpastas</span>
                <span><i class="dot-leg" style="background:#ec4899"></i> Usuários</span>
            </div>
            <div id="activity-log"></div>
        </div>
    </div>

    <div id="controls-hint">
        🖱️ Arraste para mover | Scroll: Zoom | Clique em um log para focar no setor
    </div>

    <div id="canvas-container"></div>

    <script>
        const container = document.getElementById('canvas-container');
        const scene = new THREE.Scene();
        const camera = new THREE.PerspectiveCamera(48, window.innerWidth / window.innerHeight, 1, 3000);
        const renderer = new THREE.WebGLRenderer({ antialias: true });
        renderer.setSize(window.innerWidth, window.innerHeight);
        renderer.setPixelRatio(window.devicePixelRatio);
        container.appendChild(renderer.domElement);

        const controls = new THREE.OrbitControls(camera, renderer.domElement);
        controls.enableDamping = true;
        controls.dampingFactor = 0.08;

        scene.add(new THREE.AmbientLight(0xffffff, 0.95));
        const dirLight = new THREE.DirectionalLight(0xffffff, 0.5);
        dirLight.position.set(50, 150, 50);
        scene.add(dirLight);

        let is2D = true;
        let maxDepth = 2;
        let currentSector = '';

        const ringRadii = [0, 42, 82, 118, 155];
        ringRadii.slice(1).forEach((r, idx) => {
            const geo = new THREE.RingGeometry(r - 0.2, r + 0.2, 128);
            geo.rotateX(-Math.PI / 2);
            const mat = new THREE.MeshBasicMaterial({
                color: idx === 3 ? 0xec4899 : 0x1e293b,
                side: THREE.DoubleSide, transparent: true, opacity: idx === 3 ? 0.25 : 0.55
            });
            scene.add(new THREE.Mesh(geo, mat));
        });

        function createLabel(text, textColor = '#f8fafc', bgColor = 'rgba(15, 23, 42, 0.88)', fontSize = 26) {
            const canvas = document.createElement('canvas');
            const ctx = canvas.getContext('2d');
            canvas.width = 512; canvas.height = 96;
            ctx.font = `bold ${fontSize}px Segoe UI, sans-serif`;
            const cleanText = text.length > 22 ? text.slice(0, 20) + '…' : text;
            const w = ctx.measureText(cleanText).width + 26;

            ctx.fillStyle = bgColor;
            ctx.strokeStyle = textColor;
            ctx.lineWidth = 2;
            ctx.beginPath();
            ctx.roundRect(256 - w / 2, 20, w, 50, 8);
            ctx.fill(); ctx.stroke();

            ctx.fillStyle = textColor;
            ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
            ctx.fillText(cleanText, 256, 46);

            const texture = new THREE.CanvasTexture(canvas);
            const mat = new THREE.SpriteMaterial({ map: texture, transparent: true, depthTest: false });
            const sprite = new THREE.Sprite(mat);
            sprite.scale.set(15, 2.8, 1);
            return sprite;
        }

        let treeNodes = {};
        const structuralLines = [];
        const usersMap = {};
        const activeBeams = [];

        function clearGraph() {
            Object.values(treeNodes).forEach(n => scene.remove(n.group));
            structuralLines.forEach(l => { scene.remove(l); l.geometry.dispose(); });
            structuralLines.length = 0;
            treeNodes = {};
            treeNodes['/dados'] = {
                path: '/dados', name: '/dados', depth: 0, children: [],
                group: createVisualNode('/dados', 0)
            };
        }

        function createVisualNode(name, depth) {
            const group = new THREE.Group();
            const geo = depth === 0 ? new THREE.SphereGeometry(3.2, 24, 24)
                      : depth === 1 ? new THREE.CylinderGeometry(2.0, 2.0, 1.2, 6)
                      : new THREE.SphereGeometry(1.3, 16, 16);
            const colorHex = depth === 0 ? 0x00f3ff : (depth === 1 ? 0x3b82f6 : 0xf59e0b);
            const labelColor = depth === 0 ? '#00f3ff' : (depth === 1 ? '#60a5fa' : '#fbbf24');

            const mat = new THREE.MeshStandardMaterial({ color: colorHex, roughness: 0.3 });
            const mesh = new THREE.Mesh(geo, mat);
            mesh.userData.origColor = colorHex;
            group.add(mesh);

            const label = createLabel(name, labelColor);
            label.position.set(0, 2.6, 0);
            group.add(label);

            scene.add(group);
            return group;
        }

        function ensureFolderPath(rawPath, skipLayout = false) {
            const parts = rawPath.split('/').filter(Boolean);
            if (parts.length === 0 || parts[0] !== 'dados') return treeNodes['/dados'];
            if (currentSector && parts[1] && parts[1] !== currentSector) return null;

            const cappedParts = parts.slice(0, 1 + maxDepth);
            let currentPath = '/dados';
            let parentObj = treeNodes['/dados'];
            let addedNew = false;

            for (let i = 1; i < cappedParts.length; i++) {
                const partName = cappedParts[i];
                currentPath += '/' + partName;

                if (!treeNodes[currentPath]) {
                    const newObj = {
                        path: currentPath, name: partName, depth: i,
                        parent: parentObj, children: [],
                        group: createVisualNode(partName, i)
                    };
                    treeNodes[currentPath] = newObj;
                    parentObj.children.push(newObj);
                    addedNew = true;
                }
                parentObj = treeNodes[currentPath];
            }

            if (addedNew && !skipLayout) recalculateTreeLayout();
            return parentObj;
        }

        function recalculateTreeLayout() {
            structuralLines.forEach(l => { scene.remove(l); l.geometry.dispose(); });
            structuralLines.length = 0;

            const root = treeNodes['/dados'];
            if (!root) return;
            root.group.position.set(0, 0, 0);

            function layoutSubtree(node, startAngle, endAngle) {
                const count = node.children.length;
                if (count === 0) return;

                const step = (endAngle - startAngle) / count;
                node.children.forEach((child, index) => {
                    const a0 = startAngle + index * step;
                    const a1 = a0 + step;
                    const midAngle = (a0 + a1) / 2;

                    // Alterna levemente o raio quando há muitas pastas lado a lado para os textos nunca colidirem
                    const baseR = ringRadii[Math.min(child.depth, 3)];
                    const stagger = count > 8 ? ((index % 2) * 8 - 4) : 0;
                    const r = baseR + stagger;
                    const yPos = is2D ? 0 : -child.depth * 8;

                    child.group.position.set(Math.cos(midAngle) * r, yPos, Math.sin(midAngle) * r);

                    const lineGeo = new THREE.BufferGeometry().setFromPoints([
                        node.group.position.clone(), child.group.position.clone()
                    ]);
                    const lineMat = new THREE.LineBasicMaterial({
                        color: child.depth === 1 ? 0x3b82f6 : 0x475569,
                        transparent: true, opacity: 0.45
                    });
                    const line = new THREE.Line(lineGeo, lineMat);
                    scene.add(line);
                    structuralLines.push(line);

                    layoutSubtree(child, a0, a1);
                });
            }

            layoutSubtree(root, 0, Math.PI * 2);

            const userKeys = Object.keys(usersMap);
            userKeys.forEach((u, idx) => {
                const angle = (idx / Math.max(1, userKeys.length)) * Math.PI * 2;
                const r = ringRadii[4];
                usersMap[u].position.set(Math.cos(angle) * r, is2D ? 0 : 18, Math.sin(angle) * r);
            });
        }

        function getOrCreateUser(username) {
            if (usersMap[username]) return usersMap[username];
            const group = new THREE.Group();
            const geo = new THREE.OctahedronGeometry(2.0, 0);
            const mat = new THREE.MeshStandardMaterial({ color: 0xec4899, roughness: 0.2 });
            group.add(new THREE.Mesh(geo, mat));

            const shortName = username.includes('\\\\') ? username.split('\\\\')[1] : username;
            const label = createLabel(shortName, '#f472b6', 'rgba(45, 10, 35, 0.92)');
            label.position.set(0, 2.8, 0);
            group.add(label);

            scene.add(group);
            usersMap[username] = group;
            recalculateTreeLayout();
            return group;
        }

        function triggerActivity(ev) {
            const targetNode = ensureFolderPath(ev.caminho);
            if (!targetNode) return;
            const userGroup = getOrCreateUser(ev.usuario);

            const isDel = ev.acao.includes('Apagando');
            const isWrite = ev.acao.includes('Gravando') || ev.acao.includes('Criando');
            const color = isDel ? 0xef4444 : (isWrite ? 0x10b981 : 0x00f3ff);

            const mid = userGroup.position.clone().lerp(targetNode.group.position, 0.5);
            mid.y += is2D ? 0.5 : 20;

            const curve = new THREE.QuadraticBezierCurve3(userGroup.position.clone(), mid, targetNode.group.position.clone());
            const geo = new THREE.BufferGeometry().setFromPoints(curve.getPoints(28));
            const mat = new THREE.LineBasicMaterial({ color: color, transparent: true, opacity: 1.0 });
            const line = new THREE.Line(geo, mat);
            scene.add(line);
            activeBeams.push({ line, mat, life: 1.0 });

            const mesh = targetNode.group.children[0];
            if (mesh && mesh.material) {
                mesh.material.color.setHex(0x00f3ff);
                targetNode.group.scale.set(1.5, 1.5, 1.5);
                setTimeout(() => {
                    targetNode.group.scale.set(1, 1, 1);
                    mesh.material.color.setHex(mesh.userData.origColor);
                }, 500);
            }

            const logContainer = document.getElementById('activity-log');
            const item = document.createElement('div');
            item.className = 'log-item';
            item.innerHTML = `<span class="log-user">${ev.usuario}</span> • <span class="log-action">${ev.acao}</span><br><small style="color:#94a3b8">${ev.caminho}</small>`;
            item.onclick = () => {
                const parts = ev.caminho.split('/').filter(Boolean);
                if (parts.length >= 2 && parts[0] === 'dados') {
                    document.getElementById('sector-filter').value = parts[1];
                    currentSector = parts[1];
                    loadDirectories();
                }
            };
            logContainer.prepend(item);
            if (logContainer.children.length > 8) logContainer.lastChild.remove();
        }

        function applyCameraMode() {
            const toggleBtn = document.getElementById('toggle-view');
            if (is2D) {
                toggleBtn.innerText = 'Mudar p/ 3D';
                camera.position.set(0, 260, 0.01);
                controls.target.set(0, 0, 0);
                controls.enableRotate = false;
                controls.mouseButtons = { LEFT: THREE.MOUSE.PAN, MIDDLE: THREE.MOUSE.DOLLY, RIGHT: THREE.MOUSE.PAN };
            } else {
                toggleBtn.innerText = 'Mudar p/ 2D';
                camera.position.set(0, 140, 190);
                controls.target.set(0, 0, 0);
                controls.enableRotate = true;
                controls.mouseButtons = { LEFT: THREE.MOUSE.ROTATE, MIDDLE: THREE.MOUSE.DOLLY, RIGHT: THREE.MOUSE.PAN };
            }
            controls.update();
            recalculateTreeLayout();
        }

        document.getElementById('toggle-view').addEventListener('click', () => {
            is2D = !is2D;
            applyCameraMode();
        });

        document.getElementById('sector-filter').addEventListener('change', (e) => {
            currentSector = e.target.value;
            loadDirectories();
        });

        document.getElementById('depth-filter').addEventListener('change', (e) => {
            maxDepth = parseInt(e.target.value, 10);
            loadDirectories();
        });

        async function loadDirectories() {
            clearGraph();
            const res = await fetch('/api/radar/dirs?setor=' + encodeURIComponent(currentSector));
            const data = await res.json();

            const select = document.getElementById('sector-filter');
            if (select.options.length === 1 && data.setores) {
                data.setores.forEach(s => {
                    const opt = document.createElement('option');
                    opt.value = s; opt.innerText = s;
                    select.appendChild(opt);
                });
            }

            data.caminhos.forEach(p => ensureFolderPath(p, true));
            recalculateTreeLayout();
        }

        let lastEventId = 0;
        async function pollEvents() {
            try {
                const res = await fetch('/api/radar/events?after_id=' + lastEventId);
                const data = await res.json();
                if (data.last_id) lastEventId = data.last_id;
                if (data.events && data.events.length) {
                    data.events.forEach(ev => triggerActivity(ev));
                }
            } catch (e) {}
            setTimeout(pollEvents, 1000);
        }

        applyCameraMode();
        loadDirectories();
        pollEvents();

        function animate() {
            requestAnimationFrame(animate);
            for (let i = activeBeams.length - 1; i >= 0; i--) {
                const b = activeBeams[i];
                b.life -= 0.016;
                if (b.life <= 0) {
                    scene.remove(b.line); b.line.geometry.dispose(); b.mat.dispose();
                    activeBeams.splice(i, 1);
                } else {
                    b.mat.opacity = b.life;
                }
            }
            controls.update();
            renderer.render(scene, camera);
        }
        animate();

        window.addEventListener('resize', () => {
            camera.aspect = window.innerWidth / window.innerHeight;
            camera.updateProjectionMatrix();
            renderer.setSize(window.innerWidth, window.innerHeight);
        });
    </script>
</body>
</html>
"""

if __name__ == '__main__':
    init_db()
    t = threading.Thread(target=tail_log, daemon=True)
    t.start()
    threading.Thread(target=_calc_dashboard, daemon=True).start()
    app.run(host=HOST, port=PORT, debug=False)
