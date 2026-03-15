import os
import re
import json
import uuid
import zipfile
import tempfile
from datetime import datetime
from pathlib import Path
from flask import Flask, render_template, request, jsonify, send_from_directory

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['REPORTS_FOLDER'] = 'reports'

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['REPORTS_FOLDER'], exist_ok=True)

# ─── Security patterns (ported from scan_skills.py) ───────────────────────────

PATTERNS = {
    "sensitive_operations": {
        "label": "🔑 Sensitive Operations",
        "color": "#f59e0b",
        "rules": [
            (r'(?i)(api[_\-]?key|secret[_\-]?key|access[_\-]?token|password|passwd|credential)', "API key / credential reference"),
            (r'os\.environ\[|os\.getenv\(|process\.env\.', "Environment variable access"),
            (r'(?i)(\.env|dotenv|load_dotenv)', ".env file usage"),
            (r'(?i)(private[_\-]?key|rsa[_\-]?key|pem|pkcs)', "Private key reference"),
        ]
    },
    "network_activity": {
        "label": "🌐 Network Activity",
        "color": "#3b82f6",
        "rules": [
            (r'https?://[^\s\'"<>]{8,}', "External URL"),
            (r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', "IP address"),
            (r'(?i)(fetch\(|axios|requests\.get|requests\.post|urllib|httpx|aiohttp)', "HTTP request"),
            (r'(?i)(webhook|ngrok|tunnel)', "Webhook / tunnel"),
        ]
    },
    "obfuscation": {
        "label": "🎭 Obfuscation Signals",
        "color": "#8b5cf6",
        "rules": [
            (r'(?i)base64\.(b64encode|b64decode|encodebytes|decodebytes)', "Base64 encode/decode"),
            (r'\beval\s*\(', "eval() call"),
            (r'(?i)(exec\s*\(|compile\s*\()', "Dynamic code execution"),
            (r'__import__\s*\(', "Dynamic import"),
            (r'(?i)(\\x[0-9a-f]{2}){4,}', "Hex-encoded string"),
        ]
    },
    "package_installs": {
        "label": "📦 Package Installs",
        "color": "#10b981",
        "rules": [
            (r'(?i)\b(pip|pip3)\s+install\b', "pip install"),
            (r'(?i)\bnpm\s+install\b', "npm install"),
            (r'(?i)\bapt(?:-get)?\s+install\b', "apt install"),
            (r'(?i)\bbrew\s+install\b', "brew install"),
            (r'(?i)\b(yarn|pnpm)\s+add\b', "yarn/pnpm add"),
            (r'(?i)\bgem\s+install\b', "gem install"),
            (r'(?i)\bgo\s+install\b', "go install"),
        ]
    },
    "high_risk": {
        "label": "⚠️ High-Risk Patterns",
        "color": "#ef4444",
        "rules": [
            (r'(?i)(subprocess\.(run|Popen|call|check_output)|os\.system|os\.popen)', "Shell execution"),
            (r'(?i)(curl|wget)\s+.*\|\s*(bash|sh|python|perl)', "Download & execute"),
            (r'(?i)(chmod\s+[0-7]*7|chown\s+root)', "Permission escalation"),
            (r'(?i)(rm\s+-rf|shutil\.rmtree)', "Recursive delete"),
            (r'(?i)(shadow|/etc/passwd|/etc/hosts)', "System file access"),
        ]
    },
}

RISK_WEIGHTS = {
    "high_risk": 3,
    "obfuscation": 2,
    "sensitive_operations": 1,
    "network_activity": 1,
    "package_installs": 1,
}

# ─── Scanner logic ─────────────────────────────────────────────────────────────

def scan_text(content, filename):
    findings = []
    lines = content.splitlines()
    for category, meta in PATTERNS.items():
        for pattern, description in meta["rules"]:
            for lineno, line in enumerate(lines, 1):
                if re.search(pattern, line):
                    findings.append({
                        "category": category,
                        "label": meta["label"],
                        "color": meta["color"],
                        "description": description,
                        "line": lineno,
                        "snippet": line.strip()[:120],
                        "file": filename,
                    })
    return findings


def compute_risk(findings):
    score = 0
    for f in findings:
        score += RISK_WEIGHTS.get(f["category"], 1)
    if score == 0:
        return "Low", "#10b981"
    elif score <= 4:
        return "Medium", "#f59e0b"
    else:
        return "High", "#ef4444"


def scan_directory(root_path):
    results = []
    root = Path(root_path)
    text_exts = {'.py', '.js', '.ts', '.sh', '.bash', '.md', '.txt', '.yaml', '.yml', '.json', '.env', '.toml', '.cfg', '.ini', '.rb', '.go', '.java', '.cs'}

    for fpath in root.rglob('*'):
        if not fpath.is_file():
            continue
        if fpath.suffix.lower() not in text_exts:
            continue
        try:
            content = fpath.read_text(errors='replace')
        except Exception:
            continue
        rel = str(fpath.relative_to(root))
        findings = scan_text(content, rel)
        risk_level, risk_color = compute_risk(findings)

        # Category counts
        cat_counts = {}
        for f in findings:
            cat_counts[f["category"]] = cat_counts.get(f["category"], 0) + 1

        results.append({
            "file": rel,
            "findings": findings,
            "risk_level": risk_level,
            "risk_color": risk_color,
            "total": len(findings),
            "category_counts": cat_counts,
        })

    results.sort(key=lambda x: {"High": 0, "Medium": 1, "Low": 2}[x["risk_level"]])
    return results


def build_summary(results):
    total_files = len(results)
    total_findings = sum(r["total"] for r in results)
    high = sum(1 for r in results if r["risk_level"] == "High")
    medium = sum(1 for r in results if r["risk_level"] == "Medium")
    low = sum(1 for r in results if r["risk_level"] == "Low")

    # Overall score 0-100 (lower = safer)
    if total_files == 0:
        score = 100
    else:
        raw = sum(RISK_WEIGHTS.get(f["category"], 1)
                  for r in results for f in r["findings"])
        score = max(0, 100 - int(raw * 3))

    cat_totals = {}
    for r in results:
        for cat, cnt in r["category_counts"].items():
            cat_totals[cat] = cat_totals.get(cat, 0) + cnt

    return {
        "total_files": total_files,
        "total_findings": total_findings,
        "high": high,
        "medium": medium,
        "low": low,
        "security_score": score,
        "category_totals": cat_totals,
        "scanned_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }

# ─── Routes ───────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/scan', methods=['POST'])
def scan():
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    f = request.files['file']
    if f.filename == '':
        return jsonify({"error": "Empty filename"}), 400

    scan_id = uuid.uuid4().hex[:8]
    tmp_dir = tempfile.mkdtemp(prefix=f"scan_{scan_id}_")

    try:
        fname = f.filename
        save_path = os.path.join(tmp_dir, fname)
        f.save(save_path)

        # If zip, extract
        if fname.endswith('.zip'):
            with zipfile.ZipFile(save_path, 'r') as z:
                z.extractall(tmp_dir)
            os.remove(save_path)
            scan_root = tmp_dir
        else:
            # Single file scan
            scan_root = tmp_dir

        results = scan_directory(scan_root)
        summary = build_summary(results)

        report = {"scan_id": scan_id, "summary": summary, "results": results}

        # Save report
        report_path = os.path.join(app.config['REPORTS_FOLDER'], f"{scan_id}.json")
        with open(report_path, 'w') as rf:
            json.dump(report, rf, indent=2)

        return jsonify(report)

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/scan/text', methods=['POST'])
def scan_text_endpoint():
    data = request.get_json()
    if not data or 'content' not in data:
        return jsonify({"error": "No content"}), 400

    content = data['content']
    filename = data.get('filename', 'pasted_code.txt')
    scan_id = uuid.uuid4().hex[:8]

    findings = scan_text(content, filename)
    risk_level, risk_color = compute_risk(findings)
    cat_counts = {}
    for fnd in findings:
        cat_counts[fnd["category"]] = cat_counts.get(fnd["category"], 0) + 1

    result = {
        "file": filename,
        "findings": findings,
        "risk_level": risk_level,
        "risk_color": risk_color,
        "total": len(findings),
        "category_counts": cat_counts,
    }
    summary = build_summary([result])

    report = {"scan_id": scan_id, "summary": summary, "results": [result]}
    report_path = os.path.join(app.config['REPORTS_FOLDER'], f"{scan_id}.json")
    with open(report_path, 'w') as rf:
        json.dump(report, rf, indent=2)

    return jsonify(report)


@app.route('/report/<scan_id>')
def get_report(scan_id):
    path = os.path.join(app.config['REPORTS_FOLDER'], f"{scan_id}.json")
    if not os.path.exists(path):
        return jsonify({"error": "Report not found"}), 404
    with open(path) as f:
        return jsonify(json.load(f))


if __name__ == '__main__':
    #app.run(debug=True, port=5000)
    app.run(port=5000)
