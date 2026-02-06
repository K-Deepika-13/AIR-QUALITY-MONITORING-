from flask import Flask, render_template, request, redirect, url_for, jsonify, flash
import json
import smtplib, ssl
from email.message import EmailMessage
import requests
from flask_mail import Mail, Message
import os
import threading, socket, argparse, time
from datetime import datetime
import concurrent.futures
import sqlite3
import base64
import mimetypes
from werkzeug.utils import secure_filename
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import google.generativeai as genai

# -------------------- APP SETUP --------------------
app = Flask(__name__, template_folder="templates")
app.debug = os.environ.get("FLASK_DEBUG", "1").lower() in {"1", "true", "yes", "on"}
app.secret_key = os.environ.get("FLASK_SECRET", "supersecretkey")

# -------------------- MAIL CONFIG --------------------
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'keerthikulandhaivel308@gmail.com'
app.config['MAIL_PASSWORD'] = 'kyvg qesm pkhj fsin'  # Gmail App Password
app.config['MAIL_DEFAULT_SENDER'] = 'bdgk2027@gmail.com'

mail = Mail(app)

# 4 recipients for all air quality alerts
ALERT_RECIPIENTS = [
    'bharathi39506@gmail.com',
    'deepikadkps@gmail.com',
    'gowshikadevaraju@gmail.com',
    'kulandhaivelkeerthi@gmail.com'
]

# -------------------- EMAIL SENDER --------------------
def send_email(to_addr, subject, body, from_addr=None, timeout=15):
    """Send an email to one or multiple recipients using Flask-Mail."""
    try:
        # Normalize recipients
        if isinstance(to_addr, str):
            recipients = [a.strip() for a in to_addr.replace(";", ",").split(",") if a.strip()]
        elif isinstance(to_addr, (list, tuple)):
            recipients = [a.strip() for a in to_addr if a.strip()]
        else:
            recipients = []

        if not recipients:
            print("[Email] No valid recipients found.")
            return False, "No recipients."

        from_addr = from_addr or app.config.get('MAIL_DEFAULT_SENDER')

        with app.app_context():
            msg = Message(subject=subject, sender=from_addr, recipients=recipients, body=body)
            mail.send(msg)
            print(f"[Email] ✅ Sent to: {', '.join(recipients)}")
            return True, f"Sent to {', '.join(recipients)}"
    except Exception as e:
        print(f"[Email] ❌ Failed to send: {e}")
        return False, str(e)

# -------------------- OTHER CONFIG --------------------
bcrypt = Bcrypt(app)

# GENAI CONFIG
FALLBACK_KEY = "AIzaSyBbT7lFb919QPHorLkSQMp0y3fmr_tv1Xs"
_genai_key = os.environ.get("GEMINI_API_KEY") or FALLBACK_KEY
try:
    genai.configure(api_key=_genai_key)
    print("[GenAI] Configured successfully.")
except Exception as e:
    print(f"[GenAI] Configuration failed: {e}")

login_manager = LoginManager(app)
login_manager.login_view = "login"

UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 20 * 1024 * 1024
ALLOWED_REPORT_EXTENSIONS = {"pdf", "png", "jpg", "jpeg"}

# UDP
UDP_IP = ""
UDP_PORT = 4210
LOG_FILE = "AirQuality_Log.txt"
NOMINATIM_BASE = "https://nominatim.openstreetmap.org"
NOMINATIM_HEADERS = {
    "User-Agent": os.environ.get("NOMINATIM_UA", "AirQualityDashboard/1.0 (bdgk2027@gmail.com)")
}

AUTO_ALERT_THRESHOLD = float(os.environ.get("AQ_ALERT_THRESHOLD", 380))
AUTO_ALERT_COOLDOWN_SEC = int(os.environ.get("AQ_ALERT_COOLDOWN", 300))
AUTO_ALERT_POLL_INTERVAL = int(os.environ.get("AQ_ALERT_POLL_INTERVAL", 30))
_last_auto_alert_signature = None
_last_auto_alert_time = 0
auto_alert_lock = threading.Lock()

if not os.path.exists(LOG_FILE):
    with open(LOG_FILE, "w", encoding="utf-8") as f:
        f.write("Timestamp,Temperature,Humidity,Gas\n")

# DATABASE
DB_NAME = "users.db"

def init_db():
    with sqlite3.connect(DB_NAME) as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT,
                        email TEXT UNIQUE,
                        password TEXT,
                        age INTEGER,
                        disease1 TEXT,
                        disease2 TEXT,
                        disease3 TEXT,
                        disease4 TEXT,
                        disease5 TEXT
                    )''')
        c.execute('''CREATE TABLE IF NOT EXISTS analysis (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER,
                        disease TEXT,
                        temperature REAL,
                        humidity REAL,
                        gas REAL,
                        result TEXT,
                        timestamp TEXT
                    )''')
        c.execute('''CREATE TABLE IF NOT EXISTS health_reports (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER,
                        filename TEXT,
                        original_name TEXT,
                        mime_type TEXT,
                        ai_summary TEXT,
                        created_at TEXT
                    )''')
        conn.commit()

init_db()

# Ensure columns exist
def ensure_user_columns():
    cols_needed = {
        'age': 'INTEGER',
        'disease1': 'TEXT',
        'disease2': 'TEXT',
        'disease3': 'TEXT',
        'disease4': 'TEXT',
        'disease5': 'TEXT'
    }
    with sqlite3.connect(DB_NAME) as conn:
        c = conn.cursor()
        c.execute("PRAGMA table_info(users)")
        existing = [r[1] for r in c.fetchall()]
        for col, ctype in cols_needed.items():
            if col not in existing:
                try:
                    c.execute(f"ALTER TABLE users ADD COLUMN {col} {ctype}")
                except Exception:
                    pass
        conn.commit()

ensure_user_columns()

# USER CLASS
class User(UserMixin):
    def __init__(self, id_, username, email, password, age=None, disease1=None, disease2=None, disease3=None, disease4=None, disease5=None):
        self.id = id_
        self.username = username
        self.email = email
        self.password = password
        try:
            self.age = int(age) if age is not None else None
        except Exception:
            self.age = None
        self.disease1 = disease1
        self.disease2 = disease2
        self.disease3 = disease3
        self.disease4 = disease4
        self.disease5 = disease5

    def health_conditions(self):
        fields = []
        for attr in ("disease1", "disease2", "disease3", "disease4", "disease5"):
            val = getattr(self, attr, None)
            if val:
                val = str(val).strip()
                if val:
                    fields.append(val)
        return fields

@login_manager.user_loader
def load_user(user_id):
    with sqlite3.connect(DB_NAME) as conn:
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE id=?", (user_id,))
        user = c.fetchone()
        if user:
            return User(*user)
        return None


def describe_conditions(user):
    if not user:
        return []
    try:
        return user.health_conditions()
    except Exception:
        return []


def classify_gas_status(gas_value):
    try:
        g = float(gas_value)
    except (TypeError, ValueError):
        return "unknown"
    if 180 <= g < 380:
        return "safe"
    if 380 <= g <= 1024:
        return "unsafe"
    return "normal"


def build_health_risk_message(status, gas_value, conditions):
    msg = []
    status = (status or "unknown").lower()
    severity = {
        "unsafe": "critical",
        "normal": "moderate",
        "safe": "stable"
    }.get(status, "unknown")
    if status == "unsafe":
        msg.append("High pollution detected. Stay indoors, improve ventilation, and avoid strenuous activity.")
    elif status == "safe":
        msg.append("Air quality is acceptable. Continue routine monitoring and hydration.")
    else:
        msg.append("Air quality is stable. Maintain airflow and keep tracking readings.")
    lower_conditions = [c.lower() for c in conditions]
    if any("asthma" in c or "bronch" in c for c in lower_conditions):
        if status == "unsafe":
            msg.append("Asthma alert: conditions are critical because smoke and gas accumulation can trigger attacks. Use inhalers, wear an N95 mask, and avoid outdoor exposure.")
        else:
            msg.append("Asthma caution: keep inhalers nearby and limit exposure to dust or fumes.")
    if any("copd" in c or "lung" in c for c in lower_conditions):
        msg.append(f"Lung condition warning: {severity.capitalize()} irritation expected. Practice pursed-lip breathing and stay in well-ventilated rooms.")
    if any("heart" in c or "cardio" in c for c in lower_conditions):
        msg.append(f"Cardiac advisory: {severity} stress on the cardiovascular system. Rest often, avoid exertion, and monitor symptoms.")
    if any("allergy" in c or "sinus" in c for c in lower_conditions):
        msg.append("Allergy warning: airborne pollutants may inflame sinuses. Use antihistamines and keep air purifiers on.")
    if any("preg" in c for c in lower_conditions):
        msg.append("Pregnancy note: stay hydrated, remain indoors during peak pollution, and consult a physician if discomfort occurs.")
    if not msg:
        return "General wellness guidance applies."
    return " ".join(msg)


def compose_analysis_text(status, latest, ai_text, risk_text, conditions):
    cond = ", ".join(conditions) if conditions else "None reported"
    temp = latest.get("Temperature")
    hum = latest.get("Humidity")
    gas = latest.get("Gas")
    temp_disp = f"{temp}°C" if temp is not None else "—"
    hum_disp = f"{hum}%" if hum is not None else "—"
    gas_disp = f"{gas} ppm" if gas is not None else "—"
    return (
        f"Summary:\n"
        f"- Status: {status.upper()}\n"
        f"- Readings: Temp {temp_disp} | Humidity {hum_disp} | Gas {gas_disp}\n"
        f"User Health:\n"
        f"- Conditions: {cond}\n"
        f"Insights:\n{ai_text}\n"
        f"Personalized Guidance:\n- {risk_text}"
    )

def compose_auto_alert(latest, status):
    timestamp = latest.get("timestamp") or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    temp = latest.get("Temperature")
    hum = latest.get("Humidity")
    gas = latest.get("Gas")
    subject = f"Automatic Air Quality Alert ({(status or 'unknown').upper()})"
    body = f"""High pollution detected at {timestamp}.

Current Readings:
- Status: {(status or 'unknown').upper()}
- Gas Level: {gas if gas is not None else '—'} ppm (threshold {AUTO_ALERT_THRESHOLD} ppm)
- Temperature: {temp if temp is not None else '—'}°C
- Humidity: {hum if hum is not None else '—'}%

Recommended Actions:
- Limit outdoor exposure and ensure proper ventilation.
- Use protective masks if you must be outside.
- Monitor vulnerable individuals closely.

This notification was sent automatically when the pollution threshold was exceeded.

Sensor log reference: {latest.get('timestamp')} entry
"""
    return subject, body


def check_and_send_auto_alert(latest):
    global _last_auto_alert_signature, _last_auto_alert_time
    if not latest:
        return False
    gas = latest.get("Gas")
    status = classify_gas_status(gas)
    if gas is None:
        return False
    should_alert = gas >= AUTO_ALERT_THRESHOLD or status == "unsafe"
    if not should_alert:
        return False
    now = time.time()
    signature = (latest.get("timestamp"), gas, status)
    with auto_alert_lock:
        if _last_auto_alert_signature == signature and (now - _last_auto_alert_time) < AUTO_ALERT_COOLDOWN_SEC:
            return False
        if (now - _last_auto_alert_time) < AUTO_ALERT_COOLDOWN_SEC:
            return False
        subject, body = compose_auto_alert(latest, status)
        sent, info = send_email(ALERT_RECIPIENTS, subject, body)
        if sent:
            _last_auto_alert_signature = signature
            _last_auto_alert_time = now
            print(f"[AutoAlert] Notification sent for {signature}.")
        else:
            print(f"[AutoAlert] Failed to send: {info}")
        return sent

def auto_alert_monitor():
    print(f"[AutoAlert] Monitor active (threshold {AUTO_ALERT_THRESHOLD} ppm, cooldown {AUTO_ALERT_COOLDOWN_SEC}s)")
    while True:
        try:
            sensor_data = read_sensor_data(limit=1)
            if not sensor_data:
                continue
            latest = sensor_data[0]
            check_and_send_auto_alert(latest)
        except Exception as e:
            print(f"[AutoAlert] Error: {e}")
        finally:
            time.sleep(AUTO_ALERT_POLL_INTERVAL)

# -------------------- UDP LISTENER --------------------
def udp_listener(bind_ip, bind_port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((bind_ip, bind_port))
        print(f"[UDP] Listening on {bind_ip or '0.0.0.0'}:{bind_port}")
    except OSError as e:
        print(f"[UDP ERROR] could not bind: {e}")
        sock.close()
        return

    while True:
        try:
            data, _ = sock.recvfrom(1024)
        except Exception as e:
            print(f"[UDP ERROR] recv failed: {e}")
            continue
        try:
            message = data.decode(errors="ignore").strip()
        except Exception as e:
            print(f"[UDP ERROR] decode failed: {e}")
            continue
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(f"{timestamp},{message}\n")
        except Exception as e:
            print(f"[UDP ERROR] log write failed: {e}")
    sock.close()

# -------------------- SENSOR READER --------------------
def read_sensor_data(limit=10):
    if not os.path.exists(LOG_FILE):
        return []
    with open(LOG_FILE, "r", encoding="utf-8") as f:
        lines = [l.strip() for l in f.readlines() if l.strip()]
    if not lines:
        return []
    lines = lines[-limit:]
    data = []
    for line in lines:
        try:
            # Split by commas, first field is timestamp
            parts = [p.strip() for p in line.split(",") if p.strip()]
            ts = parts[0]
            parts = parts[1:]
            t = h = g = None
            # Handle several possible formats: "temp:25", "Temperature:25", or just numeric values
            for p in parts:
                lp = p.lower()
                # key:value form
                if ":" in p:
                    key, val = p.split(":", 1)
                    key = key.strip().lower()
                    val = val.strip()
                    try:
                        fv = float(val)
                    except Exception:
                        # try to extract digits
                        import re
                        m = re.search(r"[-+]?[0-9]*\.?[0-9]+", val)
                        fv = float(m.group(0)) if m else None
                    if "temp" in key or "temperature" in key:
                        t = fv
                    elif "hum" in key or "humidity" in key:
                        h = fv
                    elif "gas" in key:
                        g = fv
                else:
                    # value-only form, try to assign in order if numeric
                    try:
                        fv = float(p)
                        # assign to first empty slot (t, h, g)
                        if t is None:
                            t = fv
                        elif h is None:
                            h = fv
                        elif g is None:
                            g = fv
                    except Exception:
                        # attempt to extract number inside
                        import re
                        m = re.search(r"[-+]?[0-9]*\.?[0-9]+", p)
                        if m:
                            fv = float(m.group(0))
                            if t is None:
                                t = fv
                            elif h is None:
                                h = fv
                            elif g is None:
                                g = fv
            data.append({"timestamp": ts, "Temperature": t, "Humidity": h, "Gas": g})
        except Exception as e:
            print(f"[Sensor Parse] Failed to parse line: {line} ({e})")
            continue
    return data


def allowed_report_file(filename):
    return bool(filename and "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_REPORT_EXTENSIONS)


def infer_mime_type(filename, provided):
    if provided:
        return provided
    guess, _ = mimetypes.guess_type(filename)
    return guess or "application/octet-stream"


def analyze_health_report_bytes(file_bytes, mime_type):
    instructions = (
        "You are a clinical AI assistant. Review the attached health report and produce a concise summary with "
        "three sections: 1) Risk Summary, 2) Key Observations, 3) Follow-up Guidance. Highlight any alarming "
        "metrics or physician directives. Keep output under 160 words."
    )
    payload = [
        {
            "role": "user",
            "parts": [
                {"text": instructions},
                {
                    "inline_data": {
                        "mime_type": mime_type,
                        "data": base64.b64encode(file_bytes).decode("utf-8")
                    }
                }
            ]
        }
    ]
    try:
        model = genai.GenerativeModel("gemini-1.5-flash")
        response = model.generate_content(payload)
        if response and hasattr(response, "text"):
            return response.text.strip()
    except Exception as e:
        print(f"[GenAI Report] Error: {e}")
    return "No automated report summary available. Please review manually."

# -------------------- GENAI ANALYSIS --------------------
def _call_genai_analysis(disease, temp, hum, gas, manual="", health_notes=None):
    status = classify_gas_status(gas)
    health_notes = health_notes or []
    health_text = ", ".join(health_notes) if health_notes else "None reported"
    prompt = f"""
    Analyze air quality impact for '{disease or manual or 'unspecified'}'.
    Sensor readings:
      - Temperature: {temp}°C
      - Humidity: {hum}%
      - Gas: {gas} ppm
    Status bucket: {status}.
    User conditions: {health_text}.
    Provide:
      1. A short risk summary.
      2. Immediate actions.
      3. Preventive care guidance.
    Keep it under 120 words.
    """
    try:
        model = genai.GenerativeModel("gemini-2.5-flash-lite")
        response = model.generate_content(prompt)
        if response and hasattr(response, "text"):
            return response.text.strip()
    except Exception as e:
        print(f"[GenAI] Error: {e}")
    return "No AI insight available. Follow standard ventilation and hydration practices."

# -------------------- ROUTES --------------------
@app.route("/")
def home():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return render_template("home.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]
        confirm = request.form["confirm"]
        age = request.form.get("age") or None
        diseases_raw = request.form.get("diseases", "[]")
        if password != confirm:
            flash("Passwords do not match!")
            return redirect(url_for("register"))
        try:
            diseases_list = json.loads(diseases_raw)
            if not isinstance(diseases_list, list):
                diseases_list = []
        except Exception:
            diseases_list = []
        diseases_list = [str(d).strip() for d in diseases_list if str(d).strip()]
        diseases_list = diseases_list[:5]
        while len(diseases_list) < 5:
            diseases_list.append(None)
        disease_values = diseases_list
        hashed = bcrypt.generate_password_hash(password).decode("utf-8")
        try:
            with sqlite3.connect(DB_NAME) as conn:
                c = conn.cursor()
                c.execute("INSERT INTO users (username, email, password, age, disease1, disease2, disease3, disease4, disease5) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                          (username, email, hashed, int(age) if age else None, *disease_values))
                conn.commit()
            flash("Registration successful. Please log in.")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Email already registered.")
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        ident = request.form.get("username") or request.form.get("email")
        password = request.form.get("password")
        with sqlite3.connect(DB_NAME) as conn:
            c = conn.cursor()
            c.execute("SELECT * FROM users WHERE username=? OR email=?", (ident, ident))
            user = c.fetchone()
        if user and bcrypt.check_password_hash(user[3], password):
            login_user(User(*user))
            return redirect(url_for("dashboard"))
        flash("Invalid credentials.")
    return render_template("login.html")

@app.route("/dashboard")
@login_required
def dashboard():
    recent_data = read_sensor_data(limit=10)
    latest = recent_data[-1] if recent_data else {"Temperature": "—", "Humidity": "—", "Gas": "—", "timestamp": "—"}
    
    # Fetch all past analyses for the user
    records = []
    try:
        with sqlite3.connect(DB_NAME) as conn:
            c = conn.cursor()
            # Fetch all records, ordered by newest first
            c.execute("SELECT id, disease, temperature, humidity, gas, result, timestamp FROM analysis WHERE user_id=? ORDER BY id DESC", (current_user.id,))
            records = c.fetchall()
    except Exception as e:
        print(f"[Dashboard] DB error: {e}")
        
    return render_template("dashboard.html", user=current_user, sensor_data=recent_data, latest=latest, records=records)

@app.route('/api/auto_analyze', methods=['POST', 'GET'])
@login_required
def api_auto_analyze():
    sensor_data = read_sensor_data(limit=1)
    latest = sensor_data[0] if sensor_data else {"Temperature": None, "Humidity": None, "Gas": None}
    conditions = describe_conditions(current_user)
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
            future = ex.submit(_call_genai_analysis, "Air Quality", latest.get("Temperature"), latest.get("Humidity"), latest.get("Gas"), health_notes=conditions)
            try:
                ai_text = future.result(timeout=15)
            except concurrent.futures.TimeoutError:
                ai_text = "Analysis timed out. Please try again later."
    except Exception as e:
        print(f"[GenAI Async] Error: {e}")
        ai_text = "Unable to analyze due to internal error."

    status = classify_gas_status(latest.get("Gas"))
    risk_text = build_health_risk_message(status, latest.get("Gas"), conditions)
    formatted_result = compose_analysis_text(status or "unknown", latest, ai_text, risk_text, conditions)

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    analysis_details = {
        "status": (status or "unknown").upper(),
        "temperature": latest.get('Temperature'),
        "humidity": latest.get('Humidity'),
        "gas": latest.get('Gas'),
        "timestamp": timestamp,
        "conditions": conditions,
        "risk_text": risk_text,
        "ai_text": ai_text
    }

    subject = f"Air Quality Alert: {status.upper()}"
    cond_text = ", ".join(conditions) if conditions else "None reported"
    body = f"""Air Quality Report for {current_user.username or current_user.email}

Summary:
- Status: {status.upper()}
- AQI Indicator (Gas): {latest.get('Gas')} ppm
- Recorded at: {timestamp}

Sensors:
- Temperature: {latest.get('Temperature')}°C
- Humidity: {latest.get('Humidity')}%

User Health Notes:
- Conditions: {cond_text}

Personalized Risk:
{risk_text}

AI Insights:
{ai_text}

— Air Quality Monitoring Team
"""

    sent, info = send_email(ALERT_RECIPIENTS, subject, body)

    analyses = []
    try:
        with sqlite3.connect(DB_NAME) as conn:
            c = conn.cursor()
            c.execute(
                "INSERT INTO analysis (user_id, disease, temperature, humidity, gas, result, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (current_user.id, "Air Quality", latest.get('Temperature'), latest.get('Humidity'), latest.get('Gas'), formatted_result, timestamp)
            )
            conn.commit()
            aid = c.lastrowid
            analyses.append({
                "id": aid,
                "disease": "Air Quality",
                "temperature": latest.get('Temperature'),
                "humidity": latest.get('Humidity'),
                "gas": latest.get('Gas'),
                "status": status,
                "result": formatted_result,
                "risk": risk_text,
                "timestamp": timestamp,
                "details": analysis_details
            })
    except Exception as e:
        print(f"[Analysis DB] Failed to save analysis: {e}")

    return jsonify({"status": status, "analyses": analyses, "details": analysis_details, "email_sent": sent, "email_info": info})


# --- Small UI/API routes used by templates ---
@app.route('/api/data', methods=['GET'])
@login_required
def api_data():
    """Return latest sensor data used by the dashboard polling JS."""
    sensor_data = read_sensor_data(limit=10)
    latest = sensor_data[-1] if sensor_data else {"Temperature": None, "Humidity": None, "Gas": None, "timestamp": None}
    return jsonify({"latest": latest, "sensor_data": sensor_data})


@app.route('/api/health_reports', methods=['GET'])
@login_required
def list_health_reports():
    records = []
    try:
        with sqlite3.connect(DB_NAME) as conn:
            c = conn.cursor()
            c.execute("SELECT id, original_name, mime_type, ai_summary, created_at FROM health_reports WHERE user_id=? ORDER BY id DESC LIMIT 20", (current_user.id,))
            rows = c.fetchall()
            for r in rows:
                records.append({
                    "id": r[0],
                    "name": r[1],
                    "mime": r[2],
                    "summary": r[3],
                    "created_at": r[4]
                })
    except Exception as e:
        print(f"[HealthReports] fetch error: {e}")
    return jsonify({"reports": records})


@app.route('/api/health_reports', methods=['POST'])
@login_required
def upload_health_report():
    if 'report' not in request.files:
        return jsonify({"error": "missing_file"}), 400
    file = request.files['report']
    if file.filename == '':
        return jsonify({"error": "empty_filename"}), 400
    if not allowed_report_file(file.filename.lower()):
        return jsonify({"error": "unsupported_type"}), 400
    original_name = file.filename
    filename = secure_filename(f"{current_user.id}_{int(time.time())}_{original_name}")
    path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    try:
        file_bytes = file.read()
        with open(path, 'wb') as f:
            f.write(file_bytes)
    except Exception as e:
        print(f"[HealthReports] save error: {e}")
        return jsonify({"error": "save_failed"}), 500
    mime_type = infer_mime_type(original_name, file.mimetype)
    summary = analyze_health_report_bytes(file_bytes, mime_type)
    created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        with sqlite3.connect(DB_NAME) as conn:
            c = conn.cursor()
            c.execute("INSERT INTO health_reports (user_id, filename, original_name, mime_type, ai_summary, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                      (current_user.id, filename, original_name, mime_type, summary, created_at))
            conn.commit()
    except Exception as e:
        print(f"[HealthReports] insert error: {e}")
    return jsonify({"summary": summary, "created_at": created_at, "name": original_name})


@app.route('/api/geocode')
@login_required
def api_geocode():
    query = (request.args.get('q') or '').strip()
    if not query:
        return jsonify({"results": []})
    viewbox = request.args.get('viewbox')
    bounded = (request.args.get('bounded') or '').strip().lower()
    countrycodes = (request.args.get('countrycodes') or '').strip()
    params = {
        "format": "jsonv2",
        "q": query,
        "limit": 5,
        "addressdetails": 1
    }
    if viewbox:
        params['viewbox'] = viewbox
    if bounded in {"1", "true", "yes"}:
        params['bounded'] = 1
    if countrycodes:
        params['countrycodes'] = countrycodes
    try:
        resp = requests.get(f"{NOMINATIM_BASE}/search", params=params, headers=NOMINATIM_HEADERS, timeout=10)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        print(f"[Geocode] Error: {e}")
        return jsonify({"error": "lookup_failed"}), 502
    return jsonify({"results": data})


@app.route('/api/reverse_geocode')
@login_required
def api_reverse_geocode():
    try:
        lat = float(request.args.get('lat'))
        lon = float(request.args.get('lon'))
    except (TypeError, ValueError):
        return jsonify({"error": "invalid_coords"}), 400
    params = {
        "format": "jsonv2",
        "lat": lat,
        "lon": lon,
        "zoom": 14,
        "addressdetails": 1
    }
    try:
        resp = requests.get(f"{NOMINATIM_BASE}/reverse", params=params, headers=NOMINATIM_HEADERS, timeout=10)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        print(f"[ReverseGeocode] Error: {e}")
        return jsonify({"error": "lookup_failed"}), 502
    return jsonify({"result": data})


@app.route('/profile')
@login_required
def profile():
    """Render the user's profile and past analyses."""
    records = []
    try:
        with sqlite3.connect(DB_NAME) as conn:
            c = conn.cursor()
            c.execute("SELECT id, disease, temperature, humidity, gas, result, timestamp FROM analysis WHERE user_id=? ORDER BY id DESC LIMIT 200", (current_user.id,))
            records = c.fetchall()
    except Exception as e:
        print(f"[Profile] DB error: {e}")
    return render_template('profile.html', user=current_user, records=records)


@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    if request.method == 'POST':
        age = request.form.get('age') or None
        disease1 = request.form.get('disease1') or None
        disease2 = request.form.get('disease2') or None
        disease3 = request.form.get('disease3') or None
        disease4 = request.form.get('disease4') or None
        disease5 = request.form.get('disease5') or None
        try:
            with sqlite3.connect(DB_NAME) as conn:
                c = conn.cursor()
                c.execute("UPDATE users SET age=?, disease1=?, disease2=?, disease3=?, disease4=?, disease5=? WHERE id=?",
                          (int(age) if age else None, disease1, disease2, disease3, disease4, disease5, current_user.id))
                conn.commit()
            flash('Profile updated.')
        except Exception as e:
            print(f"[EditProfile] Error updating user: {e}")
            flash('Failed to update profile.')
        return redirect(url_for('profile'))
    return render_template('edit_profile.html', user=current_user)


@app.route('/delete_health', methods=['POST'])
@login_required
def delete_health():
    # expects a field param like disease1..disease5
    field = request.args.get('field') or request.form.get('field')
    allowed = {'disease1', 'disease2', 'disease3', 'disease4', 'disease5'}
    if not field or field not in allowed:
        flash('Invalid field.')
        return redirect(url_for('profile'))
    try:
        with sqlite3.connect(DB_NAME) as conn:
            c = conn.cursor()
            c.execute(f"UPDATE users SET {field}=NULL WHERE id=?", (current_user.id,))
            conn.commit()
        flash('Health entry removed.')
    except Exception as e:
        print(f"[DeleteHealth] Error: {e}")
        flash('Failed to remove health entry.')
    return redirect(url_for('profile'))


@app.route('/prune_analyses', methods=['POST'])
@login_required
def prune_analyses():
    # delete oldest N analyses for this user
    try:
        count = int(request.form.get('count', 50))
    except Exception:
        count = 50
    try:
        with sqlite3.connect(DB_NAME) as conn:
            c = conn.cursor()
            c.execute("SELECT id FROM analysis WHERE user_id=? ORDER BY id ASC LIMIT ?", (current_user.id, count))
            ids = [r[0] for r in c.fetchall()]
            if ids:
                placeholders = ','.join('?' for _ in ids)
                c.execute(f"DELETE FROM analysis WHERE id IN ({placeholders})", ids)
            conn.commit()
        flash('Old analyses removed.')
    except Exception as e:
        print(f"[Prune] Error: {e}")
        flash('Failed to prune analyses.')
    return redirect(url_for('dashboard'))


@app.route('/logout')
def logout():
    try:
        logout_user()
    except Exception:
        pass
    return redirect(url_for('home'))

# -------------------- STARTUP --------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--no-udp", action="store_true")
    parser.add_argument("--port", type=int, default=5000)
    args = parser.parse_args()

    should_start_background = (not app.debug) or os.environ.get("WERKZEUG_RUN_MAIN") == "true"

    if should_start_background and not args.no_udp:
        t = threading.Thread(target=udp_listener, args=(UDP_IP, UDP_PORT), daemon=True)
        t.start()

    if should_start_background:
        alert_thread = threading.Thread(target=auto_alert_monitor, daemon=True)
        alert_thread.start()

    app.run(host="0.0.0.0", port=args.port, debug=app.debug)
