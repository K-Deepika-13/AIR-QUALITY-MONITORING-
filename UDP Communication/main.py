from flask import Flask, render_template, request, redirect, url_for, jsonify, flash
import threading, socket, os, argparse
from datetime import datetime
import sqlite3
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import google.generativeai as genai

# -------------------- APP SETUP --------------------
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", "supersecretkey")
bcrypt = Bcrypt(app)

# -------------------- GENAI CONFIG --------------------
FALLBACK_KEY = "AIzaSyBbT7lFb919QPHorLkSQMp0y3fmr_tv1Xs"  # ⚠️ Replace later with environment variable for security
_genai_key = os.environ.get("GEMINI_API_KEY") or FALLBACK_KEY

if _genai_key:
    try:
        genai.configure(api_key=_genai_key)
        print("[GenAI] Configured successfully.")
    except Exception as e:
        print(f"[GenAI] Configuration failed: {e}")
else:
    print("[GenAI] Warning: No API key found.")

# -------------------- LOGIN MANAGER --------------------
login_manager = LoginManager(app)
login_manager.login_view = "login"

# -------------------- UDP CONFIG --------------------
UDP_IP = ""
UDP_PORT = 4210
LOG_FILE = "AirQuality_Log.txt"

if not os.path.exists(LOG_FILE):
    with open(LOG_FILE, "w", encoding="utf-8") as f:
        f.write("Timestamp,Temperature,Humidity,Gas\n")

# -------------------- DATABASE --------------------
DB_NAME = "users.db"

def init_db():
    with sqlite3.connect(DB_NAME) as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT,
                        email TEXT UNIQUE,
                        password TEXT
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
        conn.commit()

init_db()

# -------------------- USER CLASS --------------------
class User(UserMixin):
    def __init__(self, id_, username, email, password):
        self.id = id_
        self.username = username
        self.email = email
        self.password = password

@login_manager.user_loader
def load_user(user_id):
    with sqlite3.connect(DB_NAME) as conn:
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE id=?", (user_id,))
        user = c.fetchone()
        if user:
            return User(*user)
        return None

# -------------------- UDP LISTENER --------------------
def udp_listener(bind_ip: str, bind_port: int):
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
            message = data.decode().strip()
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(f"{timestamp},{message}\n")
        except Exception as e:
            print(f"[UDP ERROR] {e}")
            break
    sock.close()

# -------------------- SENSOR READER --------------------
def read_sensor_data(limit=10):
    """Read the last N lines of sensor data and parse Temperature, Humidity, Gas."""
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
            # Support both formats: CSV and bracketed timestamp
            if line.startswith("[") and "]" in line:
                ts, rest = line.split("]", 1)
                ts = ts.strip("[] ")
                rest = rest.strip()
                parts = [p.strip() for p in rest.split(",") if p.strip()]
            else:
                parts = [p.strip() for p in line.split(",") if p.strip()]
                ts = parts[0]
                parts = parts[1:]
            t = h = g = status = None
            for p in parts:
                if ":" in p:
                    key, val = p.split(":", 1)
                    key, val = key.lower(), val.strip()
                    if "temp" in key:
                        t = float(val)
                    elif "hum" in key:
                        h = float(val)
                    elif "gas" in key:
                        g = float(val)
                    elif "status" in key:
                        status = val
                elif p.lower().startswith("t") and "c" in p.lower():
                    t = float(p.lower().replace("t", "").replace("c", "").strip())
                elif p.lower().startswith("h") and "%" in p:
                    h = float(p.lower().replace("h", "").replace("%", "").strip())
                elif p.lower().startswith("g"):
                    g = float(p.lower().replace("g", "").strip())
                elif p.lower().startswith("status"):
                    status = p.split(":",1)[-1].strip() if ":" in p else p.strip()
            data.append({
                "timestamp": ts,
                "Temperature": t,
                "Humidity": h,
                "Gas": g,
                "Status": status
            })
        except Exception as e:
            print(f"[Sensor Parse] Failed to parse line: {line} ({e})")
            continue
    return data

# -------------------- GENAI ANALYSIS --------------------
def _call_genai_analysis(disease: str, temp, hum, gas, manual: str = ""):
    # Status logic based on gas value
    status = None
    try:
        gval = float(gas) if gas is not None else None
        if gval is not None:
            if 180 <= gval < 380:
                status = "safe"
            elif 380 <= gval <= 1024:
                status = "unsafe"
            else:
                status = "normal"
    except Exception:
        pass

    # Prompt for AI
    prompt = f"""
    Analyze the health risk for '{disease or manual or 'unspecified'}' given:
    Temperature={temp}°C, Humidity={hum}%, Gas={gas} ppm.
    Status: {status or 'unknown'}.
    If status is 'safe', explain why and give general wellness advice.
    If status is 'unsafe', explain the risks and give specific health recommendations for air quality and gas exposure.
    Be concise and clear.
    """
    try:
        model = genai.GenerativeModel("gemini-2.5-flash-lite")
        response = model.generate_content(prompt)
        if response and hasattr(response, "text"):
            return response.text.strip()
    except Exception as e:
        print(f"[GenAI] Fallback due to error: {e}")

    # Fallback logic
    advice = []
    if status == "safe":
        advice.append("Gas levels are within a safe range. Maintain good ventilation and continue monitoring. General wellness: stay hydrated, ensure regular breaks, and keep the environment clean.")
    elif status == "unsafe":
        advice.append("Warning: Gas levels are unsafe! Increase ventilation immediately, avoid prolonged exposure, and seek medical attention if symptoms occur. Vulnerable individuals should evacuate the area.")
    else:
        advice.append("Unable to determine status. Please check sensor readings.")
    if temp and temp > 35:
        advice.append("High temperature — may cause heat stress.")
    if hum and hum > 80:
        advice.append("High humidity — can lead to discomfort or mold.")
    return " ".join(advice)

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

        if password != confirm:
            flash("Passwords do not match!")
            return redirect(url_for("register"))

        hashed = bcrypt.generate_password_hash(password).decode("utf-8")
        try:
            with sqlite3.connect(DB_NAME) as conn:
                c = conn.cursor()
                c.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                          (username, email, hashed))
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

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("home"))

@app.route("/dashboard")
@login_required
def dashboard():
    recent_data = read_sensor_data(limit=10)
    # Filter out entries with None for all values
    filtered_data = [d for d in recent_data if any([d.get("Temperature") is not None, d.get("Humidity") is not None, d.get("Gas") is not None])]
    latest = filtered_data[-1] if filtered_data else {"Temperature": "—", "Humidity": "—", "Gas": "—", "timestamp": "—"}
    with sqlite3.connect(DB_NAME) as conn:
        c = conn.cursor()
        c.execute("SELECT disease, temperature, humidity, gas, result, timestamp FROM analysis WHERE user_id=? ORDER BY id ASC LIMIT 10",
                  (current_user.id,))
        records = c.fetchall()
    return render_template("dashboard.html", user=current_user, records=records, sensor_data=filtered_data, latest=latest)

@app.route("/api/data")
def api_data():
    data = read_sensor_data(limit=10)
    filtered = [d for d in data if any([d.get("Temperature") is not None, d.get("Humidity") is not None, d.get("Gas") is not None])]
    latest = filtered[-1] if filtered else {"Temperature": "—", "Humidity": "—", "Gas": "—", "timestamp": "—"}
    return jsonify({"latest": latest, "recent": filtered})

@app.route("/api/analyze", methods=["POST"])
@login_required
def api_analyze():
    payload = request.get_json(silent=True) or {}
    disease = (payload.get("disease") or "").strip()
    sensor_data = read_sensor_data(limit=1)
    latest = sensor_data[0] if sensor_data else {"Temperature": None, "Humidity": None, "Gas": None}
    result = _call_genai_analysis(disease, latest["Temperature"], latest["Humidity"], latest["Gas"], manual=disease)
    # Determine status for storage
    status = None
    try:
        gval = float(latest["Gas"]) if latest["Gas"] is not None else None
        if gval is not None:
            if 180 <= gval < 380:
                status = "safe"
            elif 380 <= gval <= 1024:
                status = "unsafe"
    except Exception:
        pass
    # Always store an analysis, even if disease is empty
    store_disease = f"{disease} [{status}]" if status else (disease or "[normal]")
    with sqlite3.connect(DB_NAME) as conn:
        c = conn.cursor()
        c.execute("INSERT INTO analysis (user_id, disease, temperature, humidity, gas, result, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?)",
                  (current_user.id, store_disease, latest["Temperature"], latest["Humidity"], latest["Gas"], result, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        conn.commit()
    return jsonify({"result": result})

@app.route("/profile")
@login_required
def profile():
    return render_template("profile.html", user=current_user)

# -------------------- STARTUP --------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--no-udp", action="store_true")
    args = parser.parse_args()

    if not args.no_udp:
        t = threading.Thread(target=udp_listener, args=(UDP_IP, UDP_PORT), daemon=True)
        t.start()

    app.run(host="0.0.0.0", port=5000, debug=True)
