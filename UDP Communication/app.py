from flask import Flask, render_template, jsonify
import threading
import socket
from datetime import datetime
import os
import argparse
import sys

# -------------------- FLASK APP SETUP --------------------
app = Flask(__name__)

# UDP Config (defaults)
UDP_IP = ""
UDP_PORT = 4210
LOG_FILE = "AirQuality_Log.txt"

# Make sure log file exists
if not os.path.exists(LOG_FILE):
    with open(LOG_FILE, "w") as f:
        f.write("Timestamp,Temperature,Humidity,Gas\n")

# -------------------- UDP LISTENER --------------------
def udp_listener(bind_ip: str, bind_port: int):
    """Continuously receive data from ESP8266 and save to text file."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # Allow address reuse to reduce bind errors when restarting quickly
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    except Exception:
        pass

    try:
        sock.bind((bind_ip, bind_port))
    except OSError as e:
        print(f"[UDP ERROR] Could not bind to {(bind_ip or '0.0.0.0', bind_port)}: {e}")
        sock.close()
        return

    print(f"[UDP] Listening on {bind_ip or '0.0.0.0'}:{bind_port} for ESP8266 data...")

    try:
        while True:
            try:
                data, addr = sock.recvfrom(1024)
            except OSError as e:
                print(f"[UDP ERROR] socket recv error: {e}")
                break

            try:
                message = data.decode().strip()
            except Exception:
                message = repr(data)

            # Expecting format: Temperature:25.4, Humidity:60, Gas:210
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"[UDP] {timestamp} <- {addr}: {message}")

            # Clean and save (append timestamp + message)
            try:
                with open(LOG_FILE, "a", encoding="utf-8") as f:
                    f.write(f"{timestamp},{message}\n")
            except Exception as e:
                print(f"[UDP ERROR] failed to write to log: {e}")

    except Exception as e:
        print(f"[UDP ERROR] {e}")
    finally:
        sock.close()

def parse_args():
    p = argparse.ArgumentParser(description="Flask dashboard + optional UDP listener for ESP8266 data")
    p.add_argument("--no-udp", dest="udp", action="store_false", help="Do not start the UDP listener (useful if another process listens)")
    p.add_argument("--udp-port", type=int, default=UDP_PORT, help="UDP port to bind to (default: 4210)")
    p.add_argument("--udp-ip", default=UDP_IP, help="UDP address to bind to (default: all interfaces)")
    return p.parse_args()


# NOTE: CLI parsing and starting the UDP listener happens when run as a script
# to avoid side-effects when importing this module in other code.

# -------------------- HELPER FUNCTIONS --------------------
def read_sensor_data(limit=20):
    """Read last N sensor records from text file."""
    if not os.path.exists(LOG_FILE):
        return []
    with open(LOG_FILE, "r", encoding="utf-8") as f:
        lines = [l.rstrip() for l in f.readlines() if l.strip()]

    data = []

    # look at last `limit` non-empty lines
    for line in lines[-limit:]:
        try:
            raw = line.strip()

            # Determine timestamp
            timestamp = None
            rest = None

            # Format 1: [YYYY-MM-DD HH:MM:SS] rest
            if raw.startswith("[") and "]" in raw:
                end = raw.find("]")
                timestamp = raw[1:end].strip()
                rest = raw[end+1:].lstrip()
            else:
                # Format 2: CSV-like: TIMESTAMP,rest
                if "," in raw and raw[:4].isdigit():
                    # split on first comma
                    timestamp, rest = raw.split(",", 1)
                    timestamp = timestamp.strip()
                    rest = rest.strip()
                else:
                    # unknown format: use whole line as rest, timestamp empty
                    rest = raw

            # Split fields by comma
            parts = [p.strip() for p in rest.split(",") if p.strip()]

            record = {"timestamp": timestamp or ""}

            # helper parsers
            def try_float(s):
                try:
                    return float(s)
                except Exception:
                    return None

            def try_int(s):
                try:
                    return int(float(s))
                except Exception:
                    return None

            for p in parts:
                # Normalize separators like 'Temperature:25.4' or 'T31.1C' or 'H66%'
                if ":" in p:
                    key, val = p.split(":", 1)
                    k = key.strip().lower()
                    v = val.strip()
                    if k.startswith("temp"):
                        fv = try_float(v)
                        if fv is not None:
                            record["Temperature"] = fv
                    elif k.startswith("humid"):
                        iv = try_int(v)
                        if iv is not None:
                            record["Humidity"] = iv
                    elif k.lower().startswith("gas"):
                        iv = try_int(v)
                        if iv is not None:
                            record["Gas"] = iv
                    else:
                        # store raw
                        record[key.strip()] = v
                else:
                    # patterns like T31.1C, H66%, G96 or Status:SAFE
                    pp = p.replace(" ", "")
                    # Temperature: T31.1C or 31.1C
                    if pp.upper().startswith("T") and pp.upper().endswith("C"):
                        num = pp[1:-1]
                        fv = try_float(num)
                        if fv is not None:
                            record["Temperature"] = fv
                    # Humidity: H66% or 66%
                    elif pp.upper().startswith("H") and pp.endswith("%"):
                        num = pp[1:-1] if pp.upper().startswith("H") else pp[:-1]
                        iv = try_int(num)
                        if iv is not None:
                            record["Humidity"] = iv
                    # Gas: G96 or G96ppm
                    elif pp.upper().startswith("G"):
                        num = pp[1:]
                        # strip non-digits
                        num = ''.join(ch for ch in num if (ch.isdigit() or ch == '.' or ch == '-'))
                        iv = try_int(num)
                        if iv is not None:
                            record["Gas"] = iv
                    else:
                        # other key=value or status strings
                        if ":" in p:
                            k, v = p.split(":", 1)
                            record[k.strip()] = v.strip()

            data.append(record)
        except Exception:
            continue

    return data

# -------------------- FLASK ROUTES --------------------
@app.route("/")
def dashboard():
    """Render HTML dashboard with recent data."""
    sensor_data = read_sensor_data()
    return render_template("dashboard.html", sensor_data=sensor_data)

@app.route("/api/data")
def api_data():
    """Return data as JSON for live updates."""
    sensor_data = read_sensor_data()
    return jsonify(sensor_data)

# -------------------- RUN FLASK SERVER --------------------
if __name__ == "__main__":
    # parse CLI args and optionally start UDP listener
    args = parse_args()
    if args.udp:
        udp_thread = threading.Thread(target=udp_listener, args=(args.udp_ip, args.udp_port), daemon=True)
        udp_thread.start()

    app.run(host="0.0.0.0", port=5000, debug=True)
