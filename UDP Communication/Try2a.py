import socket
import argparse
from datetime import datetime
import sys


def parse_args():
    p = argparse.ArgumentParser(description="Simple UDP listener for ESP8266 data (logs to AirQuality_Log.txt)")
    p.add_argument("-p", "--port", type=int, default=4210, help="UDP port to bind to (default: 4210)")
    p.add_argument("-a", "--address", default="", help="Address to bind to (default: all interfaces)")
    return p.parse_args()


def main():
    args = parse_args()

    UDP_PORT = args.port
    BIND_ADDR = args.address

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Allow reusing the address — useful if a previous instance closed recently
    # On Windows this may not allow binding if another process has the port open
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        sock.bind((BIND_ADDR, UDP_PORT))
    except OSError as e:
        print(f"ERROR: Could not bind to {(BIND_ADDR or '0.0.0.0', UDP_PORT)}: {e}")
        print("Possible causes:")
        print(" - Another process is already listening on that port")
        print(" - The port is privileged or restricted")
        print("Options:")
        print(" - Stop the other process using the port")
        print(" - Run this script with a different --port value that matches your device")
        sock.close()
        sys.exit(1)

    print(f"Waiting for data from ESP8266 on port {UDP_PORT}...")

    # Open (or create) a log file for appending
    log_file = open("AirQuality_Log.txt", "a", encoding="utf-8")

    try:
        while True:
            try:
                data, addr = sock.recvfrom(1024)
            except OSError as e:
                print(f"Socket error while receiving data: {e}")
                break

            try:
                message = data.decode().strip()
            except Exception:
                # If decoding fails, represent raw bytes
                message = repr(data)

            # Add timestamp
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log_entry = f"[{timestamp}] {message}\n"

            # Print live on console
            print(f"Data from {addr}: {message}")

            # Write to file
            log_file.write(log_entry)
            log_file.flush()  # ensures immediate save to disk
    except KeyboardInterrupt:
        print("\nStopped by user.")
    finally:
        log_file.close()
        sock.close()


if __name__ == "__main__":
    main()
