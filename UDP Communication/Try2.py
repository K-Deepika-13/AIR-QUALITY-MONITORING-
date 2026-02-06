import socket

UDP_PORT = 4210
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("", UDP_PORT))
print("Waiting for data from ESP8266...")

while True:
    data, addr = sock.recvfrom(1024)
    print(f"Data from {addr}: {data.decode()}")
