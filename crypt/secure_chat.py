import socket
import threading
import os
import scapy.all as scapy
from cryptography.fernet import Fernet
from flask import Flask, render_template_string
from flask_socketio import SocketIO

app = Flask(__name__)
socketio = SocketIO(app)

KEY_FILE = "key.key"

def load_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as key_file:
            return key_file.read()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as key_file:
            key_file.write(key)
        return key

encryption_key = load_key()
cipher = Fernet(encryption_key)

def encrypt_message(message):
    return cipher.encrypt(message.encode()).decode()

def decrypt_message(encrypted_message):
    try:
        return cipher.decrypt(encrypted_message.encode()).decode()
    except:
        return "[ERROR] Decryption failed"

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", 9999))
    server.listen(5)
    socketio.emit('log', '[*] Server listening on port 9999...')
    client_socket, addr = server.accept()
    socketio.emit('log', f'[*] Connection established with {addr}')
    
    while True:
        encrypted_data = client_socket.recv(1024).decode()
        if not encrypted_data:
            break
        decrypted_msg = decrypt_message(encrypted_data)
        socketio.emit('log', f'[Encrypted] {encrypted_data}')
        socketio.emit('log', f'[Decrypted] {decrypted_msg}')
        
        response = "Acknowledged"
        client_socket.send(encrypt_message(response).encode())
    
    client_socket.close()

def start_client(server_ip):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((server_ip, 9999))
    socketio.emit('log', '[CONNECTED] to server')
    
    while True:
        message = input("Enter message: ")
        if message.lower() == 'exit':
            break
        encrypted_message = encrypt_message(message)
        client.send(encrypted_message.encode())
        response = client.recv(1024).decode()
        socketio.emit('log', f'[Encrypted] {encrypted_message}')
        socketio.emit('log', f'[Decrypted] {decrypt_message(response)}')
    
    client.close()

def packet_sniffer():
    fake_mac_addresses = ["00:11:22:33:44:55", "66:77:88:99:AA:BB"]

    def process_packet(packet):
        if packet.haslayer(scapy.Ether):
            mac_src = packet[scapy.Ether].src
            if mac_src in fake_mac_addresses:
                socketio.emit('log', f'[ALERT] Suspicious packet detected from fake MAC {mac_src}')
            else:
                socketio.emit('log', f'[SNIFFED] {packet.summary()}')
    
    socketio.emit('log', '[INFO] Starting packet sniffer...')
    scapy.sniff(prn=process_packet, store=False, count=10)

def arp_spoof_detector():
    fake_ip_list = ["192.168.1.100", "10.0.0.50"]
    ip_table = {}
    
    def detect_arp_spoof(packet):
        if packet.haslayer(scapy.ARP) and packet.op == 2:
            ip = packet.psrc
            if ip in fake_ip_list:
                socketio.emit('log', f'[ALERT] ARP Spoofing Detected! Fake IP: {ip}')
            elif ip in ip_table:
                socketio.emit('log', f'[ALERT] ARP Spoofing Detected! Duplicate IP detected: {ip}')
            else:
                ip_table[ip] = True
    
    socketio.emit('log', '[INFO] Monitoring ARP traffic for spoofing attacks...')
    scapy.sniff(filter="arp", prn=detect_arp_spoof, store=False)

html_template = """
<!DOCTYPE html>
<html lang='en'>
<head>
    <meta charset='UTF-8'>
    <meta name='viewport' content='width=device-width, initial-scale=1.0'>
    <title>Secure Communication</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.1/socket.io.js"></script>
    <style>
        body { font-family: Arial, sans-serif; text-align: center; background-color: #f4f4f4; }
        .container { width: 50%; margin: auto; background: white; padding: 20px; box-shadow: 0px 0px 10px gray; }
        button { padding: 10px; margin: 10px; font-size: 16px; cursor: pointer; }
        #log { text-align: left; height: 200px; overflow-y: scroll; background: #222; color: #0f0; padding: 10px; }
    </style>
</head>
<body>
    <div class='container'>
        <h1>Secure Communication And Intrusion Detection</h1>
        <button onclick="startServer()">Start Server</button>
        <button onclick="startClient()">Start Client</button>
        <button onclick="startSniffer()">Start Packet Sniffer</button>
        <button onclick="startARP()">Start ARP Detector</button>
        <div id='log'></div>
    </div>
    <script>
        var socket = io();
        socket.on('log', function(msg) {
            var logDiv = document.getElementById('log');
            logDiv.innerHTML += msg + '<br>';
            logDiv.scrollTop = logDiv.scrollHeight;
        });
        function startServer() { fetch('/start_server'); }
        function startClient() { fetch('/start_client'); }
        function startSniffer() { fetch('/start_sniffer'); }
        function startARP() { fetch('/start_arp'); }
    </script>
</body>
</html>
"""

@app.route('/')
def home():
    return render_template_string(html_template)

@app.route('/start_server')
def run_server():
    threading.Thread(target=start_server, daemon=True).start()
    return "Server started"

@app.route('/start_client')
def run_client():
    server_ip = "127.0.0.1"
    threading.Thread(target=start_client, args=(server_ip,), daemon=True).start()
    return "Client started"

@app.route('/start_sniffer')
def run_sniffer():
    threading.Thread(target=packet_sniffer, daemon=True).start()
    return "Packet sniffer started"

@app.route('/start_arp')
def run_arp():
    threading.Thread(target=arp_spoof_detector, daemon=True).start()
    return "ARP Detector started"

if __name__ == "__main__":
    socketio.run(app, debug=True)
