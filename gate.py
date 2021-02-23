import socket

HOST = '127.0.0.1'  # Standard loopback interface address (localhost)
PORT = 123456       # Port to listen on (non-privileged ports are > 1023)

pem = asymService.public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

with open('merchant_key.pem', 'wb') as f:
    f.write(pem)
    
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    conn, addr = s.accept()
    with conn:
        print('Connected by', addr)
        while True:
            data = conn.recv(1024)
            if not data:
                break

            conn.sendall(data)