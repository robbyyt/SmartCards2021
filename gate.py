import socket
from CryptoService import asymetric, symetric, CryptoService

HOST = '127.0.0.1'  
PORT = 12345      

asymHibridService = CryptoService.CryptoService()


with open('gate_key.pem', 'wb') as f:
    pk = asymHibridService.rsa_keypair.publickey().export_key()
    f.write(pk)

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