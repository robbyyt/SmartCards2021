import socket
from CryptoService import asymetric, symetric, CryptoService

HOST = '127.0.0.1'  
PORT = 12345      

hibridService = CryptoService.CryptoService()
merchant_key = RSA.import_key(open("merchant_key.pem").read())

def receiveAndDecypt(conn):
    length = conn.recv(1024).decode()
    length = length.split()
    cipherTextClient = conn.recv(int(length[0]))
    aes_encryped_key = conn.recv(int(length[1]))
    #decode data
    return hibridService.decrypt_hybrid(cipherTextClient, aes_encryped_key)

with open('gate_key.pem', 'wb') as f:
    pk = asymHibridService.rsa_keypair.publickey().export_key()
    f.write(pk)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    conn, addr = s.accept()
    with conn:
        print('Connected by', addr)
        #receive and decrypt pm and signature of pm
        merchant_message = receiveAndDecypt(conn)
        merchant_message = merchant_message.split("DELIMITATOR")
        PM, sign = merchant_message[0],merchant_message[1]

        #think we should verify the sign
        # hibridService.verify_message()


