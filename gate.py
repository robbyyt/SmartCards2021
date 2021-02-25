import socket
from CryptoService import CryptoService
from Crypto.PublicKey import RSA

HOST = '127.0.0.1'
PORT = 12345

hybridService = CryptoService.CryptoService()
merchant_key = RSA.import_key(open("merchant_key.pem").read())


with open('gate_key.pem', 'wb') as f:
    pk = hybridService.rsa_keypair.publickey().export_key()
    f.write(pk)


def receiveAndDecypt(conn):
    length = conn.recv(1024).decode()
    length = length.split()
    cipherTextClient = conn.recv(int(length[0]))
    aes_encryped_key = conn.recv(int(length[1]))
    # decode data
    return hybridService.decrypt_hybrid(cipherTextClient, aes_encryped_key)


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    print("[Gateway] Gateway public key is:\nN: %d\nE:%d" % (hybridService.rsa_keypair.n, hybridService.rsa_keypair.e))
    s.bind((HOST, PORT))
    s.listen()
    conn, addr = s.accept()
    with conn:
        print('Connected by', addr)
        # receive and decrypt pm and signature of pm
        merchant_message = receiveAndDecypt(conn)
        PI_enc, PI_key, signature = merchant_message.split("DELIMITATOR")

        PM = hybridService.decrypt_hybrid(PI_enc, PI_key)
        print("PM:\n", PM)