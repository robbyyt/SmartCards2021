import socket
import uuid
from CryptoService import asymetric, symetric, CryptoService
import json
from Crypto.PublicKey import RSA

HOST = '127.0.0.1'
PORT_PG = 12345       
PORT_CLIENT = 54321

hibridService = CryptoService.CryptoService()


with open('merchant_key.pem', 'wb') as f:
    pk = hibridService.rsa_keypair.publickey().export_key()
    f.write(pk)

def receiveAndDecypt(conn):
    length = conn.recv(1024).decode()
    length = length.split()
    cipherTextClient = conn.recv(int(length[0]))
    aes_encryped_key_client = conn.recv(int(length[1]))
    #decode data
    return hibridService.decrypt_hybrid(cipherTextClient, aes_encryped_key_client)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT_CLIENT))
    s.listen()
    conn, addr = s.accept()
    with conn:
        print('Connected by', addr)
        #receive cipher text and encrypted aes key and decode data
        client_pk = receiveAndDecypt(conn)
        client_pk = RSA.import_key(client_pk)
        print("client pk", client_pk)
        
        #generate uid and signature
        client_uid = str(uuid.uuid1())
        client_uid_sign = hibridService.sign_message(client_uid)
        client_message = client_uid + ' ' + str(client_uid_sign)
        print("message sended", client_message)

        #encode data for clint
        client_pk = client_pk
        chipertext, enc_aes_key = hibridService.encrypt_hybrid(client_message, client_pk)
        
        #send cipher text and encripted aes
        conn.sendall(chipertext)
        conn.sendall(enc_aes_key)

        # #receive some card info
        cardInfo = receiveAndDecypt(conn)
        cardInfo = cardInfo.split("DELIMITATOR")
        PI,PO = cardInfo[0],cardInfo[1]
        print("pi,po:", PI, PO)
            

