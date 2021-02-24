import socket
import uuid
from CryptoService import asymetric, symetric, CryptoService
import json
from Crypto.PublicKey import RSA

HOST = '127.0.0.1'
PORT_PG = 12345       
PORT_CLIENT = 54321

hibridService = CryptoService.CryptoService()
gate_key = RSA.import_key(open("gate_key.pem").read())


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

def encodeAndSend(conn, message, key):
    chipertext, enc_aes_key = hibridService.encrypt_hybrid(message ,key)
    print(len(chipertext), len(enc_aes_key))
    #send cipher and encrypted key to merchant
    length =str(len(chipertext)) + ' '+str(len(enc_aes_key))  
    s.sendall(length.encode())
    s.sendall(chipertext)
    s.sendall(enc_aes_key)

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

        #encode data for clint  send cipher text and encripted aes
        encodeAndSend(conn, client_message, client_pk)

        #receive some card info
        cardInfo = receiveAndDecypt(conn)
        cardInfo = cardInfo.split("DELIMITATOR")
        PM,PO = cardInfo[0],cardInfo[1]
        print("pM,po:", PM, PO)
        PM = PM.split(" ")
        #prepare message for gate
        gate_message_sign = PM[3]+" "+PM[4]+" "+PM[5]
        print(gate_message_sign)
        pm_sign = hibridService.sign_message(gate_message_sign)
        gate_message = PM+ "DELIMITATOR"+pm_sign.decode()

        #connect to gate
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT_PG))
            #send cipher text and encripted aes
            encodeAndSend(s, gate_message, gate_key)






            

