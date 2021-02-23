import socket
import uuid
from CryptoService import asymetric, symetric
import json
from cryptography.hazmat.primitives import serialization


HOST = '127.0.0.1'
PORT_PG = 12345       
PORT_CLIENT = 54321

asymService = asymetric.AsymetricEncription()
symService = symetric.SymetricEncription()

pem = asymService.public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

with open('merchant_key.pem', 'wb') as f:
    f.write(pem)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT_CLIENT))
    s.listen()
    conn, addr = s.accept()
    with conn:
        print('Connected by', addr)
        while True:
            #receive public key from client
            clientData = conn.recv(1024)
            print('public key from client', clientData)
            #parse public key
            mess = clientData.decode().split('~')
            print("mess", len(mess), len(mess[1]))
            client_aes_key = asymService.decrypt(mess[1]) 
            
            client_pk = symService.decrypted_msg(mess[0], client_aes_key)

            client_uid = str(uuid.uuid1())
            client_uid_sign = asymService.sign(client_uid)
            client_message = client_uid + '~' + str(client_uid_sign)
            print("message sended", client_message)
            encode_client_message = symService.encrypt_message(client_message)
            encode_aes_key = asymService.encrypt(symService.key, client_pk)
            encoded_data = str(encode_client_message) + "~" + str(encode_aes_key)
            
            #send sid and signature
            conn.sendall(encoded_data.encode())

            # #receive some card info
            # cardInfo = conn.recv(1024)
            

            # #communication with gate    
            # with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as clientSocket:
            #     clientSocket.connect((HOST, PORT_PG))
            #     #send PM and signature
            #     clientSocket.sendall(b'Hello, world')
            #     #recive a response, sid and signature
            #     data = clientSocket.recv(1024)

            # #send back to client gate response
            # if data:
            #     conn.sendall(data)

