import socket
import uuid

HOST = '127.0.0.1'
PORT_PG = 12345       
PORT_CLIENT = 54321

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    conn, addr = s.accept()
    with conn:
        print('Connected by', addr)
        while True:
            public_key = conn.recv(1024)
            print('public key from client', public_key)
            client_sid = uuid.uuid1()
            
            #send sid and signature
            conn.sendall(data)

            #receive some card info
            cardInfo = conn.recv(1024)
            

            #communication with gate    
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as clientSocket:
                clientSocket.connect((HOST, PORT_PG))
                #send PM and signature
                clientSocket.sendall(b'Hello, world')
                #recive a response, sid and signature
                data = clientSocket.recv(1024)

            #send back to client gate response
            if data:
                conn.sendall(data)

