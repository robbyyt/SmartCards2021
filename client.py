import socket
import json
from CryptoService import asymetric, symetric
HOST = '127.0.0.1'  # The server's hostname or IP address
PORT = 54321        # The port used by the server

with open('Data/paymentInfo.json') as f:
    cardInfo = json.load(f)


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    asymService = asymetric.AsymetricEncription()
    #trimite pb key
    public_key = asymService.public_key
    s.sendall(public_key)
    
    #primeste signatura
    sid, sid_signature = s.recv(1024)
    #trimite card info
    s.sendall(b'cardinfo')
    #primeste signaturi
    resp, sid, resp_signature = s.recv(1024)
    

