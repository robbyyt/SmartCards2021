import socket
import json
from Crypto.PublicKey import RSA
from CryptoService import asymetric, symetric, CryptoService
HOST = '127.0.0.1'  # The server's hostname or IP address
PORT = 54321        # The port used by the server

with open('Data/paymentInfo.json') as f:
    cardInfo = json.load(f) 

merchant_key = RSA.import_key(open("merchant_key.pem").read())

#crypto services
hibridService = CryptoService.CryptoService()

#parse card info
def parse_PM_PI(sid):
    PI = " ".join([cardInfo['CardN'],cardInfo['CardExp'],cardInfo['CCode'],sid,cardInfo['Amount'],merchant_key.publickey().exportKey().decode(),cardInfo['NC'],cardInfo['M']])
    signature_PI = hibridService.sign_message(PI)
    PI+= " " + str(signature_PI)
    PO = " ".join([cardInfo["OrderDesc"],sid,cardInfo['Amount'],cardInfo['NC']])
    signature_PO = hibridService.sign_message(PO)
    PO+= ' '+str(signature_PO)
    return PI,PO

def encodeAndSend(s, message):
    chipertext, enc_aes_key = hibridService.encrypt_hybrid(message ,merchant_key)
    print(len(chipertext), len(enc_aes_key))
    #send cipher and encrypted key to merchant
    length =str(len(chipertext)) + ' '+str(len(enc_aes_key))  
    s.sendall(length.encode())
    s.sendall(chipertext)
    s.sendall(enc_aes_key)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    
    s.connect((HOST, PORT))

    #get client public key from service
    public_key = hibridService.rsa_keypair.publickey()
    #hibrid encode public key and send to merchant
    encodeAndSend(s,public_key.export_key().decode())

    #receive uid and sign
    merchant_cipher = s.recv(1024)
    merchant_aes_key = s.recv(1024)

    #decrypt data
    merchant_message = hibridService.decrypt_hybrid(merchant_cipher, merchant_aes_key)

    #parse data
    merchant_message = merchant_message.split(' ')
    sid,signSid  = merchant_message[0], merchant_message[1]
    print("data from merchant", sid, signSid)
    #verify merchant
    if (hibridService.verify_message(sid,signSid)):
        print("Verified Merchant")
    else:
        print("ERROR: Unoknown merchant")

    #get card data
    PI,PO = parse_PM_PI(str(sid))
    print(PI,PO)
    #encode PI,PO and send to server
    stringMessage = str(PI) + "DELIMITATOR" + str(PO)
    encodeAndSend(s,stringMessage )
    
    

