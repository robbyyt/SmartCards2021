import socket
import json
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from CryptoService import asymetric, symetric
HOST = '127.0.0.1'  # The server's hostname or IP address
PORT = 54321        # The port used by the server

with open('Data/paymentInfo.json') as f:
    cardInfo = json.load(f)

    
with open("merchant_key.pem", "rb") as key_file:
    merchant_key = serialization.load_pem_public_key(
        key_file.read(),
        backend=default_backend()
    )

#crypto services
asymService = asymetric.AsymetricEncription()
symService = symetric.SymetricEncription()

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))

    public_key = asymService.public_key
    encode_pk_client = symService.encrypt_message(str(public_key))
    print("merchant key",len(str(merchant_key)))
    encoded_aes_merchant = asymService.encrypt(symService.key.decode(), merchant_key)
    print("len", len(encoded_aes_merchant))
    #trimite pb key
    first_merch_message = str(encode_pk_client) + "~" +str(encoded_aes_merchant)
    print("send first message", first_merch_message)
    s.sendall(first_merch_message.encode())

    #primeste signatura
    signatureData = s.recv(1024)
    signatureData = signatureData.decode()
    #parse data
    signatureData = signatureData.split('~')
    merchant_aes_key = asymService.decrypt(signatureData[1])
    merchantSignature = symService.decrypt_message(signatureData[0], merchant_aes_key)
    sid,signSid = merchantSignature.split('~')
    print("data from merchant", sid, signSid)

    # PI = 
    # #trimite card info
    # s.sendall(b'cardinfo')
    # #primeste signaturi
    # resp, sid, resp_signature = s.recv(1024)
    

