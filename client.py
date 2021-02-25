import socket
import json
from Crypto.PublicKey import RSA
from CryptoService import CryptoService

HOST = '127.0.0.1'  # The server's hostname or IP address
PORT = 54321  # The port used by the server

with open('Data/paymentInfo.json') as f:
    cardInfo = json.load(f)

merchant_key = RSA.import_key(open("merchant_key.pem").read())
gate_key = RSA.import_key(open("gate_key.pem").read())
# crypto services
hybridService = CryptoService.CryptoService()


# parse card info
def parse_PM_PI(sid):
    PI = ""
    for i in [cardInfo['CardN'], cardInfo['CardExp'], cardInfo['CCode'], sid, cardInfo['Amount'],
                   merchant_key.publickey().exportKey().decode(), cardInfo['NC'], cardInfo['M']]:
        PI += i + " "
    # removing blank space for signing
    PI = PI[:-1]
    signature_PI = hybridService.sign_message(PI)
    PI += " " + str(signature_PI)
    PO = ""
    for i in [cardInfo["OrderDesc"], sid, cardInfo['Amount'], cardInfo['NC']]:
        PO += i + " "

    # removing blank space for signing
    PO = PO[:-1]
    signature_PO = hybridService.sign_message(PO)

    PO += " " + str(signature_PO)
    return PI, PO


def encodeAndSend(s, message, key=None):
    if not key:
        key = hybridService.rsa_keypair

    chipertext, enc_aes_key = hybridService.encrypt_hybrid(message, key)
    # send cipher and encrypted key to merchant
    length = str(len(chipertext)) + ' ' + str(len(enc_aes_key))
    s.sendall(length.encode())
    s.sendall(chipertext)
    s.sendall(enc_aes_key)


def receiveAndDecypt(s):
    length = s.recv(2048).decode()
    length = length.split()
    cipherTextClient = s.recv(int(length[0]))
    aes_encryped_key_client = s.recv(int(length[1]))
    # decode data
    return hybridService.decrypt_hybrid(cipherTextClient, aes_encryped_key_client)


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    # get client public key from service
    public_key = hybridService.rsa_keypair.publickey()
    print("[Client] My public key is:\nN: %d\nE:%d" % (public_key.n, public_key.e))
    print("[Client] Merchant public key is:\nN: %d\nE:%d" % (merchant_key.n, merchant_key.e))
    print("[Client] Gateway public key is:\nN: %d\nE:%d" % (gate_key.n, gate_key.e))
    # hybrid encode public key and send to merchant
    encodeAndSend(s, public_key.export_key().decode(), merchant_key)

    # receive uid and sign
    # decrypt data
    merchant_message = receiveAndDecypt(s)
    # parse data
    merchant_message = merchant_message.split(' ', 1)
    sid, signSid = merchant_message[0], merchant_message[1]
    print("[Client] Sid and signature from merchant:")
    print(sid, signSid)
    signSid = int(signSid)

    # verify merchant
    if hybridService.verify_message(sid, signSid, merchant_key):
        print("Verified Merchant")
    else:
        raise ValueError("Can't verifty signed message")

    # get card data
    PI, PO = parse_PM_PI(str(sid))
    print("PI:\n", PI)
    print("PO:\n", PO)
    PI_enc, PI_key = hybridService.encrypt_hybrid(PI, gate_key)
    PM = str(PI_enc) + 'DELIMITATOR' + str(PI_key)
    print("ENCRYPTED PI:\n", PI_enc)
    print("ENCRYPTED PI AES KEY:\n", PI_key)
    # encode PM,PO and send to server
    to_send = PM + "DELIMITATOR" + str(PO)
    encodeAndSend(s, to_send, merchant_key)
