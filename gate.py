import socket
from CryptoService import CryptoService
from Crypto.PublicKey import RSA
import json

HOST = '127.0.0.1'
PORT = 12345

hybridService = CryptoService.CryptoService()

with open('gate_key.pem', 'wb') as f:
    pk = hybridService.rsa_keypair.publickey().export_key()
    f.write(pk)


def receiveAndDecypt(conn):
    length = conn.recv(1024)
    print(length)
    length = length.decode().split()
    cipherTextClient = conn.recv(int(length[0]))
    aes_encryped_key = conn.recv(int(length[1]))
    # decode data
    return hybridService.decrypt_hybrid(cipherTextClient, aes_encryped_key)


def encodeAndSend(conn, message, key=None):
    if not key:
        key = hybridService.rsa_keypair

    chipertext, enc_aes_key = hybridService.encrypt_hybrid(message, key)
    # send ciphertext and encrypted key to merchant
    length = str(len(chipertext)) + ' ' + str(len(enc_aes_key))
    conn.sendall(length.encode())
    conn.sendall(chipertext)
    conn.sendall(enc_aes_key)


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    print("[Gateway] Gateway public key is:\nN: %d\nE:%d" % (hybridService.rsa_keypair.n, hybridService.rsa_keypair.e))
    s.bind((HOST, PORT))
    s.listen()
    conn, addr = s.accept()
    with conn:
        print('Connected by', addr)
        # receive and decrypt pm and signature of pm
        merchant_message = receiveAndDecypt(conn)
        PI_enc, PI_key, signature = merchant_message.split("DELIMITATOR")
        PI_enc = bytes.fromhex(PI_enc)
        PI_key = bytes.fromhex(PI_key)

        PM = hybridService.decrypt_hybrid(PI_enc, PI_key)
        print(PM)
        CardN, CardExp, CCode, Sid, Amount, PI_end = PM.split(" ", 5)
        PubKC, NC, M, PI_sig = PI_end.rsplit(" ", 3)
        to_verify = Sid + " " + PubKC + " " + Amount

        merchant_key = RSA.import_key(open("merchant_key.pem").read())

        if hybridService.verify_message(to_verify, int(signature), key=merchant_key):
            print("[Gate]Successfully verified PM information from merchant")
        else:
            raise ValueError("[Gate]Could not verify PM sent by merchant!")

        to_verify = CardN + " " + CardExp + " " + CCode + " " + Sid + " " + Amount + " " + PubKC + " " + NC + " " + M

        if hybridService.verify_message(to_verify, int(PI_sig), key=RSA.import_key(PubKC)):
            print("[Gate]Successfully verified PI info from customer")
        else:
            raise ValueError("[Gate]Could not verify signed PI from customer")

        # step 5
        with open('Data/gatewayPaymentInfo.json') as f:
            gatewayClientInfo = json.load(f)

        response = "OK"
        if CardN != gatewayClientInfo["CardN"] or CardExp != gatewayClientInfo["CardExp"] \
                or CCode != gatewayClientInfo["CCode"] or int(Amount) > int(gatewayClientInfo["Balance"]):
            response = "Abort"

        if response == "OK":
            gatewayClientInfo["Balance"] = str(int(gatewayClientInfo["Balance"]) - int(Amount))
            with open('Data/accounts.txt', 'r') as f:
                merchant_account = float(f.readline())
            with open('Data/accounts.txt', 'w') as f:
                f.write(str(merchant_account+float(Amount)))

        with open('Data/gatewayPaymentInfo.json', 'w') as f:
            json.dump(gatewayClientInfo, f)


        print("[Gate] Sending response to merchant:", response)   

        to_sign = response + " " + Sid + " " + Amount + " " + NC
        signature = hybridService.sign_message(to_sign)

        to_send = response + " " + Sid + " " + str(signature)
        encodeAndSend(conn, to_send, key=merchant_key)
