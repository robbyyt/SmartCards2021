import socket
import uuid
from CryptoService import CryptoService
from Crypto.PublicKey import RSA

HOST = '127.0.0.1'
PORT_PG = 12345
PORT_CLIENT = 54321

hybridService = CryptoService.CryptoService()
gate_key = RSA.import_key(open("gate_key.pem").read())

with open('merchant_key.pem', 'wb') as f:
    pk = hybridService.rsa_keypair.publickey().exportKey()
    f.write(pk)

print("[Merchant] My public key is:\nN: %d\nE:%d" % (hybridService.rsa_keypair.publickey().n, hybridService.rsa_keypair.publickey().e))


def receiveAndDecypt(conn):
    length = conn.recv(2048).decode()
    length = length.split()
    cipherTextClient = conn.recv(int(length[0]))
    aes_encryped_key_client = conn.recv(int(length[1]))
    # decode data
    return hybridService.decrypt_hybrid(cipherTextClient, aes_encryped_key_client)


def encodeAndSend(conn, message, key):
    if not key:
        key = hybridService.rsa_keypair

    chipertext, enc_aes_key = hybridService.encrypt_hybrid(message, key)
    # send ciphertext and encrypted key to merchant
    length = str(len(chipertext)) + ' ' + str(len(enc_aes_key))
    conn.sendall(length.encode())
    conn.sendall(chipertext)
    conn.sendall(enc_aes_key)


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT_CLIENT))
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.listen()
    conn, addr = s.accept()
    with conn:
        print('Client connected from: ', addr)
        # receive cipher text and encrypted aes key and decode data
        client_pk = receiveAndDecypt(conn)
        print("CPC:" + client_pk)
        client_pk = RSA.import_key(client_pk)
        print("[Merchant] Computed Client public key as:\nN: %d\nE: %d\n" % (client_pk.n, client_pk.e))
        print("[Metchant] Gateway public key is:\nN: %d\nE:%d" % (gate_key.n, gate_key.e))
        # generate uid and signature
        client_uid = str(uuid.uuid1())
        print("[Merchant] Generated SID: ", client_uid)
        client_uid_sign = hybridService.sign_message(client_uid)
        client_message = client_uid + ' ' + str(client_uid_sign)
        print("[Merchant] Sending SID and signature")
        print(client_message)
        # encode data for client  send cipher text and encripted aes
        encodeAndSend(conn, client_message, client_pk)

        # receive some card info
        cardInfo = receiveAndDecypt(conn)
        cardInfo = cardInfo.split("DELIMITATOR")
        PI_enc, PI_key, PO = cardInfo[0], cardInfo[1], cardInfo[2]
        print("ENCRYPTED PI:\n", PI_enc)
        print("ENCRYPTED PI AES KEY:\n", PI_key)
        order_desc, sid, amount, nc, po_signature = PO.split(' ')
        PO = order_desc + " " + sid + " " + amount + " " + nc
        print("PO:\n", PO)
        po_signature = int(po_signature)

        if sid != client_uid:
            raise ValueError("Wrong sid!")

        if hybridService.verify_message(PO, po_signature, key=client_pk):
            print("Verified customer PO successfully")
        else:
            raise ValueError("Could not verify customer PO!")

        # prepare message for gate (step 4)
        PM = PI_enc + 'DELIMITATOR' + PI_key
        print(PI_enc)
        to_sign = sid + " " + client_pk.export_key().decode() + " " + amount
        print("TO SIGN:\n|", to_sign,"|")
        signature = hybridService.sign_message(to_sign)
        print("SIGNATURE:\n", signature)
        to_send = PM + "DELIMITATOR" + str(signature)

        # connect to gate
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s2:
            s2.connect((HOST, PORT_PG))
            # send cipher text and encripted aes
            encodeAndSend(s2, to_send, gate_key)
            response = receiveAndDecypt(s2)
            Resp, Sid, SigPG = response.split(" ")
            SigPG = int(SigPG)
            to_verify = Resp + " " + sid + " " + amount + " " + nc

            if hybridService.verify_message(to_verify, SigPG, key=gate_key):
                print("Verified info from PG")
            else:
                raise ValueError("Can't verify info from PG")

            # step 6
            to_send = Resp + " " + sid + " " + str(SigPG)
            encodeAndSend(conn, to_send, key=client_pk)



