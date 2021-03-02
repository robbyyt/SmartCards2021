import socket
from CryptoService import CryptoService
from Crypto.PublicKey import RSA

HOST = '127.0.0.1'
PORT = 12345

hybridService = CryptoService.CryptoService()

with open('gate_key.pem', 'wb') as f:
    pk = hybridService.rsa_keypair.publickey().export_key()
    f.write(pk)
merchant_key = RSA.import_key(open("merchant_key.pem").read())

def receiveAndDecypt(conn):
    length = conn.recv(1024)
    print(length)
    length = length.decode().split()
    cipherTextClient = conn.recv(int(length[0]))
    aes_encryped_key = conn.recv(int(length[1]))
    # decode data
    return hybridService.decrypt_hybrid(cipherTextClient, aes_encryped_key)


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
        print("TO VERIFY:\n|", to_verify, "|")
        print("SIGNATURE:\n", signature)
        PI_sig = int(PI_sig)
        print("merchant",merchant_key.n)
        if hybridService.verify_message(to_verify, PI_sig, key=RSA.import_key(open("merchant_key.pem").read())
):
            print("Successfully verified PM information from merchant")
        else:
            raise ValueError("Could not verify PM sent by merchant!")

