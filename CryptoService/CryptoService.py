from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.Util.Padding import pad, unpad


class CryptoService:
    def __init__(self):
        self.rsa_keypair = RSA.generate(2048)

    def encrypt_hybrid(self, message, key=None):
        if not key:
            key = self.rsa_keypair
        # encrypting aes key
        aes_session_key = get_random_bytes(16)
        chiper_rsa = PKCS1_OAEP.new(key)
        enc_aes_key = chiper_rsa.encrypt(aes_session_key)
        # encrypting message
        chiper_aes = AES.new(aes_session_key, mode=AES.MODE_ECB)
        chipertext = chiper_aes.encrypt(pad(message.encode(), 16))

        return chipertext, enc_aes_key

    def decrypt_hybrid(self, cryptotext, encrypted_aes_key, key=None):
        if not key:
            key = self.rsa_keypair

        cipher_rsa = PKCS1_OAEP.new(key)
        aes_session_key = cipher_rsa.decrypt(encrypted_aes_key)

        cipher_aes = AES.new(aes_session_key, mode=AES.MODE_ECB)
        data = unpad(cipher_aes.decrypt(cryptotext), 16)

        return data.decode()

    def sign_message(self, message, key=None):
        if not key:
            key = self.rsa_keypair

        h = SHA256.new(message.encode())
        signature = pkcs1_15.new(key).sign(h)
        return signature

    def verify_message(self, message, signature, key=None):
        if not key:
            key = self.rsa_keypair.publickey()

        h = SHA256.new(message.encode())
        try:
            pkcs1_15.new(key).verify(h, signature)
            return True
        except (ValueError, TypeError):
            return False


if __name__ == '__main__':
    cs = CryptoService()
    msg = 'Hello world!'
    ct, enc_key = cs.encrypt_hybrid(msg)
    print(ct, enc_key)
    plaintext = cs.decrypt_hybrid(ct, enc_key)
    print(plaintext)
    sig = cs.sign_message(msg)
    print(cs.verify_message(msg, sig))
