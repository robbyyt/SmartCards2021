import base64, os
from Crypto.Cipher import AES


class SymetricEncription:
    key = ''
    key_length = 16 
    padding_character = '^'
    
    def __init__(self):
        self.key = self.generateNewKey()
    
    def generateNewKey(self):
        secret_key = os.urandom(self.key_length)
        encoded_secret_key = base64.b64encode(secret_key)
        return encoded_secret_key

    def encrypt_message(self,private_msg,tmpKey=''):
        if not tmpKey:
            tmpKey = self.key
        cipher = AES.new(tmpKey, mode=AES.MODE_ECB)
        padded_private_msg = private_msg + (self.padding_character * ((16-len(private_msg)) % 16))
        encrypted_msg = cipher.encrypt(padded_private_msg.encode())
        encoded_encrypted_msg = base64.b64encode(encrypted_msg)
        return encoded_encrypted_msg

    def decrypt_message(self,encoded_encrypted_msg, tmpKey=''):
        if not tmpKey:
            tmpKey = self.key
        encrypted_msg = base64.b64decode(encoded_encrypted_msg)
        cipher = AES.new(tmpKey, mode=AES.MODE_ECB)
        decrypted_msg = cipher.decrypt(encrypted_msg)
        unpadded_private_msg = decrypted_msg.rstrip(self.padding_character.encode())
        return unpadded_private_msg

