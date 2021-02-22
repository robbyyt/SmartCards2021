from CryptoService import asymetric, symetric

sym = symetric.SymetricEncription()
print(sym.decrypt_message(sym.encrypt_message('hello world')))

asym = asymetric.AsymetricEncription()
print(asym.decrypt(asym.encrypt('hello world')))