import pyDHFixed as pyDH
from Crypto.Cipher import AES
import base64
d1 = pyDH.DiffieHellman(15)
d2 = pyDH.DiffieHellman(15)

d1_pub = d1.gen_public_key()
d2_pub = d2.gen_public_key()


d1_shared = d1.gen_shared_key(d2_pub).encode()
d2_shared = d2.gen_shared_key(d1_pub).encode()
# d1_shared = base64.b64encode(d1_shared)

cipher = AES.new(d1_shared, AES.MODE_SIV)
text = 'hello chap'.encode()
data, tag = cipher.encrypt_and_digest(text)

cipher2 = AES.new(d2_shared, AES.MODE_SIV)
print(cipher2.decrypt_and_verify(data, tag))
