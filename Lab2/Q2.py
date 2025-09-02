from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

key = bytes.fromhex("0123456789ABCDEF0123456789ABCDEF")
data = b"Sensitive Information"

cipher = AES.new(key, AES.MODE_ECB)

ciphertext = cipher.encrypt(pad(data, AES.block_size))
print("AES-128 Ciphertext:", ciphertext.hex())

plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
print("AES-128 Decrypted:", plaintext.decode())
