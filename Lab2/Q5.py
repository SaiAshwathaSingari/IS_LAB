from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


key = bytes.fromhex("FEDCBA9876543210FEDCBA9876543210")
data = b"Top Secret Data"

cipher = AES.new(key, AES.MODE_ECB)
ciphertext = cipher.encrypt(pad(data, AES.block_size))
print("AES-192 Ciphertext:", ciphertext.hex())

plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
print("AES-192 Decrypted:", plaintext.decode())
