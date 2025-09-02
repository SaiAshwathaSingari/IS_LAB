import time
from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad

message = b"Performance Testing of Encryption Algorithms"

# DES setup
des_key = b"A1B2C3D4"
des_cipher = DES.new(des_key, DES.MODE_ECB)

# AES-256 setup
aes_key = b"0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"[:32]
aes_cipher = AES.new(aes_key, AES.MODE_ECB)

# DES timing
start = time.time()
des_cipher.encrypt(pad(message, DES.block_size))
des_time = time.time() - start

# AES-256 timing
start = time.time()
aes_cipher.encrypt(pad(message, AES.block_size))
aes_time = time.time() - start

print(f"DES encryption time: {des_time:.6f} seconds")
print(f"AES-256 encryption time: {aes_time:.6f} seconds")
