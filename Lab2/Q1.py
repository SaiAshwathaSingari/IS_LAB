from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

# DES requires 8-byte keys
key = b"A1B2C3D4"
data = b"Confidential Data"

# Create DES cipher in ECB mode
cipher = DES.new(key, DES.MODE_ECB)

# Encrypt (data must be multiple of 8 bytes)
ciphertext = cipher.encrypt(pad(data, DES.block_size))
print("DES Ciphertext:", ciphertext.hex())

# Decrypt
plaintext = unpad(cipher.decrypt(ciphertext), DES.block_size)
print("DES Decrypted:", plaintext.decode())
