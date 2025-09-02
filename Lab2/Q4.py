from Crypto.Util.Padding import pad, unpad

# 24-byte key (3-key 3DES)
key = b'0123456789ABCDEF01234567'  # 24 bytes

# Adjust parity automatically
from Crypto.Cipher import DES3
from Crypto.Cipher.DES3 import adjust_key_parity

key = adjust_key_parity(key)

data = b"Classified Text"

cipher = DES3.new(key, DES3.MODE_ECB)
ciphertext = cipher.encrypt(pad(data, DES3.block_size))
print("3DES Ciphertext:", ciphertext.hex())

plaintext = unpad(cipher.decrypt(ciphertext), DES3.block_size)
print("3DES Decrypted:", plaintext.decode())
