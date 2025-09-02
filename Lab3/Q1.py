from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import binascii

# Generate RSA key pair
key = RSA.generate(2048)
public_key = key.publickey()

message = "Asymmetric Encryption".encode()

# Encrypt
cipher = PKCS1_OAEP.new(public_key)
ciphertext = cipher.encrypt(message)
print("Ciphertext:", binascii.hexlify(ciphertext))

# Decrypt
decipher = PKCS1_OAEP.new(key)
plaintext = decipher.decrypt(ciphertext)
print("Decrypted message:", plaintext.decode())
