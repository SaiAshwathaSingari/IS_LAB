from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

# Generate ECC key pair
private_key = ec.generate_private_key(ec.SECP256R1())
public_key = private_key.public_key()

message = b"Secure Transactions"

# Derive shared key (simulate ECIES step)
# For demo, we'll just derive a key from private key (usually you need a peer's public key)
shared_key = private_key.exchange(ec.ECDH(), public_key)

# Derive symmetric key from shared secret
derived_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'handshake data',
).derive(shared_key)

# Encrypt message with AES-GCM
iv = os.urandom(12)
encryptor = Cipher(
    algorithms.AES(derived_key),
    modes.GCM(iv)
).encryptor()

ciphertext = encryptor.update(message) + encryptor.finalize()
tag = encryptor.tag

# Decrypt
decryptor = Cipher(
    algorithms.AES(derived_key),
    modes.GCM(iv, tag)
).decryptor()
plaintext = decryptor.update(ciphertext) + decryptor.finalize()

print("Decrypted message:", plaintext.decode())
