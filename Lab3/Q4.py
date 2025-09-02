import os
import time
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# ===== AES Utility Functions =====
def generate_aes_key(key_size=32):
    return os.urandom(key_size)

def aes_encrypt(key, plaintext):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return iv + encryptor.update(plaintext) + encryptor.finalize()

def aes_decrypt(key, ciphertext):
    iv = ciphertext[:16]
    ct = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ct) + decryptor.finalize()

# ===== RSA Implementation =====
def rsa_keygen():
    start = time.time()
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    end = time.time()
    return private_key, end - start

def rsa_encrypt(public_key, data):
    return public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def rsa_decrypt(private_key, ciphertext):
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# ===== ECC Implementation (ECDH + AES key) =====
def ecc_keygen():
    start = time.time()
    private_key = ec.generate_private_key(
        ec.SECP256R1(),
        backend=default_backend()
    )
    end = time.time()
    return private_key, end - start

def ecc_derive_shared_key(priv_key, peer_pub_key):
    shared_secret = priv_key.exchange(ec.ECDH(), peer_pub_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
        backend=default_backend()
    ).derive(shared_secret)
    return derived_key

# ===== Main Test =====
def test_algorithm(file_size_mb):
    print(f"\n=== Testing with {file_size_mb}MB File ===")
    data = os.urandom(file_size_mb * 1024 * 1024)

    # AES key
    aes_key = generate_aes_key()

    # ===== RSA =====
    rsa_priv, rsa_gen_time = rsa_keygen()
    rsa_pub = rsa_priv.public_key()

    start_enc = time.time()
    enc_file = aes_encrypt(aes_key, data)
    enc_aes_key = rsa_encrypt(rsa_pub, aes_key)
    end_enc = time.time()

    start_dec = time.time()
    dec_aes_key = rsa_decrypt(rsa_priv, enc_aes_key)
    dec_file = aes_decrypt(dec_aes_key, enc_file)
    end_dec = time.time()

    print(f"RSA KeyGen: {rsa_gen_time:.4f}s, Encrypt: {end_enc - start_enc:.4f}s, Decrypt: {end_dec - start_dec:.4f}s")

    # ===== ECC =====
    ecc_priv1, ecc_gen_time1 = ecc_keygen()
    ecc_priv2, ecc_gen_time2 = ecc_keygen()
    ecc_pub1 = ecc_priv1.public_key()
    ecc_pub2 = ecc_priv2.public_key()

    start_enc = time.time()
    # Sender derives key from receiver's public key
    ecc_shared_key_sender = ecc_derive_shared_key(ecc_priv1, ecc_pub2)
    enc_file = aes_encrypt(ecc_shared_key_sender, data)
    end_enc = time.time()

    start_dec = time.time()
    # Receiver derives same key using sender's public key
    ecc_shared_key_receiver = ecc_derive_shared_key(ecc_priv2, ecc_pub1)
    dec_file = aes_decrypt(ecc_shared_key_receiver, enc_file)
    end_dec = time.time()

    print(f"ECC KeyGen: {(ecc_gen_time1 + ecc_gen_time2)/2:.4f}s, Encrypt: {end_enc - start_enc:.4f}s, Decrypt: {end_dec - start_dec:.4f}s")

    assert dec_file == data, "Decryption failed!"

if __name__ == "__main__":
    for size in [1, 10]:
        test_algorithm(size)
