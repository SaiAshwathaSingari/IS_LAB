import random

# Key parameters (example small primes for demo)
p = 467
g = 2
x = random.randint(1, p-2)  # private key
h = pow(g, x, p)  # public key

def elgamal_encrypt(m, p, g, h):
    k = random.randint(1, p-2)
    c1 = pow(g, k, p)
    c2 = (m * pow(h, k, p)) % p
    return (c1, c2)

def elgamal_decrypt(c1, c2, p, x):
    s = pow(c1, x, p)
    s_inv = pow(s, -1, p)  # modular inverse of s
    m = (c2 * s_inv) % p
    return m

# Convert message to integer (simple way, e.g., sum of ASCII)
message = "Confidential Data"
m_int = sum(ord(c) for c in message) % p

cipher = elgamal_encrypt(m_int, p, g, h)
print("Ciphertext:", cipher)

decrypted_int = elgamal_decrypt(cipher[0], cipher[1], p, x)
print("Decrypted integer:", decrypted_int)
