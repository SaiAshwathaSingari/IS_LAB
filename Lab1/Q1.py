def mod_inverse(a, m=26):
    """Find multiplicative inverse of a modulo m using Extended Euclidean Algorithm."""
    a = a % m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None  # no inverse if None

def preprocess(text):
    """Convert to lowercase and remove spaces."""
    return text.replace(" ", "").lower()

def letter_to_num(c):
    return ord(c) - ord('a')

def num_to_letter(n):
    return chr(n + ord('a'))

def additive_encrypt(text, key):
    text = preprocess(text)
    encrypted = ''
    for c in text:
        x = letter_to_num(c)
        y = (x + key) % 26
        encrypted += num_to_letter(y)
    return encrypted

def additive_decrypt(cipher, key):
    decrypted = ''
    for c in cipher:
        y = letter_to_num(c)
        x = (y - key) % 26
        decrypted += num_to_letter(x)
    return decrypted

def multiplicative_encrypt(text, key):
    text = preprocess(text)
    encrypted = ''
    for c in text:
        x = letter_to_num(c)
        y = (key * x) % 26
        encrypted += num_to_letter(y)
    return encrypted

def multiplicative_decrypt(cipher, key):
    inv = mod_inverse(key)
    if inv is None:
        raise ValueError(f"No multiplicative inverse for key={key}")
    decrypted = ''
    for c in cipher:
        y = letter_to_num(c)
        x = (inv * y) % 26
        decrypted += num_to_letter(x)
    return decrypted

def affine_encrypt(text, a, b):
    text = preprocess(text)
    encrypted = ''
    for c in text:
        x = letter_to_num(c)
        y = (a * x + b) % 26
        encrypted += num_to_letter(y)
    return encrypted

def affine_decrypt(cipher, a, b):
    inv = mod_inverse(a)
    if inv is None:
        raise ValueError(f"No multiplicative inverse for a={a}")
    decrypted = ''
    for c in cipher:
        y = letter_to_num(c)
        x = (inv * (y - b)) % 26
        decrypted += num_to_letter(x)
    return decrypted

# Test input
message = "I am learning information security"

# a) Additive cipher with key = 20
key_add = 20
enc_add = additive_encrypt(message, key_add)
dec_add = additive_decrypt(enc_add, key_add)

# b) Multiplicative cipher with key = 15
key_mul = 15
enc_mul = multiplicative_encrypt(message, key_mul)
dec_mul = multiplicative_decrypt(enc_mul, key_mul)

# c) Affine cipher with key = (15, 20)
a_key, b_key = 15, 20
enc_affine = affine_encrypt(message, a_key, b_key)
dec_affine = affine_decrypt(enc_affine, a_key, b_key)

print("Additive Cipher:")
print("Encrypted:", enc_add)
print("Decrypted:", dec_add)

print("\nMultiplicative Cipher:")
print("Encrypted:", enc_mul)
print("Decrypted:", dec_mul)

print("\nAffine Cipher:")
print("Encrypted:", enc_affine)
print("Decrypted:", dec_affine)
