def vigenere_encrypt(plaintext, key):
    key = key.lower()
    ciphertext = ""
    for i, char in enumerate(plaintext):
        p = ord(char) - ord('a')
        k = ord(key[i % len(key)]) - ord('a')
        c = (p + k) % 26
        ciphertext += chr(c + ord('a'))
    return ciphertext

def vigenere_decrypt(ciphertext, key):
    key = key.lower()
    plaintext = ""
    for i, char in enumerate(ciphertext):
        c = ord(char) - ord('a')
        k = ord(key[i % len(key)]) - ord('a')
        p = (c - k) % 26
        plaintext += chr(p + ord('a'))
    return plaintext

def autokey_encrypt(plaintext, key_num):
    key = [key_num]  # initial numeric key
    ciphertext = ""
    for i, char in enumerate(plaintext):
        p = ord(char) - ord('a')
        k = key[i]
        c = (p + k) % 26
        ciphertext += chr(c + ord('a'))
        key.append(p)  # append plaintext letter for next key char
    return ciphertext

def autokey_decrypt(ciphertext, key_num):
    key = [key_num]
    plaintext = ""
    for i, char in enumerate(ciphertext):
        c = ord(char) - ord('a')
        k = key[i]
        p = (c - k) % 26
        plaintext += chr(p + ord('a'))
        key.append(p)
    return plaintext

plaintext = "the house is being sold tonight".replace(" ", "").lower()

# Vigenere
vigenere_key = "dollars"
vigenere_cipher = vigenere_encrypt(plaintext, vigenere_key)
vigenere_decrypted = vigenere_decrypt(vigenere_cipher, vigenere_key)

print("Vigenere Ciphertext:", vigenere_cipher)
print("Vigenere Decrypted:", vigenere_decrypted)

# Autokey
autokey_key_num = 7  # corresponds to 'h'
autokey_cipher = autokey_encrypt(plaintext, autokey_key_num)
autokey_decrypted = autokey_decrypt(autokey_cipher, autokey_key_num)

print("Autokey Ciphertext:", autokey_cipher)
print("Autokey Decrypted:", autokey_decrypted)
