def affine_decrypt(ciphertext, a, b):
    a_inv = 21  # modular inverse of 5 mod 26
    plaintext = ""
    for char in ciphertext:
        if char.isalpha():
            y = ord(char.upper()) - ord('A')
            x = (a_inv * (y - b)) % 26
            plaintext += chr(x + ord('a'))
        else:
            plaintext += char
    return plaintext

ciphertext = "XPALASXYFGFUKPXUSOGEUTKCDGEXANMGNVS"
a = 5
b = 6

decrypted = affine_decrypt(ciphertext, a, b)
print("Decrypted message:", decrypted)
