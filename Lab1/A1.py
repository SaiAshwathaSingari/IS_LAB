ciphertext = "NCJAEZRCLAS/LYODEPRLYZRCLASJLCPEHZDTOPDZOLN&BY"

def decrypt_additive(ciphertext, key):
    plaintext = ""
    for char in ciphertext:
        if 'A' <= char <= 'Z':
            shifted = (ord(char) - ord('A') - key) % 26
            plaintext += chr(ord('A') + shifted)
        else:
            plaintext += char
    return plaintext

# Try keys near Alice's birthday
for key in range(10, 17):
    result = decrypt_additive(ciphertext, key)
    print(f"Key = {key}:\n{result}\n")
