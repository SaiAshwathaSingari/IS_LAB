def vigenere_encrypt(plaintext, keyword):
    plaintext = plaintext.replace(" ", "").upper()
    keyword = keyword.upper()

    ciphertext = ""
    keyword_length = len(keyword)

    for i, char in enumerate(plaintext):
        if 'A' <= char <= 'Z':
            p_val = ord(char) - ord('A')
            k_val = ord(keyword[i % keyword_length]) - ord('A')
            c_val = (p_val + k_val) % 26
            ciphertext += chr(c_val + ord('A'))
        else:
            # Non-alphabetic characters are ignored or you can keep them as-is
            ciphertext += char

    return ciphertext


# Example usage
plaintext = "Life is full of surprises"
keyword = "HEALTH"
encrypted_text = vigenere_encrypt(plaintext, keyword)
print("Ciphertext:", encrypted_text)
