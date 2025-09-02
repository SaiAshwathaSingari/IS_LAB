import numpy as np

def hill_encrypt(plaintext, key_matrix):
    # Convert to uppercase, remove spaces
    plaintext = plaintext.upper().replace(' ', '')
    # Pad if length is odd
    if len(plaintext) % 2 != 0:
        plaintext += 'X'
    # Convert letters to numbers 0-25
    numbers = [ord(c) - ord('A') for c in plaintext]
    ciphertext = ""

    for i in range(0, len(numbers), 2):
        pair = np.array([[numbers[i]], [numbers[i+1]]])
        encrypted_pair = np.dot(key_matrix, pair) % 26
        ciphertext += chr(encrypted_pair[0][0] + ord('A'))
        ciphertext += chr(encrypted_pair[1][0] + ord('A'))
    return ciphertext

# Example usage:
plaintext = "WE LIVE IN AN INSECURE WORLD"
key_matrix = np.array([[3, 3],
                       [2, 7]])

print("Hill Cipher:", hill_encrypt(plaintext.replace(" ", ""), key_matrix))
