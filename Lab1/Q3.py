import string

def prepare_key_matrix(key):
    key = key.upper().replace('J', 'I')
    seen = set()
    matrix = []
    for char in key + string.ascii_uppercase:
        if char not in seen and char.isalpha():
            seen.add(char)
            matrix.append(char)
    return [matrix[i*5:(i+1)*5] for i in range(5)]

def find_position(matrix, char):
    for i in range(5):
        for j in range(5):
            if matrix[i][j] == char:
                return i, j
    return None

def playfair_encrypt(plaintext, key):
    matrix = prepare_key_matrix(key)
    plaintext = plaintext.upper().replace('J', 'I')
    # Prepare plaintext: remove non-alpha, split in digrams, insert X if needed
    filtered = [c for c in plaintext if c.isalpha()]
    i = 0
    digrams = []
    while i < len(filtered):
        a = filtered[i]
        b = ''
        if i + 1 < len(filtered):
            b = filtered[i+1]
        if b == a or b == '':
            b = 'X'
            i += 1
        else:
            i += 2
        digrams.append((a, b))

    ciphertext = ""
    for a, b in digrams:
        r1, c1 = find_position(matrix, a)
        r2, c2 = find_position(matrix, b)
        if r1 == r2:
            # same row: shift columns right by 1
            ciphertext += matrix[r1][(c1 + 1) % 5]
            ciphertext += matrix[r2][(c2 + 1) % 5]
        elif c1 == c2:
            # same column: shift rows down by 1
            ciphertext += matrix[(r1 + 1) % 5][c1]
            ciphertext += matrix[(r2 + 1) % 5][c2]
        else:
            # rectangle swap columns
            ciphertext += matrix[r1][c2]
            ciphertext += matrix[r2][c1]
    return ciphertext

# Example usage:
key = "PLAYFAIR EXAMPLE"
plaintext = "HIDE THE GOLD IN THE TREE STUMP"
print("Playfair Cipher:", playfair_encrypt(plaintext.replace(" ", ""), key))
