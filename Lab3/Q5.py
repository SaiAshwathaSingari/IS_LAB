import time
import random

p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1  # example safe prime (not full)
g = 2

def generate_private_key(p):
    return random.randint(2, p - 2)

def generate_public_key(private_key, p, g):
    return pow(g, private_key, p)

def compute_shared_secret(their_public, private_key, p):
    return pow(their_public, private_key, p)

# Peer A
start = time.time()
a_private = generate_private_key(p)
a_public = generate_public_key(a_private, p, g)
end = time.time()
print(f"Peer A key generation time: {end - start:.5f}s")

# Peer B
start = time.time()
b_private = generate_private_key(p)
b_public = generate_public_key(b_private, p, g)
end = time.time()
print(f"Peer B key generation time: {end - start:.5f}s")

# Key exchange and shared secret computation
start = time.time()
shared_secret_a = compute_shared_secret(b_public, a_private, p)
shared_secret_b = compute_shared_secret(a_public, b_private, p)
end = time.time()
print(f"Key exchange and shared secret computation time: {end - start:.5f}s")

print("Shared secret equal:", shared_secret_a == shared_secret_b)
