
"""
Enhanced DLERSA v2.1 (Corrected)
Fixes:
1. Reversible permutation using stored deterministic index
2. Correct inverse permutation
3. Verified encrypt/decrypt symmetry
4. Safe UTF-8 recovery check
"""

import random
import hashlib
import math
import time
import psutil
import os
import base64
from collections import Counter
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import matplotlib.pyplot as plt

ROUNDS = 8

# --------------------------------------------------
# Chaos Key
# --------------------------------------------------

def logistic_sequence(seed, n, r=3.999):
    x = seed
    seq = []
    for _ in range(n):
        x = r * x * (1 - x)
        seq.append(x)
    return seq

def generate_session_key(length=32):
    seq = logistic_sequence(random.uniform(0.1, 0.9), length)
    return bytes(int((v * 1e6) % 256) for v in seq)

# --------------------------------------------------
# Dynamic SBOX
# --------------------------------------------------

def create_sbox(key):
    vals = list(range(256))
    seed = int(hashlib.sha256(key).hexdigest(), 16)
    rnd = random.Random(seed)
    rnd.shuffle(vals)

    inv = [0] * 256
    for i, v in enumerate(vals):
        inv[v] = i

    return vals, inv

# --------------------------------------------------
# Permutation
# --------------------------------------------------

def get_permutation(length, key):
    seed = int(hashlib.sha256(key).hexdigest(), 16)
    rnd = random.Random(seed)

    idx = list(range(length))
    rnd.shuffle(idx)

    return idx

def permute(data, idx):
    out = bytearray(len(data))
    for i, j in enumerate(idx):
        out[i] = data[j]
    return bytes(out)

def inverse_permute(data, idx):
    out = bytearray(len(data))
    for i, j in enumerate(idx):
        out[j] = data[i]
    return bytes(out)

# --------------------------------------------------
# Encryption
# --------------------------------------------------

def encrypt_block(data, key):

    sbox, _ = create_sbox(key)

    buf = bytes(data)

    for r in range(ROUNDS):

        # substitution
        buf = bytes(sbox[b] for b in buf)

        # permutation
        idx = get_permutation(
            len(buf),
            key + bytes([r])
        )
        buf = permute(buf, idx)

        # diffusion
        temp = bytearray(buf)

        prev = key[r % len(key)]

        for i in range(len(temp)):
            temp[i] ^= prev
            prev = temp[i]

        buf = bytes(temp)

    return buf

# --------------------------------------------------
# Decryption
# --------------------------------------------------

def decrypt_block(data, key):

    _, inv_sbox = create_sbox(key)

    buf = bytes(data)

    for r in reversed(range(ROUNDS)):

        # reverse diffusion
        temp = bytearray(len(buf))

        prev = key[r % len(key)]

        for i in range(len(buf)):
            cur = buf[i]
            temp[i] = cur ^ prev
            prev = cur

        buf = bytes(temp)

        # inverse permutation
        idx = get_permutation(
            len(buf),
            key + bytes([r])
        )

        buf = inverse_permute(buf, idx)

        # inverse substitution
        buf = bytes(inv_sbox[b] for b in buf)

    return buf

# --------------------------------------------------
# RSA Wrapper
# --------------------------------------------------

def generate_rsa():
    k = RSA.generate(2048)
    return k, k.publickey()

def dlersa_encrypt(text, pub):

    key = generate_session_key()

    cipher = encrypt_block(
        text.encode("utf-8"),
        key
    )

    wrapped = PKCS1_OAEP.new(pub).encrypt(key)

    return base64.b64encode(cipher), wrapped

def dlersa_decrypt(ciphertext, wrapped, priv):

    key = PKCS1_OAEP.new(priv).decrypt(wrapped)

    plain = decrypt_block(
        base64.b64decode(ciphertext),
        key
    )

    return plain.decode("utf-8")

# --------------------------------------------------
# Analysis
# --------------------------------------------------

def entropy(data):
    freq = Counter(data)
    n = len(data)
    return -sum((c/n) * math.log2(c/n)
                for c in freq.values())

def chi_square(data):

    obs = [0] * 256

    for b in data:
        obs[b] += 1

    exp = len(data) / 256

    return sum(
        ((o-exp)**2)/exp
        for o in obs
        if exp > 0
    )

def throughput(data_size, enc_time):
    return data_size / enc_time

def avalanche_test(text):

    modified = list(text)

    modified[0] = chr(ord(modified[0]) ^ 1)

    modified = "".join(modified)

    key = generate_session_key()

    c1 = encrypt_block(text.encode(), key)

    c2 = encrypt_block(modified.encode(), key)

    b1 = ''.join(format(x,'08b') for x in c1)
    b2 = ''.join(format(x,'08b') for x in c2)

    diff = sum(a != b for a,b in zip(b1,b2))

    return diff/len(b1)*100

def key_sensitivity(text):

    key1 = generate_session_key()

    key2 = bytearray(key1)

    key2[0] ^= 1

    c1 = encrypt_block(text.encode(), key1)

    c2 = encrypt_block(text.encode(), bytes(key2))

    diff = sum(a != b for a,b in zip(c1,c2))

    return diff/len(c1)*100

def frequency_plot(data):

    freq = [0]*256

    for b in data:
        freq[b]+=1

    plt.figure(figsize=(12,4))
    plt.plot(freq)

    plt.title("Cipher Byte Frequency")
    plt.xlabel("Byte Value")
    plt.ylabel("Frequency")

    plt.grid(True)

    plt.savefig("byte_frequency.png")

def histogram_comparison(plain,cipher):

    plt.figure(figsize=(10,4))

    plt.subplot(1,2,1)

    plt.hist(plain.encode(), bins=50)

    plt.title("Plaintext Histogram")

    plt.subplot(1,2,2)

    plt.hist(cipher, bins=50)

    plt.title("Cipher Histogram")

    plt.savefig("histogram_comparison.png")
    


# --------------------------------------------------
# Test
# --------------------------------------------------

if __name__ == "__main__":

    text = ("DLERSA Enhanced Lightweight Cryptography "
            "for SDN Research Framework " * 50)
    start = time.perf_counter()
    priv, pub = generate_rsa()
    
    ct, wrapped = dlersa_encrypt(text, pub)
    enc_time = time.perf_counter() - start
    
    start = time.perf_counter()
    recovered = dlersa_decrypt(ct, wrapped, priv)
    dec_time = time.perf_counter() - start
    raw = base64.b64decode(ct)
    tp = throughput(len(text.encode()), enc_time)
    process = psutil.Process(os.getpid())
    memory = process.memory_info().rss / (1024*1024)
    
    
    algorithms = ["RSA","AES","DLERSA"]
    enc_times = [rsa_time,aes_time,enc_time]
    plt.figure(figsize=(6,4))
    plt.bar(algorithms, enc_times)
    plt.ylabel("Time (s)")
    plt.title("Encryption Time Comparison")
    plt.savefig("encryption_comparison.png")
    
    entropy_values = [rsa_entropy,aes_entropy,entropy(raw)]
    plt.figure(figsize=(6,4))
    plt.bar(["RSA","AES","DLERSA"], entropy_values)
    plt.title("Entropy Comparison")
    plt.ylabel("Entropy")
    plt.savefig("entropy_comparison.png")
    
    chi_values = [
    rsa_chi,
    aes_chi,
    chi_square(raw)
    ]
    
    plt.figure(figsize=(6,4))
    
    plt.bar(["RSA","AES","DLERSA"],chi_values)

    plt.ylabel("Chi Square")
    
    plt.title("Randomness Comparison")
    
    plt.savefig("chi_square_comparison.png")


    print("Memory Usage (MB):", memory)
    print("Throughput (Bytes/s):", tp)
    print("Entropy :", round(entropy(raw), 4))
    print("ChiSquare :", round(chi_square(raw), 2))
    print("Encryption Time:", enc_time)
    print("Decryption Time:", dec_time)
    print("Recovery Successful :", recovered == text)

    
