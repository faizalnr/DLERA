
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
import base64
from collections import Counter
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

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

# --------------------------------------------------
# Test
# --------------------------------------------------

if __name__ == "__main__":

    text = ("DLERSA Enhanced Lightweight Cryptography "
            "for SDN Research Framework " * 50)

    priv, pub = generate_rsa()

    ct, wrapped = dlersa_encrypt(text, pub)

    recovered = dlersa_decrypt(
        ct,
        wrapped,
        priv
    )

    print("Recovery Successful :", recovered == text)

    raw = base64.b64decode(ct)

    print("Entropy :", round(entropy(raw), 4))
    print("ChiSquare :", round(chi_square(raw), 2))



# ==================================================
# DLERSA v3 Research Extensions
# Added:
# - Throughput
# - Memory Usage
# - Correlation
# - Avalanche Effect
# - Key Sensitivity
# - CSV/XLSX Export
# - Output Folder
# - Plot Generation
# ==================================================

import os, time, psutil
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

OUTPUT_DIR = "Output"
os.makedirs(OUTPUT_DIR, exist_ok=True)

def correlation(data):
    if len(data) < 2:
        return 0
    x = np.array(list(data[:-1]), dtype=float)
    y = np.array(list(data[1:]), dtype=float)
    return float(np.corrcoef(x,y)[0,1])

def avalanche_test(text):
    key = generate_session_key()
    c1 = encrypt_block(text.encode(), key)

    altered = bytearray(text.encode())
    altered[0] ^= 1
    c2 = encrypt_block(bytes(altered), key)

    b1=''.join(format(x,'08b') for x in c1)
    b2=''.join(format(x,'08b') for x in c2)

    return sum(a!=b for a,b in zip(b1,b2))*100/len(b1)

def key_sensitivity(text):
    k1 = generate_session_key()
    k2 = bytearray(k1)
    k2[0] ^= 1

    c1 = encrypt_block(text.encode(), k1)
    c2 = encrypt_block(text.encode(), bytes(k2))

    return sum(a!=b for a,b in zip(c1,c2))*100/len(c1)

def generate_research_outputs():
    text = ("DLERSA Enhanced Lightweight Cryptography for SDN " * 200)

    priv,pub = generate_rsa()

    start=time.perf_counter()
    ct,wrapped = dlersa_encrypt(text,pub)
    enc_time=time.perf_counter()-start

    start=time.perf_counter()
    recovered=dlersa_decrypt(ct,wrapped,priv)
    dec_time=time.perf_counter()-start

    raw = base64.b64decode(ct)

    results = {
        "EncryptionTime":[enc_time],
        "DecryptionTime":[dec_time],
        "Throughput":[len(text.encode())/enc_time],
        "Entropy":[entropy(raw)],
        "ChiSquare":[chi_square(raw)],
        "Avalanche":[avalanche_test(text)],
        "KeySensitivity":[key_sensitivity(text)],
        "Correlation":[correlation(raw)],
        "MemoryMB":[psutil.Process().memory_info().rss/(1024*1024)]
    }

    df = pd.DataFrame(results)
    df.to_csv(os.path.join(OUTPUT_DIR,"results.csv"),index=False)
    df.to_excel(os.path.join(OUTPUT_DIR,"results.xlsx"),index=False)

    for col in df.columns:
        plt.figure()
        plt.bar([col],[float(df[col].iloc[0])])
        plt.title(col)
        plt.savefig(os.path.join(OUTPUT_DIR,f"{col}.png"))
        plt.close()

    with open(os.path.join(OUTPUT_DIR,"summary_report.txt"),"w") as f:
        f.write("Recovery Successful: %s\n" % (recovered==text))
        for k,v in results.items():
            f.write(f"{k}: {v[0]}\n")

if __name__ == "__main__":
    generate_research_outputs()
