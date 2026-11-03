#!/usr/bin/env python3
"""
TASK 4 - "Clockwork Key"                                       [Medium-Hard]
Lecture topic: Symmetric encryption (AES-CBC), entropy and randomness

A developer encrypted a secret with AES-128-CBC (just like the AES demo
slide). To "generate a random key" they seeded Python's random module with
the current Unix timestamp. The leaked server log says the file was
encrypted at some point on 2025-10-24 (UTC).

The encrypted blob is base64( IV (16 bytes) || ciphertext ), PKCS#7 padded.
Recover the flag (format NTNU{...}).

Hints
  * How many seconds are there in a day?
  * You do NOT need to know the key. You only need to know how it was made.
  * A wrong key almost always produces invalid padding or garbage. Check for
    the flag prefix b"NTNU{" to know when you have succeeded.

Requirements:  pip install pycryptodome
Run:  python3 task4_aes.py
"""
import base64
import random

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# Window from the server log: 2025-10-24 00:00:00 UTC  ..  2025-10-24 23:59:59 UTC
WINDOW_START = 1761264000
WINDOW_END = 1761350400


def generate_key(seed):
    """The vulnerable key generator used by the developer."""
    r = random.Random(seed)
    return bytes(r.getrandbits(8) for _ in range(16))


BLOB = "Ej3Y9JLHHq6fnvNuCyzUY9jXlRBMBxp1mvCYTnZ0uqKWpEdVV6iaRYTjsX5SGkR5TvdvPrq/7ClQdkaJ37h/Jw=="


def decrypt(blob_b64, key):
    raw = base64.b64decode(blob_b64)
    iv, ct = raw[:16], raw[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size)


if __name__ == "__main__":
    print("Encrypted blob:", BLOB)
    # The key depends only on the seed, which is a Unix timestamp somewhere in
    # the one-day window -> only 86400 possible keys. Brute-force them all.
    for seed in range(WINDOW_START, WINDOW_END):
        key = generate_key(seed)
        try:
            plaintext = decrypt(BLOB, key)
        except ValueError:
            continue               # wrong key -> invalid PKCS#7 padding
        if plaintext.startswith(b"NTNU{"):
            print(f"seed = {seed}  ({seed - WINDOW_START}s into the day)")
            print("Flag:", plaintext.decode())
            break
    else:
        print("No seed in the window produced a valid flag.")
