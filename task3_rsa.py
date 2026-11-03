#!/usr/bin/env python3
"""
TASK 3 - "Tiny Primes, Big Problems"                           [Medium]
Lecture topic: RSA algorithm, key generation, factoring

A careless developer copied the "RSA Key Generation" slide and used primes
that are WAY too small. The flag was encrypted with textbook RSA
(no padding):

    * the flag was split into 6-byte chunks (the last chunk was padded with
      NUL bytes, b"\x00", to 6 bytes)
    * every chunk m (big-endian integer) was encrypted as  c = m^e mod n

Recover the flag (format NTNU{...}).

Hints
  * n is only about 49 bits. How long would it take to factor it?
  * Once you have p and q: phi = (p-1)(q-1),  d = e^-1 mod phi
    (Python 3.8+:  pow(e, -1, phi))
  * Convert the decrypted integers back to bytes with int.to_bytes(6, "big")

Run:  python3 task3_rsa.py
"""

n = 889970796180013
e = 65537

ciphertext = [
    283355017161443,
    300083924892126,
    15528015238632,
    591455819941687,
    491941932604380,
]


import math
import random


def pollard_rho(num):
    """Return a non-trivial factor of num (Pollard's rho). n is tiny, so this
    is instant; plain trial division up to sqrt(n) would also work."""
    if num % 2 == 0:
        return 2
    while True:
        x = random.randrange(2, num)
        y = x
        c = random.randrange(1, num)
        d = 1
        while d == 1:
            x = (x * x + c) % num
            y = (y * y + c) % num
            y = (y * y + c) % num
            d = math.gcd(abs(x - y), num)
        if d != num:
            return d


if __name__ == "__main__":
    print("n =", n, f"({n.bit_length()} bits)")
    print("e =", e)
    print("blocks =", len(ciphertext))

    p = pollard_rho(n)
    q = n // p
    assert p * q == n
    print(f"factored: p = {p}, q = {q}")

    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)             # private exponent

    flag = b""
    for c in ciphertext:
        m = pow(c, d, n)           # textbook RSA decryption
        flag += m.to_bytes(6, "big")
    flag = flag.rstrip(b"\x00")    # remove the NUL padding of the last chunk
    print("Flag:", flag.decode())
