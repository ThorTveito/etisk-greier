#!/usr/bin/env python3
"""
TASK 2 - "Rock You Like a Hash Cat"                            [Easy-Medium]
Lecture topic: Hash functions, password security, hash cracking

An attacker dumped four password hashes from a database (think of the
SQLi -> hash cracking slides). Recover all four passwords.

When you have all four, call unlock([pw1, pw2, pw3, pw4]) - in the order of
the IDs below - and the flag will be revealed. The flag is encrypted with a
key derived from the passwords, so you really do have to crack them.

Files
  * wordlist.txt   a small wordlist (you may also use rockyou.txt on Kali)

Hints
  * Targets 1-3 are unsalted; target 4 is salted (the salt is public and is
    PREPENDED to the password:  sha256(salt + password)).
  * Users are creative, but not THAT creative. Think about the typical
    mutation rules: Capitalise, leetspeak (a->@, o->0, e->3, ...),
    appended digits / years.
  * You are free to use hashcat or john, but writing your own 20-line Python
    cracker is more fun (and is the intended solution).

Run:  python3 task2_hashes.py
"""
import hashlib

TARGETS = [
    {"id": 1, "algo": "md5", "salt": "", "hash": "0d107d09f5bbe40cade3de5c71e9e9b7"},
    {"id": 2, "algo": "sha1", "salt": "", "hash": "dad1e5f4b84d0ada3f2ab71a4e434efe0ef04020"},
    {"id": 3, "algo": "sha256", "salt": "", "hash": "4c8d6c0b67309bfb02fb9147956322e8eeb4342d32ca00de2bb1dddf83ecbb5b"},
    {"id": 4, "algo": "sha256", "salt": "ntnu_salt_2025$", "hash": "433571706156a710382ae3e72e09dadb1da23e75b5f8d7206e561e45a7d32404"},
]

ENC_FLAG = "53ae6f59b24f238bb51f6c2956270edc08d9d5e64e3085540270d7cbac4d4a9f4fbe6d459a4c1b"


def hash_password(algo, password, salt=""):
    return hashlib.new(algo, (salt + password).encode()).hexdigest()


def unlock(passwords):
    """Pass the four cracked passwords (ordered by target id)."""
    key = hashlib.sha256("|".join(passwords).encode()).digest()
    raw = bytes.fromhex(ENC_FLAG)
    flag = bytes(b ^ key[i % len(key)] for i, b in enumerate(raw))
    if flag.startswith(b"NTNU{") and flag.endswith(b"}"):
        print("Correct! Flag:", flag.decode())
    else:
        print("Not quite - at least one password is wrong or in the wrong order.")


LEET = {"a": "@", "o": "0", "e": "3", "i": "1", "s": "$", "t": "7"}
SUFFIXES = [""] + [str(d) for d in range(10)] + [
    "123", "1234", "!", "1", "12", "2023", "2024", "2025", "01", "007"
]


def mutations(word):
    """Yield typical user password mutations of a wordlist entry:
    case changes, leetspeak substitutions, and appended digits/years."""
    cases = {word, word.lower(), word.upper(), word.capitalize()}
    bases = set(cases)
    for c in cases:
        bases.add("".join(LEET.get(ch, ch) for ch in c))            # full leet
        bases.add("".join(LEET.get(ch, ch) if ch in "aoe" else ch   # vowel leet
                          for ch in c))
    for base in bases:
        for suffix in SUFFIXES:
            yield base + suffix


def crack(targets, wordlist_path="wordlist.txt"):
    words = [w.strip() for w in open(wordlist_path) if w.strip()]
    found = {}
    for word in words:
        for candidate in mutations(word):
            for t in targets:
                if t["id"] not in found and \
                   hash_password(t["algo"], candidate, t["salt"]) == t["hash"]:
                    found[t["id"]] = candidate
            if len(found) == len(targets):
                return found
    return found


if __name__ == "__main__":
    found = crack(TARGETS)
    for t in TARGETS:
        print(f"target {t['id']} ({t['algo']}): {found.get(t['id'], '??? NOT CRACKED')}")
    unlock([found.get(t["id"], "") for t in TARGETS])
