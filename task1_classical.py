#!/usr/bin/env python3
"""
TASK 1 - "Caesar's Column"                                     [Easy]
Lecture topic: Classical Cryptography (substitution + transposition)

A message was protected with TWO classical ciphers, applied in this order:

    1. Columnar transposition  (keyword = 6 DIFFERENT letters, unknown)
    2. Caesar cipher           (shift between 1 and 25, unknown)

The full encryption code is below. The ciphertext is at the bottom.
Your job: recover the plaintext. The flag has the format NTNU{...}

Hints
  * Only the letters A-Z are shifted by the Caesar step. Everything else stays.
  * The plaintext is upper-case English. The transposition was padded with 'X'.
  * A 6-letter keyword only has 6! = 720 possible column orders.
  * Think about how many total (order, shift) combinations exist, and how you
    could recognise the right one automatically.
  * Careful: finding "NTNU{" is NOT enough - swapping two columns that do not
    touch the flag leaves the flag readable but the rest garbled. Score every
    candidate (e.g. count common English words like THE / IS / AFTER) and keep
    the best one.

Run:  python3 task1_classical.py
"""

def caesar(text, shift):
    out = []
    for ch in text:
        if "A" <= ch <= "Z":
            out.append(chr((ord(ch) - 65 + shift) % 26 + 65))
        else:
            out.append(ch)
    return "".join(out)


def columnar_encrypt(text, key, pad_char="X"):
    cols = len(key)
    while len(text) % cols:
        text += pad_char
    rows = [text[i:i + cols] for i in range(0, len(text), cols)]
    # columns are read in alphabetical order of the key letters
    order = sorted(range(cols), key=lambda i: (key[i], i))
    return "".join(row[c] for c in order for row in rows)


def encrypt(plaintext, key, shift):
    return caesar(columnar_encrypt(plaintext, key), shift)


def columnar_decrypt(ciphertext, order):
    """Invert columnar_encrypt for a given column read-order.

    `order` is the permutation of column indices that encryption read the
    columns in (order[k] = original column that produced the k-th chunk).
    The ciphertext is a multiple of len(order); it is split into len(order)
    equal column-chunks, each chunk is put back in its original column, and
    the grid is read row by row to recover the (padded) plaintext.
    """
    cols = len(order)
    rows = len(ciphertext) // cols
    chunks = [ciphertext[i * rows:(i + 1) * rows] for i in range(cols)]
    grid_cols = [None] * cols
    for k, c in enumerate(order):
        grid_cols[c] = chunks[k]
    return "".join(grid_cols[c][r] for r in range(rows) for c in range(cols))


# Common English words used to score candidate plaintexts, so we keep the
# genuinely-English decryption rather than any text that merely contains NTNU{.
_WORDS = ["THE", "AND", "IS", "AFTER", "OF", "TO", "IN", "THAT", "SECRET",
          "MESSAGE", "DESTROY", "READING", "AGENT", "CONGRATULATIONS"]


def english_score(text):
    score = sum(text.count(w) for w in _WORDS)
    if "NTNU{" in text:
        score += 50
    return score


CIPHERTEXT = "TKFVYI WER__JJRIXIKR VZLLRZVVUPIZOXR .J EH_JMV FVUOFLEEVVEITCEJ}KWV.ECJK KKVPPVC.IKRORZXKTJ{VEJIGV  EO"


def solve(ciphertext):
    """Brute force all (column order, Caesar shift) pairs and return the best.

    6-letter keyword -> 6! = 720 column orders; Caesar shift 1-25.
    Decryption is the reverse of encryption: undo Caesar, then undo the
    columnar transposition. Each candidate is scored for English.
    """
    from itertools import permutations
    best = None  # (score, shift, order, plaintext)
    for shift in range(26):
        unshifted = caesar(ciphertext, -shift)       # undo Caesar
        for order in permutations(range(6)):
            plaintext = columnar_decrypt(unshifted, order)
            score = english_score(plaintext)
            if best is None or score > best[0]:
                best = (score, shift, order, plaintext)
    return best


if __name__ == "__main__":
    import re
    print("Ciphertext:", CIPHERTEXT)
    score, shift, order, plaintext = solve(CIPHERTEXT)
    print(f"Caesar shift : {shift}")
    print(f"Column order : {order}")
    print(f"Plaintext    : {plaintext}")
    match = re.search(r"NTNU\{[^}]*\}", plaintext)
    print("Flag         :", match.group(0) if match else "(not found)")
