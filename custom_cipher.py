# custom_cipher.py
from collections import Counter

def sanitize(s):
    """Return uppercase letters only (A-Z)."""
    return ''.join(ch for ch in s.upper() if ch.isalpha())

# -------------------------------
# 1. Vigenère Cipher Functions
# -------------------------------
def vigenere_encrypt(plaintext, key):
    plaintext = sanitize(plaintext)
    key = sanitize(key)
    ciphertext = ""
    if len(key) == 0:
        raise ValueError("Vigenère key must contain letters.")
    for i, char in enumerate(plaintext):
        shift = ord(key[i % len(key)]) - 65
        new_char = chr((ord(char) - 65 + shift) % 26 + 65)
        ciphertext += new_char
    return ciphertext


def vigenere_decrypt(ciphertext, key):
    ciphertext = sanitize(ciphertext)
    key = sanitize(key)
    plaintext = ""
    if len(key) == 0:
        raise ValueError("Vigenère key must contain letters.")
    for i, char in enumerate(ciphertext):
        shift = ord(key[i % len(key)]) - 65
        new_char = chr((ord(char) - 65 - shift) % 26 + 65)
        plaintext += new_char
    return plaintext


# -------------------------------
# 2. Shift (Caesar) Cipher Functions
# -------------------------------
def shift_encrypt(text, shift_key):
    text = sanitize(text)
    ciphertext = ""
    for char in text:
        ciphertext += chr((ord(char) - 65 + (shift_key % 26)) % 26 + 65)
    return ciphertext


def shift_decrypt(ciphertext, shift_key):
    ciphertext = sanitize(ciphertext)
    plaintext = ""
    for char in ciphertext:
        plaintext += chr((ord(char) - 65 - (shift_key % 26)) % 26 + 65)
    return plaintext


# -------------------------------
# 3. Combined Custom Cipher
# -------------------------------
def custom_encrypt(plaintext, key_vigenere, key_shift):
    # Input validation (sanitized inside sub-functions as well)
    if len(sanitize(key_vigenere)) < 1:
        raise ValueError("Vigenère key must be non-empty and alphabetic.")
    stage1 = vigenere_encrypt(plaintext, key_vigenere)
    stage2 = shift_encrypt(stage1, key_shift)
    return stage2


def custom_decrypt(ciphertext, key_vigenere, key_shift):
    if len(sanitize(key_vigenere)) < 1:
        raise ValueError("Vigenère key must be non-empty and alphabetic.")
    stage1 = shift_decrypt(ciphertext, key_shift)
    stage2 = vigenere_decrypt(stage1, key_vigenere)
    return stage2


# -------------------------------
# 4. Example Run (User Input)
# -------------------------------
if __name__ == "__main__":
    plaintext = input("Enter your plaintext: ").strip()
    key_vigenere = input("Enter Vigenère key (min 10 letters): ").strip()
    if len(sanitize(key_vigenere)) < 10:
        print("[!] Vigenère key must be at least 10 letters (A-Z).")
        exit(1)
    try:
        key_shift = int(input("Enter numeric Shift key (e.g. 3 or 5): "))
    except ValueError:
        print("[!] Shift key must be an integer.")
        exit(1)

    ciphertext = custom_encrypt(plaintext, key_vigenere, key_shift)
    decrypted = custom_decrypt(ciphertext, key_vigenere, key_shift)

    print("\n===============================")
    print("Plaintext:  ", sanitize(plaintext))
    print("Ciphertext: ", ciphertext)
    print("Decrypted:  ", decrypted)
    print("===============================")
