from collections import Counter

def sanitize(s):
    return ''.join(ch for ch in s.upper() if ch.isalpha())

def vigenere_decrypt(ciphertext, key):
    ciphertext = sanitize(ciphertext)
    key = sanitize(key)
    if len(key) == 0:
        raise ValueError("Vigenère key must contain letters.")
    return ''.join(chr((ord(c)-65 - (ord(key[i % len(key)])-65))%26 + 65) for i,c in enumerate(ciphertext))

def shift_decrypt(ciphertext, shift_key):
    ciphertext = sanitize(ciphertext)
    return ''.join(chr((ord(c)-65 - (shift_key%26))%26 + 65) for c in ciphertext)

def infer_key_fragment(known_plain, known_vchunk):
    kp = sanitize(known_plain)
    vc = sanitize(known_vchunk)
    frag = []
    for p, v in zip(kp, vc):
        frag.append(chr(((ord(v) - ord(p)) % 26) + 65))
    return ''.join(frag)

def smallest_period(s):
    for p in range(1, len(s)+1):
        if s == (s[:p] * (len(s)//p + 1))[:len(s)]:
            return p
    return len(s)

def known_plaintext_attack(known_plaintext, known_ciphertext_segment, full_ciphertext):
    kp = sanitize(known_plaintext)
    kc = sanitize(known_ciphertext_segment)
    fc = sanitize(full_ciphertext)
    if len(kp) == 0 or len(kc) == 0 or len(kp) != len(kc):
        raise ValueError("Known plaintext and ciphertext must be same length and non-empty.")
    for shift_try in range(26):
        vchunk = shift_decrypt(kc, shift_try)
        keyfrag = infer_key_fragment(kp, vchunk)
        period = smallest_period(keyfrag)
        candidate_key = keyfrag[:period]
        stage1 = shift_decrypt(fc, shift_try)
        recovered = vigenere_decrypt(stage1, candidate_key)
        if kp in recovered:
            return candidate_key, shift_try, recovered
    return None, None, None

def search_alignment_and_attack(known_plaintext, full_ciphertext):
    kp = sanitize(known_plaintext)
    fc = sanitize(full_ciphertext)
    for i in range(0, len(fc) - len(kp) + 1):
        kc_segment = fc[i:i+len(kp)]
        key, shift, rec = known_plaintext_attack(kp, kc_segment, fc)
        if key:
            return i, key, shift, rec
    return None, None, None, None


if __name__ == "__main__":
    print("=== Known-Plaintext Attack  ===")
    full_cipher = input("Enter FULL ciphertext:\n> ").strip()
    known_plain = input("\nEnter KNOWN plaintext segment:\n> ").strip()
    known_cipher = input("\nEnter corresponding ciphertext segment:\n> ").strip()

    if not full_cipher or not known_plain:
        print("\n[!] Ciphertext and known plaintext are required.")
        exit(1)

    if known_cipher:
        print("\n[*] Using provided known-ciphertext alignment...")
        k, s, rec = known_plaintext_attack(known_plain, known_cipher, full_cipher)
        if k:
            print("\n=== Attack Successful ===")
            print(f"Recovered Vigenère key candidate: {k}")
            print(f"Recovered shift candidate: {s}")
            print("\nRecovered plaintext:")
            print(rec)
        else:
            print("\n[!] Attack failed. Try checking alignment or provide longer known segment.")
    else:
        print("\n[*] No known ciphertext segment provided — searching for alignment automatically...")
        pos, k, s, rec = search_alignment_and_attack(known_plain, full_cipher)
        if pos is not None:
            print("\n=== Attack Successful ===")
            print(f"Found alignment at ciphertext index: {pos}")
            print(f"Recovered Vigenère key candidate: {k}")
            print(f"Recovered shift candidate: {s}")
            print("\nRecovered plaintext:")
            print(rec)
        else:
            print("\n[!] Attack failed. Try providing known ciphertext segment or longer plaintext.")
