from collections import Counter

def sanitize(s):
    return ''.join(ch for ch in (s or "").upper() if ch.isalpha())

def vigenere_decrypt(ciphertext, key):
    ct = sanitize(ciphertext)
    key = sanitize(key)
    if len(key) == 0:
        return ""
    out = []
    for i, c in enumerate(ct):
        k = ord(key[i % len(key)]) - 65
        out.append(chr((ord(c) - 65 - k) % 26 + 65))
    return ''.join(out)

def shift_decrypt(ciphertext, shift_key):
    ct = sanitize(ciphertext)
    return ''.join(chr((ord(c) - 65 - (shift_key % 26)) % 26 + 65) for c in ct)

ENGLISH_FREQ = [
    0.08167,0.01492,0.02782,0.04253,0.12702,0.02228,0.02015,0.06094,
    0.06966,0.00153,0.00772,0.04025,0.02406,0.06749,0.07507,0.01929,
    0.00095,0.05987,0.06327,0.09056,0.02758,0.00978,0.02360,0.00150,
    0.01974,0.00074
]

def index_of_coincidence(text):
    N = len(text)
    if N <= 1:
        return 0.0
    freq = Counter(text)
    return sum(v * (v - 1) for v in freq.values()) / (N * (N - 1))

def chi_squared_stat(observed_counts, expected_probs, group_len):
    chi = 0.0
    for i in range(26):
        letter = chr(65 + i)
        obs = observed_counts.get(letter, 0)
        exp = expected_probs[i] * group_len
        if exp > 0:
            chi += ((obs - exp) ** 2) / exp
    return chi

def break_vigenere_columns(ciphertext, key_length):
    ct = sanitize(ciphertext)
    N = len(ct)
    keyprime = []
    for i in range(key_length):
        seq = ''.join(ct[j] for j in range(i, N, key_length))
        if len(seq) == 0:
            keyprime.append('A')
            continue
        best_shift = 0
        best_chi = None
        for shift in range(26):
            decrypted = [chr((ord(c) - 65 - shift) % 26 + 65) for c in seq]
            counts = Counter(decrypted)
            chi = chi_squared_stat(counts, ENGLISH_FREQ, len(seq))
            if best_chi is None or chi < best_chi:
                best_chi = chi
                best_shift = shift
        keyprime.append(chr(best_shift + 65))
    return ''.join(keyprime)

def simple_frequency_attack(ciphertext, min_k=4, max_k=20, top_candidates=5):
    ct = sanitize(ciphertext)
    N = len(ct)
    if N == 0:
        raise ValueError("Empty ciphertext after sanitization.")
    max_k = min(max_k, max(1, N))
    # Estimate IC for candidate key lengths
    ic_list = []
    for k in range(min_k, max_k + 1):
        ics = []
        for i in range(k):
            seq = ''.join(ct[j] for j in range(i, N, k))
            ics.append(index_of_coincidence(seq))
        avg_ic = sum(ics) / len(ics) if ics else 0
        ic_list.append((k, avg_ic))
    ic_list.sort(key=lambda x: x[1], reverse=True)
    candidates = [k for k, _ in ic_list[:top_candidates]]

    # Try each candidate key length
    best_overall = (None, None, None, float('inf'))  
    for k in candidates:
        keyprime = break_vigenere_columns(ct, k)
        for shift_try in range(26):
            stage1 = shift_decrypt(ct, shift_try)
            recovered = vigenere_decrypt(stage1, keyprime)
            counts = Counter(recovered)
            chi = chi_squared_stat(counts, ENGLISH_FREQ, len(recovered))
            if chi < best_overall[3]:
                orig_key = ''.join(chr((ord(ch) - 65 - shift_try) % 26 + 65) for ch in keyprime)
                best_overall = (orig_key, shift_try, recovered, chi)
    return candidates, best_overall

if __name__ == "__main__":
    print("=== Simple Frequency-Only Attack ===")
    ciphertext = input("Enter FULL ciphertext:\n> ").strip()
    if not ciphertext:
        print("[!] No ciphertext provided. Exiting.")
        exit(1)
    try:
        min_k = int(input("Min key length to test (default 4): ") or "4")
        max_k = int(input("Max key length to test (default 20): ") or "20")
        top_cand = int(input("How many top key-lengths to try (default 5): ") or "5")
    except ValueError:
        print("[!] Invalid inputs; using defaults 4,20,5.")
        min_k, max_k, top_cand = 4, 20, 5

    print("\n[*] Estimating likely key lengths (by average IC)...")
    candidates, best = simple_frequency_attack(ciphertext, min_k=min_k, max_k=max_k, top_candidates=top_cand)
    print("Key-length candidates tried (top):", candidates)
    orig_key, shift_try, plaintext, score = best
    if orig_key is None:
        print("[!] Attack produced no candidate.")
    else:
        print("\n=== Best candidate ===")
        print("Recovered Vigenère key (candidate):", orig_key)
        print("Recovered shift (candidate):", shift_try)
        print("Chi-squared score (lower is better):", score)
        print("\nRecovered plaintext (first 1000 chars):\n")
        print(plaintext[:1000])

