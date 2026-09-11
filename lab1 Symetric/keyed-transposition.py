def change(s, key):
    ans = ""
    for x in key:
        ans += s[x - 1]
    return ans


def inv_key(key):
    inv = [0] * len(key)
    for i in range(len(key)):
        inv[key[i] - 1] = i + 1
    return inv


def pad(s, n):
    while len(s) % n != 0:
        s += "X"
    return s


def encrypt(s, key):
    s = s.replace(" ", "").upper()
    n = len(key)
    s = pad(s, n)
    ans = ""

    for i in range(0, len(s), n):
        ans += change(s[i:i + n], key)
    return ans


def decrypt(s, key):
    key = inv_key(key)
    n = len(key)
    ans = ""

    for i in range(0, len(s), n):
        ans += change(s[i:i + n], key)
    return ans


s = input("Enter plaintext: ")
key = list(map(int, input("Enter permutation: ").split()))

n = len(key)

if sorted(key) != list(range(1, n + 1)):
    print("Invalid permutation.")
else:
    c = encrypt(s, key)
    p = decrypt(c, key)

    print("Ciphertext:", c)
    print("Decrypted text:", p)