# AFFINE KNOWN PLAINTEXT ATTACK
from math import gcd

def clean(s):
    ans = ""
    for c in s.upper():
        if c.isalpha():
            ans += c
    return ans


def mod_inv(a, m):
    for x in range(1, m):
        if (a * x) % m == 1:
            print("MI: ",x)
            return x
    return None


def decrypt(s, a, b):
    s = clean(s)
    inv = mod_inv(a, 26)
    ans = ""
    for c in s:
        x = ord(c) - ord("A")
        ans += chr((inv * (x - b)) % 26 + ord("A"))
    return ans


def find_keys(p, c):
    p = clean(p)
    c = clean(c)
    keys = []

    for a in range(26):
        if gcd(a, 26) != 1:
            continue

        for b in range(26):
            ok = True

            for i in range(len(p)):
                x = ord(p[i]) - ord("A")
                y = ord(c[i]) - ord("A")

                if (a * x + b) % 26 != y:
                    ok = False
                    break

            if ok:
                keys.append((a, b))
    return keys

p = input("Enter known plaintext: ")
c = input("Enter its ciphertext: ")
s = input("Enter target ciphertext: ")

keys = find_keys(p, c)

if len(keys) == 0:
    print("No key found.")
else:
    for a, b in keys:
        print("Key: a =", a, "b =", b)
        print("Plaintext:", decrypt(s, a, b))