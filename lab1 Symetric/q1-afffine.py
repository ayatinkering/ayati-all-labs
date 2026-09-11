from math import gcd

def clean(s):
    ans = ""
    for c in s.upper():
        if c.isalpha():
            ans += c
    return ans

# FINDING MI
def mod_inv(a, m):
    for x in range(1, m):
        if (a * x) % m == 1:
            print("MI is: ",x)
            return x
    return None


def encrypt(s, a, b):
    s = clean(s)
    ans = ""
    for c in s:
        x = ord(c) - ord("A")
        ans += chr((a * x + b) % 26 + ord("A"))
    return ans


def decrypt(s, a, b):
    s = clean(s)
    inv = mod_inv(a, 26)
    ans = ""
    for c in s:
        x = ord(c) - ord("A")
        ans += chr((inv * (x - b)) % 26 + ord("A"))
    return ans


s = input("Enter plaintext: ")
a = int(input("Enter multiplicative key a: "))
b = int(input("Enter additive key b: "))

if gcd(a, 26) != 1:
    print("Invalid key. a must be coprime with 26.")
else:
    c = encrypt(s, a, b)
    p = decrypt(c, a, b)

    print("Ciphertext:", c)
    print("Decrypted text:", p)