from math import gcd

def clean(s):
    ans = ""
    for c in s.upper():
        if c.isalpha():
            ans += c

    return ans

# FINDING MULTIPLICATIVE INVERSE IN MOD m=26
def mod_inv(a, m):
    for x in range(1, m):
        if (a * x) % m == 1:
            print("MI is: ",x)
            return x
    return None


def encrypt(s, k):
    s = clean(s)
    ans = ""
    for c in s:
        x = ord(c) - ord("A")
        ans += chr((x * k) % 26 + ord("A"))
    return ans


def decrypt(s, k):
    s = clean(s)
    inv = mod_inv(k, 26)
    ans = ""
    for c in s:
        x = ord(c) - ord("A")
        ans += chr((x * inv) % 26 + ord("A"))
    return ans


s = input("Enter plaintext: ")
k = int(input("Enter key: "))

if gcd(k, 26) != 1:
    print("Invalid key. Key must be coprime with 26.")
else:
    c = encrypt(s, k)
    p = decrypt(c, k)

    print("Ciphertext:", c)
    print("Decrypted text:", p)