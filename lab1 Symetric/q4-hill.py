from math import gcd

def clean(s):
    ans = ""
    for c in s.upper():
        if c.isalpha():
            ans += c
    if len(ans) % 2 != 0:
        ans += "X"
    return ans

# FINDING MI
def mod_inv(a, m):
    a %= m
    for x in range(1, m):
        if (a * x) % m == 1:
            print("MI is: ",x)
            return x
    return None

def inv_matrix(k):
    a = k[0][0]
    b = k[0][1]
    c = k[1][0]
    d = k[1][1]
    det = (a * d - b * c) % 26
    inv = mod_inv(det, 26)

    if inv is None:
        return None
    return [
        [(inv * d) % 26, (inv * -b) % 26],
        [(inv * -c) % 26, (inv * a) % 26]]

def change(a, b, k):
    x = ord(a) - ord("A")
    y = ord(b) - ord("A")

    p = (k[0][0] * x + k[0][1] * y) % 26
    q = (k[1][0] * x + k[1][1] * y) % 26

    return chr(p + ord("A")) + chr(q + ord("A"))


def encrypt(s, k):
    s = clean(s)
    ans = ""
    for i in range(0, len(s), 2):
        ans += change(s[i], s[i + 1], k)
    return ans


def decrypt(s, k):
    ik = inv_matrix(k)
    if ik is None:
        return "Key matrix has no inverse."
    ans = ""

    for i in range(0, len(s), 2):
        ans += change(s[i], s[i + 1], ik)
    return ans


s = input("Enter plaintext: ")

print("Enter the 2 x 2 key matrix:")
a = int(input("Enter a: "))
b = int(input("Enter b: "))
c = int(input("Enter c: "))
d = int(input("Enter d: "))

k = [[a, b], [c, d]]
det = (a * d - b * c) % 26

if gcd(det, 26) != 1:
    print("Invalid key matrix as det isn't coprime with 26")
else:
    ct = encrypt(s, k)
    pt = decrypt(ct, k)

    print("Ciphertext:", ct)
    print("Decrypted text:", pt)