def clean(s):
    ans = ""
    for c in s.upper():
        if c.isalpha():
            ans += c
    return ans

def encrypt(s, k):
    s = clean(s)
    k = clean(k) # clean keytext also
    ans = ""
    for i in range(len(s)):
        x = ord(s[i]) - ord("A")
        y = ord(k[i % len(k)]) - ord("A")
        ans += chr((x + y) % 26 + ord("A"))
    return ans


def decrypt(s, k):
    s = clean(s)
    k = clean(k)
    ans = ""
    for i in range(len(s)):
        x = ord(s[i]) - ord("A")
        y = ord(k[i % len(k)]) - ord("A")
        ans += chr((x - y) % 26 + ord("A"))
    return ans

s = input("Enter plaintext: ")
k = input("Enter keyword: ")

if clean(k) == "":
    print("Keyword cannot be empty.")
else:
    c = encrypt(s, k)
    p = decrypt(c, k)

    print("Ciphertext:", c)
    print("Decrypted text:", p)