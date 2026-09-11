def clean(s):
    ans = ""
    for c in s.upper():
        if c.isalpha():
            ans += c
    return ans


def encrypt(s, k):
    s = clean(s)
    ans = ""
    for c in s:
        x = ord(c) - ord("A")
        ans += chr((x + k) % 26 + ord("A"))
    return ans


def decrypt(s, k):
    s = clean(s)
    ans = ""
    for c in s:
        x = ord(c) - ord("A")
        ans += chr((x - k) % 26 + ord("A"))
    return ans


s = input("Enter plaintext: ")
k = int(input("Enter key: "))

c = encrypt(s, k)
p = decrypt(c, k)

print("Ciphertext:", c)
print("Decrypted text:", p)