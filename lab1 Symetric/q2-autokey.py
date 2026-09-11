def clean(s):
    ans = ""
    for c in s.upper():
        if c.isalpha():
            ans += c
    return ans

def encrypt(s, k):
    s = clean(s)
    p = []
    for c in s:
        p.append(ord(c) - ord("A"))
    keys = [k]

    for x in p:
        if len(keys) == len(p):
            break
        keys.append(x)

    ans = ""
    for i in range(len(p)):
        ans += chr((p[i] + keys[i]) % 26 + ord("A"))
    return ans


def decrypt(s, k):
    s = clean(s)
    keys = [k]
    ans = ""
    for i in range(len(s)):
        x = ord(s[i]) - ord("A")
        y = (x - keys[i]) % 26
        ans += chr(y + ord("A"))
        if len(keys) < len(s):
            keys.append(y)
    return ans


s = input("Enter plaintext: ")
k = int(input("Enter numeric key: ")) % 26

c = encrypt(s, k)
p = decrypt(c, k)

print("Ciphertext:", c)
print("Decrypted text:", p)