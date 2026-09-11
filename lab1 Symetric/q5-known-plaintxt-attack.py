# ADDITIVE CIPHER

def find_key(p, c):
    x = ord(p[0].upper()) - ord("A")
    y = ord(c[0].upper()) - ord("A")
    return (y - x) % 26


def decrypt(s, k):
    ans = ""
    for c in s.upper():
        if c.isalpha():
            x = ord(c) - ord("A")
            ans += chr((x - k) % 26 + ord("A"))
        else:
            ans += c
    return ans


p = input("Enter known plaintext: ")
c = input("Enter its ciphertext: ")
s = input("Enter target ciphertext: ")

k = find_key(p, c)

print("Recovered key:", k)
print("Recovered plaintext:", decrypt(s, k))