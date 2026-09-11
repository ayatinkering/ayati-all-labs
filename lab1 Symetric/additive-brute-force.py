def decrypt(s, k):
    ans = ""

    for c in s.upper():
        if c.isalpha():
            x = ord(c) - ord("A")
            ans += chr((x - k) % 26 + ord("A"))
        else:
            ans += c

    return ans


s = input("Enter ciphertext: ")

for k in range(26):
    print("Key", k, ":", decrypt(s, k))