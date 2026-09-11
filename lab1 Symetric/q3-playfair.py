def clean(s):
    ans = ""
    for c in s.upper():
        if c.isalpha():
            if c == "J":
                ans += "I"
            else:
                ans += c
    return ans


def make_matrix(k):
    k = clean(k)
    alpha = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    s = ""
    for c in k + alpha:
        if c not in s:
            s += c

    m = []
    for i in range(5):
        m.append(list(s[i * 5:(i + 1) * 5]))
    return m

def find(m, c):
    for i in range(5):
        for j in range(5):
            if m[i][j] == c:
                return i, j

def prepare(s):
    s = clean(s)
    ans = ""
    i = 0

    while i < len(s):
        a = s[i]

        if i + 1 == len(s):
            b = "X"
            i += 1
        elif a == s[i + 1]:
            b = "X"
            i += 1
        else:
            b = s[i + 1]
            i += 2
        ans += a + b
    return ans


def encrypt(s, m):
    s = prepare(s)
    ans = ""
    for i in range(0, len(s), 2):
        a = s[i]
        b = s[i + 1]

        r1, c1 = find(m, a)
        r2, c2 = find(m, b)
        if r1 == r2:
            ans += m[r1][(c1 + 1) % 5]
            ans += m[r2][(c2 + 1) % 5]
        elif c1 == c2:
            ans += m[(r1 + 1) % 5][c1]
            ans += m[(r2 + 1) % 5][c2]
        else:
            ans += m[r1][c2]
            ans += m[r2][c1]
    return ans


def decrypt(s, m):
    s = clean(s)
    ans = ""

    for i in range(0, len(s), 2):
        a = s[i]
        b = s[i + 1]

        r1, c1 = find(m, a)
        r2, c2 = find(m, b)
        if r1 == r2:
            ans += m[r1][(c1 - 1) % 5]
            ans += m[r2][(c2 - 1) % 5]
        elif c1 == c2:
            ans += m[(r1 - 1) % 5][c1]
            ans += m[(r2 - 1) % 5][c2]
        else:
            ans += m[r1][c2]
            ans += m[r2][c1]
    return ans


s = input("Enter plaintext: ")
k = input("Enter keyword: ")

m = make_matrix(k)
print("\nPLAYFAIR MATRIX:")
for row in m:
    print(" ".join(row))

c = encrypt(s, m)
p = decrypt(c, m)

print("Ciphertext:", c)
print("Decrypted prepared text:", p)