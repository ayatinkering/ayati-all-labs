def find_key(p, c):
    if len(p) != len(c):
        return None

    key = []
    for x in c:
        if x not in p:
            return None
        key.append(p.index(x) + 1)
    return key

p = input("Enter chosen plaintext: ").upper()
c = input("Enter observed ciphertext: ").upper()

key = find_key(p, c)

if key is None:
    print("Cannot determine a valid permutation.")
else:
    print("Permutation key:", key)
    print("Key size:", len(key))