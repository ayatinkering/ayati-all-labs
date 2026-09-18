key = input("Enter key: ")                              # key entered by user

print("\nKey length:", len(key), "characters")         # show character length

if len(key) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in key):
    x = input("Looks like HEX. Treat it as HEX? (y/n): ")  # choose HEX or text

    if x.lower() == "y":
        key_bytes = len(bytes.fromhex(key))             # HEX -> actual byte length
        print("Key length:", key_bytes, "bytes")        # show byte length

        if key_bytes == 8:
            print("Use DES")
        elif key_bytes == 16:
            print("Use AES-128")
        elif key_bytes == 24:
            print("Use AES-192")
        elif key_bytes == 32:
            print("Use AES-256")
        else:
            print("No standard DES/AES key size.")
    else:
        key_bytes = len(key.encode())                   # normal text -> byte length
        print("Key length:", key_bytes, "bytes")        # show byte length

        if key_bytes < 8:
            print("Use DES, but add X until it becomes 8 bytes.")
        elif key_bytes == 8:
            print("Use DES")
        elif key_bytes == 16:
            print("Use AES-128")
        elif key_bytes == 24:
            print("Use AES-192")
        elif key_bytes == 32:
            print("Use AES-256")
        else:
            print("No standard DES/AES key size.")

else:
    key_bytes = len(key.encode())                       # normal text -> byte length
    print("Key length:", key_bytes, "bytes")             # show byte length

    if key_bytes < 8:
        print("Use DES, but add X until it becomes 8 bytes.")
    elif key_bytes == 8:
        print("Use DES")
    elif key_bytes == 16:
        print("Use AES-128")
    elif key_bytes == 24:
        print("Use AES-192")
    elif key_bytes == 32:
        print("Use AES-256")
    else:
        print("No standard DES/AES key size.")

'''
If the program says the key is HEX:

16 HEX characters → 8 bytes  → DES
32 HEX characters → 16 bytes → AES-128
48 HEX characters → 24 bytes → AES-192
64 HEX characters → 32 bytes → AES-256

If the program says the key is normal text:

8 characters  → DES
16 characters → AES-128
24 characters → AES-192
32 characters → AES-256

'''