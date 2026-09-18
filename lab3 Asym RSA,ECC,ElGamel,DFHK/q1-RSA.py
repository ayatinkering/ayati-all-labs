def get_number(s):                                    # convert number input
    try:
        if s.lower().startswith("0x"):
            return int(s, 16)                          # HEX number -> decimal
        return int(s)                                 # normal decimal number
    except:
        print("ERROR: Invalid number.")
        return None


def encrypt_rsa(message, n, e):                       # RSA encryption
    result = []                                       # store ciphertext values

    for b in message:                                 # process each message byte
        if b >= n:
            print("ERROR: Message byte is larger than n.")
            return None

        c = pow(b, e, n)                              # c = m^e mod n
        result.append(c)                              # store ciphertext

    return result


def decrypt_rsa(ciphertext, n, d):                    # RSA decryption
    result = bytearray()                              # store plaintext bytes

    for c in ciphertext:                              # process each ciphertext value
        m = pow(c, d, n)                              # m = c^d mod n

        if m > 255:
            print("ERROR: Decrypted value is not a valid byte.")
            return None

        result.append(m)                              # add plaintext byte

    return bytes(result)                              # convert to bytes


print("RSA ENCRYPTION AND DECRYPTION")

message = input("Enter message: ")                    # plaintext message

n = get_number(input("Enter n: "))                    # RSA modulus
e = get_number(input("Enter public exponent e: "))   # public exponent
d = get_number(input("Enter private exponent d: "))  # private exponent

if n is not None and e is not None and d is not None:

    plaintext = message.encode()                     # convert message to bytes

    ciphertext = encrypt_rsa(
        plaintext,
        n,
        e
    )                                                 # encrypt message

    if ciphertext is not None:

        print("\nCiphertext:")
        print(ciphertext)

        decrypted = decrypt_rsa(
            ciphertext,
            n,
            d
        )                                             # decrypt ciphertext

        if decrypted is not None:

            print("\nDecrypted:")
            print(decrypted.decode(errors="replace"))

            if decrypted == plaintext:
                print("\nVerification: SUCCESS")
            else:
                print("\nVerification: FAILED")