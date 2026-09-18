import secrets


def encrypt_elgamal(message, p, g, h):                # ElGamal encryption
    ciphertext = []                                   # ciphertext list

    for m in message:                                  # process each byte

        if m >= p:
            print("ERROR: Message byte is larger than p.")
            return None

        k = secrets.randbelow(p - 2) + 1              # random k

        c1 = pow(g, k, p)                              # c1 = g^k mod p

        shared = pow(h, k, p)                         # h^k mod p

        c2 = (m * shared) % p                         # c2 = m*h^k mod p

        ciphertext.append((c1, c2))                   # store pair

    return ciphertext


def decrypt_elgamal(ciphertext, p, x):                # ElGamal decryption
    plaintext = bytearray()                            # plaintext bytes

    for c1, c2 in ciphertext:

        shared = pow(c1, x, p)                        # c1^x mod p

        inverse = pow(shared, -1, p)                  # modular inverse

        m = (c2 * inverse) % p                        # recover m

        plaintext.append(m)                           # add byte

    return bytes(plaintext)                            # return plaintext


print("ELGAMAL GIVEN VALUES")

message = input(
    "Enter message [Asymmetric Algorithms]: "
)                                                     # message input

if message == "":
    message = "Asymmetric Algorithms"                 # default message

p_input = input("Enter p [7919]: ")                   # p input
g_input = input("Enter g [2]: ")                      # g input
h_input = input("Enter h [6465]: ")                   # h input
x_input = input("Enter private x [2999]: ")           # private key input

try:
    p = int(p_input) if p_input else 7919             # use default p
    g = int(g_input) if g_input else 2                # use default g
    h = int(h_input) if h_input else 6465             # use default h
    x = int(x_input) if x_input else 2999             # use default x

    plaintext = message.encode()                      # message -> bytes

    ciphertext = encrypt_elgamal(
        plaintext,
        p,
        g,
        h
    )                                                 # encrypt

    if ciphertext is not None:

        print("\nCiphertext:")

        for pair in ciphertext:
            print(pair)

        decrypted = decrypt_elgamal(
            ciphertext,
            p,
            x
        )                                             # decrypt

        print("\nDecrypted:")
        print(decrypted.decode(errors="replace"))

        if decrypted == plaintext:
            print("\nVerification: SUCCESS")
        else:
            print("\nVerification: FAILED")

except Exception as e:
    print("ERROR:", e)