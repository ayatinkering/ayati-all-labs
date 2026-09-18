from Crypto.Cipher import AES


def get_bytes(s):                                      # convert input into bytes
    if s and len(s) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in s):
        x = input("Looks like HEX. Treat it as HEX? (y/n): ")  # choose HEX or text

        if x.lower() == "y":
            try:
                return bytes.fromhex(s)                 # HEX -> bytes
            except ValueError:
                print("ERROR: Invalid HEX input.")
                return None

    return s.encode()                                   # normal text -> bytes


def choose_aes():                                      # choose AES version
    print("\nChoose AES version:")
    print("1. AES-128")
    print("2. AES-192")
    print("3. AES-256")

    choice = input("Enter choice: ")                    # AES choice

    if choice == "1":
        return 16, "AES-128"                            # AES-128
    elif choice == "2":
        return 24, "AES-192"                            # AES-192
    elif choice == "3":
        return 32, "AES-256"                            # AES-256
    else:
        print("ERROR: Invalid AES choice.")
        return None, None


def get_aes_key(s, size):                              # prepare AES key
    k = get_bytes(s)                                   # convert key

    if k is None:
        return None

    if len(k) != size:
        print("ERROR: AES key must be exactly", size, "bytes.")
        return None

    return k


def get_nonce(s):                                      # prepare CTR nonce
    nonce = get_bytes(s)                               # convert nonce

    if nonce is None:
        return None

    if len(nonce) != 8:
        print("ERROR: Nonce must be exactly 8 bytes.")
        return None

    return nonce


def encrypt_ctr(pt, key, nonce):                       # AES CTR encryption
    try:
        cipher = AES.new(
            key,
            AES.MODE_CTR,
            nonce=nonce
        )                                               # create CTR cipher

        return cipher.encrypt(pt)                       # encrypt plaintext

    except Exception as e:
        print("ERROR during CTR encryption:", e)
        return None


def decrypt_ctr(ct, key, nonce):                       # AES CTR decryption
    try:
        cipher = AES.new(
            key,
            AES.MODE_CTR,
            nonce=nonce
        )                                               # create CTR cipher

        return cipher.decrypt(ct)                      # decrypt ciphertext

    except Exception as e:
        print("ERROR during CTR decryption:", e)
        return None


print("AES CTR MODE")

size, name = choose_aes()                              # choose AES version

if size is not None:

    message = get_bytes(
        input("Enter plaintext: ")
    )                                                   # plaintext input

    key = get_aes_key(
        input("Enter AES key: "),
        size
    )                                                   # AES key

    nonce = get_nonce(
        input("Enter nonce: ")
    )                                                   # CTR nonce

    if message is not None and key is not None and nonce is not None:

        ciphertext = encrypt_ctr(
            message,
            key,
            nonce
        )                                               # encrypt

        if ciphertext is not None:

            print("\nAlgorithm:", name)
            print("Ciphertext HEX:", ciphertext.hex())

            decrypted = decrypt_ctr(
                ciphertext,
                key,
                nonce
            )                                           # decrypt

            if decrypted is not None:
                print(
                    "Decrypted text:",
                    decrypted.decode(errors="replace")
                )