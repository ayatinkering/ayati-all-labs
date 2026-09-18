from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


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


def get_aes_key(s, size):                              # get AES key of required size
    k = get_bytes(s)                                   # convert key to bytes

    if k is None:
        return None

    if len(k) != size:
        print("ERROR: AES key must be exactly", size, "bytes.")
        print("You entered", len(k), "bytes.")
        return None

    return k


def choose_aes():                                      # choose AES key size
    print("\nChoose AES version:")
    print("1. AES-128")
    print("2. AES-192")
    print("3. AES-256")

    choice = input("Enter choice: ")                    # AES choice

    if choice == "1":
        return 16, "AES-128"                            # 16-byte key
    elif choice == "2":
        return 24, "AES-192"                            # 24-byte key
    elif choice == "3":
        return 32, "AES-256"                            # 32-byte key
    else:
        print("ERROR: Invalid AES choice.")
        return None, None


def encrypt_aes(pt, key):                              # AES encryption
    try:
        cipher = AES.new(key, AES.MODE_ECB)             # create AES ECB cipher
        pt = pad(pt, 16)                                # AES block size = 16 bytes
        return cipher.encrypt(pt)                      # encrypt plaintext
    except Exception as e:
        print("ERROR during AES encryption:", e)
        return None


def decrypt_aes(ct, key):                              # AES decryption
    try:
        cipher = AES.new(key, AES.MODE_ECB)             # create AES ECB cipher
        pt = cipher.decrypt(ct)                        # decrypt ciphertext
        return unpad(pt, 16)                             # remove padding
    except Exception as e:
        print("ERROR during AES decryption:", e)
        return None


print("AES Encryption and Decryption")

size, name = choose_aes()                              # select AES version

if size is not None:

    message_input = input("Enter plaintext: ")          # plaintext input
    key_input = input("Enter AES key: ")                # AES key input

    message = get_bytes(message_input)                 # convert plaintext
    key = get_aes_key(key_input, size)                 # convert AES key

    if message is not None and key is not None:

        ciphertext = encrypt_aes(message, key)         # encrypt message

        if ciphertext is not None:

            print("\nAlgorithm:", name)
            print("Ciphertext HEX:", ciphertext.hex())

            decrypted = decrypt_aes(ciphertext, key)   # decrypt ciphertext

            if decrypted is not None:
                print("Decrypted text:",
                      decrypted.decode(errors="replace"))