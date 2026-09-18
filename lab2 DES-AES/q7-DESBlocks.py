from Crypto.Cipher import DES
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


def get_des_key(s):                                    # prepare DES key
    k = get_bytes(s)                                   # convert key

    if k is None:
        return None

    if len(k) < 8:
        k = k + b"X" * (8 - len(k))                    # X-pad short key

    if len(k) > 8:
        print("ERROR: DES key must be 8 bytes.")
        return None

    return k


def encrypt_des(pt, key):                              # encrypt DES data
    try:
        cipher = DES.new(key, DES.MODE_ECB)            # create DES cipher
        padded = pad(pt, 8)                             # pad data
        return cipher.encrypt(padded)                  # encrypt
    except Exception as e:
        print("ERROR during encryption:", e)
        return None


def decrypt_des(ct, key):                              # decrypt DES data
    try:
        cipher = DES.new(key, DES.MODE_ECB)            # create DES cipher
        pt = cipher.decrypt(ct)                        # decrypt
        return unpad(pt, 8)                             # remove padding
    except Exception as e:
        print("ERROR during decryption:", e)
        return None


print("DES HEX BLOCK ENCRYPTION")

key_input = input("Enter DES key: ")                   # key input
key = get_des_key(key_input)                           # convert key

if key is not None:

    block1_input = input("Enter Block 1: ")             # first block input
    block2_input = input("Enter Block 2: ")             # second block input

    block1 = get_bytes(block1_input)                   # convert block 1
    block2 = get_bytes(block2_input)                   # convert block 2

    if block1 is not None and block2 is not None:

        print("\nPlaintext Block 1 HEX:", block1.hex())
        print("Plaintext Block 2 HEX:", block2.hex())

        ct1 = encrypt_des(block1, key)                 # encrypt block 1
        ct2 = encrypt_des(block2, key)                 # encrypt block 2

        if ct1 is not None and ct2 is not None:

            print("\nCiphertext Block 1:")
            print(ct1.hex())

            print("\nCiphertext Block 2:")
            print(ct2.hex())

            dec1 = decrypt_des(ct1, key)               # decrypt block 1
            dec2 = decrypt_des(ct2, key)               # decrypt block 2

            if dec1 is not None:
                print("\nDecrypted Block 1 HEX:")
                print(dec1.hex())

                print("Decrypted Block 1 Text:")
                print(dec1.decode(errors="replace"))

            if dec2 is not None:
                print("\nDecrypted Block 2 HEX:")
                print(dec2.hex())

                print("Decrypted Block 2 Text:")
                print(dec2.decode(errors="replace"))