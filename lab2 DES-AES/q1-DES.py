from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad


def get_bytes(s):                                      # convert input into bytes
    if s and len(s) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in s):
        x = input("Looks like HEX. Treat it as HEX? (y/n): ")  # choose HEX or text

        if x.lower() == "y":
            try:
                return bytes.fromhex(s)                 # HEX string -> bytes
            except ValueError:
                print("ERROR: Invalid HEX input.")
                return None

    return s.encode()                                   # normal text -> bytes


def get_des_key(s):                                    # prepare DES key
    k = get_bytes(s)                                   # convert key to bytes

    if k is None:
        return None

    if len(k) < 8:
        k = k + b"X" * (8 - len(k))                    # pad short DES key with X
        print("DES key was short, so X padding was added.")

    if len(k) > 8:
        print("ERROR: DES key cannot be more than 8 bytes.")
        return None

    return k


def encrypt_des(pt, key):                              # DES encryption
    try:
        cipher = DES.new(key, DES.MODE_ECB)            # create DES ECB cipher
        pt = pad(pt, 8)                                # pad plaintext to 8 bytes
        return cipher.encrypt(pt)                      # encrypt plaintext
    except Exception as e:
        print("ERROR during DES encryption:", e)
        return None


def decrypt_des(ct, key):                              # DES decryption
    try:
        cipher = DES.new(key, DES.MODE_ECB)            # create DES ECB cipher
        pt = cipher.decrypt(ct)                        # decrypt ciphertext
        return unpad(pt, 8)                             # remove padding
    except Exception as e:
        print("ERROR during DES decryption:", e)
        return None


print("DES Encryption and Decryption")

message_input = input("Enter plaintext: ")              # plaintext input
key_input = input("Enter DES key: ")                   # key input

message = get_bytes(message_input)                     # convert plaintext
key = get_des_key(key_input)                            # convert DES key

if message is not None and key is not None:

    ciphertext = encrypt_des(message, key)             # encrypt message

    if ciphertext is not None:
        print("Ciphertext HEX:", ciphertext.hex())     # display ciphertext

        decrypted = decrypt_des(ciphertext, key)       # decrypt ciphertext

        if decrypted is not None:
            print("Decrypted text:", decrypted.decode(errors="replace"))