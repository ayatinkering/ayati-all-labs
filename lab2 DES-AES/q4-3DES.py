from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad

# 24-byte / 192-bit 3DES key

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


def get_3des_key(s):                    # prepare Triple DES key
    k = get_bytes(s)                                   # convert key

    if k is None:
        return None

    if len(k) < 24:
        k = k + b"X" * (24 - len(k))                   # X-pad short key

    if len(k) != 24:
        print("ERROR: 3DES key must be 24 bytes.")


    try:
        DES3.adjust_key_parity(k)                     # adjust DES parity bits
        return k
    except Exception as e:
        print("ERROR with 3DES key:", e)
        return None


def encrypt_3des(pt, key):                             # Triple DES encryption
    try:
        cipher = DES3.new(key, DES3.MODE_ECB)          # create 3DES cipher
        pt = pad(pt, 8)                                # DES block size = 8
        return cipher.encrypt(pt)                      # encrypt
    except Exception as e:
        print("ERROR during 3DES encryption:", e)
        return None


def decrypt_3des(ct, key):                             # Triple DES decryption
    try:
        cipher = DES3.new(key, DES3.MODE_ECB)          # create 3DES cipher
        pt = cipher.decrypt(ct)                       # decrypt
        return unpad(pt, 8)                            # remove padding
    except Exception as e:
        print("ERROR during 3DES decryption:", e)
        return None


print("Triple DES Encryption and Decryption")

message = get_bytes(input("Enter plaintext: "))         # plaintext input
key = get_3des_key(input("Enter 3DES key: "))           # 3DES key input

if message is not None and key is not None:

    ciphertext = encrypt_3des(message, key)             # encrypt

    if ciphertext is not None:

        print("Ciphertext HEX:", ciphertext.hex())      # display ciphertext

        decrypted = decrypt_3des(ciphertext, key)      # decrypt

        if decrypted is not None:
            print("Decrypted text:",
                  decrypted.decode(errors="replace"))