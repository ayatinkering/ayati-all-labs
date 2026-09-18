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
        print("ERROR: DES key must be exactly 8 bytes.")
        return None

    return k


def get_des_iv(s):                                     # prepare DES IV
    iv = get_bytes(s)                                  # convert IV

    if iv is None:
        return None

    if len(iv) != 8:
        print("ERROR: DES IV must be exactly 8 bytes.")
        return None

    return iv


def encrypt_cbc(pt, key, iv):                          # DES CBC encryption
    try:
        cipher = DES.new(key, DES.MODE_CBC, iv)        # create CBC cipher
        return cipher.encrypt(pad(pt, 8))              # pad and encrypt
    except Exception as e:
        print("ERROR during CBC encryption:", e)
        return None


def decrypt_cbc(ct, key, iv):                          # DES CBC decryption
    try:
        cipher = DES.new(key, DES.MODE_CBC, iv)        # create CBC cipher
        return unpad(cipher.decrypt(ct), 8)            # decrypt and unpad
    except Exception as e:
        print("ERROR during CBC decryption:", e)
        return None


print("DES CBC MODE")

message = get_bytes(input("Enter plaintext: "))         # plaintext input
key = get_des_key(input("Enter DES key: "))             # DES key input
iv = get_des_iv(input("Enter IV: "))                    # IV input

if message is not None and key is not None and iv is not None:

    ciphertext = encrypt_cbc(message, key, iv)          # encrypt

    if ciphertext is not None:

        print("Ciphertext HEX:", ciphertext.hex())

        decrypted = decrypt_cbc(ciphertext, key, iv)    # decrypt

        if decrypted is not None:
            print("Decrypted text:",
                  decrypted.decode(errors="replace"))