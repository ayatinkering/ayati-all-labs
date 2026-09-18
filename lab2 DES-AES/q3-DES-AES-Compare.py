import time
from Crypto.Cipher import DES, AES
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
        k = k + b"X" * (8 - len(k))                    # X-pad short DES key

    if len(k) > 8:
        print("ERROR: DES key must be at most 8 bytes.")
        return None

    return k


def get_aes_key(s, size):                              # prepare AES key
    k = get_bytes(s)                                   # convert key

    if k is None:
        return None

    if len(k) != size:
        print("ERROR: AES key must be exactly", size, "bytes.")
        return None

    return k


def encrypt_des(pt, key):                              # DES encryption
    cipher = DES.new(key, DES.MODE_ECB)                # create DES cipher
    return cipher.encrypt(pad(pt, 8))                  # pad and encrypt


def decrypt_des(ct, key):                              # DES decryption
    cipher = DES.new(key, DES.MODE_ECB)                # create DES cipher
    return unpad(cipher.decrypt(ct), 8)                # decrypt and unpad


def encrypt_aes(pt, key):                              # AES-256 encryption
    cipher = AES.new(key, AES.MODE_ECB)                # create AES cipher
    return cipher.encrypt(pad(pt, 16))                 # pad and encrypt


def decrypt_aes(ct, key):                              # AES-256 decryption
    cipher = AES.new(key, AES.MODE_ECB)                # create AES cipher
    return unpad(cipher.decrypt(ct), 16)               # decrypt and unpad


def measure_time(function, data, key, repeat):          # measure function execution time
    start = time.perf_counter()                        # start high-resolution timer

    for i in range(repeat):                            # repeat operation
        result = function(data, key)                   # perform encryption/decryption

    end = time.perf_counter()                          # stop timer

    total = end - start                                # total execution time
    average = total / repeat                           # average execution time

    return total, average, result


print("DES vs AES-256 Performance Test")

message = get_bytes(input("Enter plaintext: "))         # message input

des_key = get_des_key(input("Enter DES key: "))        # DES key input

aes_key = get_aes_key(
    input("Enter AES-256 key: "), 32
)                                                      # AES-256 key input

if message is not None and des_key is not None and aes_key is not None:

    repeat_input = input("Number of repetitions: ")     # repetition input

    try:
        repeat = int(repeat_input)                     # convert repetitions to integer
    except:
        print("ERROR: Repetitions must be an integer.")
        repeat = 0

    if repeat > 0:

        des_ct = encrypt_des(message, des_key)          # create DES ciphertext
        aes_ct = encrypt_aes(message, aes_key)          # create AES ciphertext

        des_enc_time, des_enc_avg, _ = measure_time(
            encrypt_des, message, des_key, repeat
        )                                              # DES encryption timing

        des_dec_time, des_dec_avg, _ = measure_time(
            decrypt_des, des_ct, des_key, repeat
        )                                              # DES decryption timing

        aes_enc_time, aes_enc_avg, _ = measure_time(
            encrypt_aes, message, aes_key, repeat
        )                                              # AES encryption timing

        aes_dec_time, aes_dec_avg, _ = measure_time(
            decrypt_aes, aes_ct, aes_key, repeat
        )                                              # AES decryption timing

        print("\nResults")

        print("DES encryption total:", des_enc_time, "seconds")
        print("DES encryption average:", des_enc_avg, "seconds")

        print("DES decryption total:", des_dec_time, "seconds")
        print("DES decryption average:", des_dec_avg, "seconds")

        print("AES-256 encryption total:", aes_enc_time, "seconds")
        print("AES-256 encryption average:", aes_enc_avg, "seconds")

        print("AES-256 decryption total:", aes_dec_time, "seconds")
        print("AES-256 decryption average:", aes_dec_avg, "seconds")