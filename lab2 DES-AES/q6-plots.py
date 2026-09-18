import time
import matplotlib.pyplot as plt

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


def make_key(material, size):                           # create key of required size
    if len(material) < size:
        material = material + b"X" * (size - len(material))  # X-pad short key

    return material[:size]                              # take required bytes


def get_messages():                                    # get five plaintext messages
    messages = []

    for i in range(5):
        s = input(f"Enter message {i + 1}: ")            # message input
        data = get_bytes(s)                             # convert message

        if data is not None:
            messages.append(data)
        else:
            messages.append(b"")                        # use empty data if invalid

    return messages


def encrypt_des(mode, pt, key, iv=None):               # DES encryption for selected mode
    if mode == "ECB":
        cipher = DES.new(key, DES.MODE_ECB)             # DES ECB
        return cipher.encrypt(pad(pt, 8))               # pad and encrypt

    if mode == "CBC":
        cipher = DES.new(key, DES.MODE_CBC, iv)         # DES CBC
        return cipher.encrypt(pad(pt, 8))               # pad and encrypt

    if mode == "CFB":
        cipher = DES.new(key, DES.MODE_CFB, iv, segment_size=64)
        return cipher.encrypt(pt)                       # CFB needs no padding

    if mode == "OFB":
        cipher = DES.new(key, DES.MODE_OFB, iv)         # DES OFB
        return cipher.encrypt(pt)                       # OFB needs no padding

    print("ERROR: Invalid DES mode.")
    return None


def decrypt_des(mode, ct, key, iv=None):               # DES decryption for selected mode
    if mode == "ECB":
        cipher = DES.new(key, DES.MODE_ECB)             # DES ECB
        return unpad(cipher.decrypt(ct), 8)             # decrypt and unpad

    if mode == "CBC":
        cipher = DES.new(key, DES.MODE_CBC, iv)         # DES CBC
        return unpad(cipher.decrypt(ct), 8)             # decrypt and unpad

    if mode == "CFB":
        cipher = DES.new(key, DES.MODE_CFB, iv, segment_size=64)
        return cipher.decrypt(ct)                       # CFB decryption

    if mode == "OFB":
        cipher = DES.new(key, DES.MODE_OFB, iv)         # DES OFB
        return cipher.decrypt(ct)                       # OFB decryption

    print("ERROR: Invalid DES mode.")
    return None


def encrypt_aes(mode, pt, key, iv=None, nonce=None):   # AES encryption for selected mode
    if mode == "ECB":
        cipher = AES.new(key, AES.MODE_ECB)             # AES ECB
        return cipher.encrypt(pad(pt, 16))              # pad and encrypt

    if mode == "CBC":
        cipher = AES.new(key, AES.MODE_CBC, iv)         # AES CBC
        return cipher.encrypt(pad(pt, 16))              # pad and encrypt

    if mode == "CFB":
        cipher = AES.new(key, AES.MODE_CFB, iv)         # AES CFB
        return cipher.encrypt(pt)                       # no padding

    if mode == "OFB":
        cipher = AES.new(key, AES.MODE_OFB, iv)         # AES OFB
        return cipher.encrypt(pt)                       # no padding

    if mode == "CTR":
        cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
        return cipher.encrypt(pt)                       # CTR needs no padding

    print("ERROR: Invalid AES mode.")
    return None


def decrypt_aes(mode, ct, key, iv=None, nonce=None):   # AES decryption for selected mode
    if mode == "ECB":
        cipher = AES.new(key, AES.MODE_ECB)             # AES ECB
        return unpad(cipher.decrypt(ct), 16)            # decrypt and unpad

    if mode == "CBC":
        cipher = AES.new(key, AES.MODE_CBC, iv)         # AES CBC
        return unpad(cipher.decrypt(ct), 16)            # decrypt and unpad

    if mode == "CFB":
        cipher = AES.new(key, AES.MODE_CFB, iv)         # AES CFB
        return cipher.decrypt(ct)                       # CFB decryption

    if mode == "OFB":
        cipher = AES.new(key, AES.MODE_OFB, iv)         # AES OFB
        return cipher.decrypt(ct)                       # OFB decryption

    if mode == "CTR":
        cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
        return cipher.decrypt(ct)                       # CTR decryption

    print("ERROR: Invalid AES mode.")
    return None


def measure_des(mode, messages, key, iv, repeat):      # measure DES mode
    start = time.perf_counter()                         # start timer

    for r in range(repeat):
        for msg in messages:
            encrypt_des(mode, msg, key, iv)             # encrypt all messages

    end = time.perf_counter()                           # stop timer

    return end - start                                 # return total time


def measure_aes(mode, messages, key, iv, nonce, repeat): # measure AES mode
    start = time.perf_counter()                         # start timer

    for r in range(repeat):
        for msg in messages:
            encrypt_aes(mode, msg, key, iv, nonce)      # encrypt all messages

    end = time.perf_counter()                           # stop timer

    return end - start                                 # return total time


print("DES AND AES MODE COMPARISON")

messages = get_messages()                              # get five messages

material_input = input("\nEnter common key material: ")  # common key
material = get_bytes(material_input)                   # convert common key

if material is not None:

    des_key = make_key(material, 8)                    # DES uses 8 bytes
    aes128_key = make_key(material, 16)                # AES-128 uses 16 bytes
    aes192_key = make_key(material, 24)                # AES-192 uses 24 bytes
    aes256_key = make_key(material, 32)                # AES-256 uses 32 bytes

    print("\nGenerated keys:")
    print("DES:", des_key.hex())
    print("AES-128:", aes128_key.hex())
    print("AES-192:", aes192_key.hex())
    print("AES-256:", aes256_key.hex())

    des_iv = get_bytes(input("\nEnter DES IV: "))        # DES IV
    aes_iv = get_bytes(input("Enter AES IV: "))         # AES IV
    nonce = get_bytes(input("Enter AES nonce: "))      # AES CTR nonce

    repeat_input = input("Enter number of repetitions: ") # timing repetitions

    try:
        repeat = int(repeat_input)                     # convert repetitions
    except:
        print("ERROR: Repetitions must be an integer.")
        repeat = 0

    if repeat > 0 and des_iv is not None and aes_iv is not None and nonce is not None:

        if len(des_iv) != 8:
            print("ERROR: DES IV must be exactly 8 bytes.")
        elif len(aes_iv) != 16:
            print("ERROR: AES IV must be exactly 16 bytes.")
        elif len(nonce) != 8:
            print("ERROR: AES nonce must be exactly 8 bytes.")
        else:

            des_modes = ["ECB", "CBC", "CFB", "OFB"]
            aes_modes = ["ECB", "CBC", "CFB", "OFB", "CTR"]

            results = {}                                # store timing results

            for mode in des_modes:
                t = measure_des(
                    mode,
                    messages,
                    des_key,
                    des_iv,
                    repeat
                )                                        # measure DES mode

                results["DES-" + mode] = t             # store DES timing

            aes_versions = {
                "AES-128": aes128_key,
                "AES-192": aes192_key,
                "AES-256": aes256_key
            }                                            # AES versions

            for version, key in aes_versions.items():

                for mode in aes_modes:

                    t = measure_aes(
                        mode,
                        messages,
                        key,
                        aes_iv,
                        nonce,
                        repeat
                    )                                    # measure AES mode

                    results[version + "-" + mode] = t  # store AES timing

            print("\nEXECUTION TIMES")

            for name, t in results.items():
                print(name, ":", t, "seconds")

            print("\nGENERATING GRAPH")

            names = list(results.keys())                 # algorithm/mode names
            times = list(results.values())              # execution times

            plt.figure(figsize=(14, 7))                  # create graph

            plt.bar(names, times)                       # draw bars

            plt.xlabel("Algorithm and Mode")
            plt.ylabel("Execution Time (seconds)")
            plt.title("DES and AES Mode Execution Time")

            plt.xticks(rotation=45, ha="right")          # rotate labels
            plt.tight_layout()                           # fit graph

            plt.show()                                   # display graph