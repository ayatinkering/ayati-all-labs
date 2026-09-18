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


def get_aes192_key(s):                                 # get AES-192 key
    k = get_bytes(s)                                   # convert key

    if k is None:
        return None

    if len(k) != 24:
        print("\nERROR: AES-192 requires exactly 24 bytes.")
        print("You entered:", len(k), "bytes.")
        print("AES-192 requires:", 24, "bytes.")
        return None

    return k


def show_key_expansion(key):                           # display AES-192 key expansion
    print("\nKEY EXPANSION")

    print("AES version       : AES-192")
    print("Key size          : 192 bits")
    print("Key bytes         :", len(key))
    print("Nk                : 6 words")
    print("Nr                : 12 rounds")
    print("Total words       : 52")
    print("Round keys        : 13")

    print("\nInitial key:")
    print(key.hex())

    print("\nAES-192 key expansion:")
    print("1. Divide the 192-bit key into six 32-bit words.")
    print("2. Generate new words using XOR.")
    print("3. Every 6th word uses:")
    print("   RotWord -> SubWord -> Rcon -> XOR")
    print("4. Continue until 52 words are generated.")
    print("5. Every four words form one 128-bit round key.")


def show_initial_round():                               # display initial AES round
    print("\nINITIAL ROUND")
    print("Operation:")
    print("AddRoundKey")
    print("State = State XOR RoundKey")


def show_main_rounds():                                 # display AES main rounds
    print("\nMAIN ROUNDS")

    for r in range(1, 12):
        print("\nRound", r)
        print("1. SubBytes")
        print("2. ShiftRows")
        print("3. MixColumns")
        print("4. AddRoundKey")


def show_final_round():                                 # display final AES round
    print("\nFINAL ROUND")
    print("Round 12")
    print("1. SubBytes")
    print("2. ShiftRows")
    print("3. AddRoundKey")
    print("MixColumns is NOT performed in the final round.")


def encrypt_aes192(pt, key):                           # AES-192 encryption
    try:
        cipher = AES.new(key, AES.MODE_ECB)             # create AES-192 cipher
        padded = pad(pt, 16)                            # pad plaintext
        return cipher.encrypt(padded)                  # encrypt
    except Exception as e:
        print("ERROR during AES-192 encryption:", e)
        return None


def decrypt_aes192(ct, key):                           # AES-192 decryption
    try:
        cipher = AES.new(key, AES.MODE_ECB)             # create AES-192 cipher
        pt = cipher.decrypt(ct)                        # decrypt
        return unpad(pt, 16)                            # remove padding
    except Exception as e:
        print("ERROR during AES-192 decryption:", e)
        return None


print("AES-192 Encryption Steps")

message = get_bytes(input("Enter plaintext: "))         # plaintext input
key = get_aes192_key(input("Enter AES-192 key: "))     # AES-192 key input

if message is not None and key is not None:

    print("\nPlaintext:")
    print(message.decode(errors="replace"))

    show_key_expansion(key)                             # show key expansion
    show_initial_round()                                # show initial round
    show_main_rounds()                                  # show main rounds
    show_final_round()                                  # show final round

    ciphertext = encrypt_aes192(message, key)           # encrypt message

    if ciphertext is not None:

        print("\nFINAL CIPHERTEXT")
        print(ciphertext.hex())

        decrypted = decrypt_aes192(ciphertext, key)     # decrypt ciphertext

        if decrypted is not None:
            print("\nDECRYPTED TEXT")
            print(decrypted.decode(errors="replace"))