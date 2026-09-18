import secrets
import time


def get_number(s):                                    # convert input to integer
    try:
        if s.lower().startswith("0x"):
            return int(s, 16)                          # HEX -> integer
        return int(s)                                 # decimal -> integer
    except:
        print("ERROR: Invalid number.")
        return None


def generate_private_key(p):                          # generate private key
    return secrets.randbelow(p - 2) + 1              # random private value


def generate_public_key(g, private_key, p):           # generate public key
    return pow(g, private_key, p)                      # g^private mod p


def calculate_shared_secret(public_key, private_key, p):
    return pow(
        public_key,
        private_key,
        p
    )                                                 # calculate shared secret


print("DIFFIE-HELLMAN KEY EXCHANGE")

p = get_number(input("Enter prime p: "))              # DH prime
g = get_number(input("Enter generator g: "))          # DH generator

if p is not None and g is not None:

    print("\nGenerating Alice's keys...")

    start = time.perf_counter()                       # start Alice timer

    alice_private = generate_private_key(p)           # Alice private key

    alice_public = generate_public_key(
        g,
        alice_private,
        p
    )                                                 # Alice public key

    end = time.perf_counter()                         # stop Alice timer

    alice_time = end - start                          # Alice key time

    print("\nGenerating Bob's keys...")

    start = time.perf_counter()                       # start Bob timer

    bob_private = generate_private_key(p)             # Bob private key

    bob_public = generate_public_key(
        g,
        bob_private,
        p
    )                                                 # Bob public key

    end = time.perf_counter()                         # stop Bob timer

    bob_time = end - start                            # Bob key time

    print("\nALICE")
    print("Private key:", alice_private)
    print("Public key :", alice_public)

    print("\nBOB")
    print("Private key:", bob_private)
    print("Public key :", bob_public)

    print("\nCalculating shared secrets...")

    start = time.perf_counter()                       # start exchange timer

    alice_secret = calculate_shared_secret(
        bob_public,
        alice_private,
        p
    )                                                 # Alice shared secret

    bob_secret = calculate_shared_secret(
        alice_public,
        bob_private,
        p
    )                                                 # Bob shared secret

    end = time.perf_counter()                         # stop exchange timer

    exchange_time = end - start                       # exchange time

    print("\nAlice shared secret:", alice_secret)
    print("Bob shared secret  :", bob_secret)

    print("\nVERIFICATION")

    if alice_secret == bob_secret:
        print("SUCCESS: Shared secrets match.")
    else:
        print("FAILED: Shared secrets do not match.")

    print("\nTIMING")
    print("Alice key generation:", alice_time, "seconds")
    print("Bob key generation  :", bob_time, "seconds")
    print("Key exchange        :", exchange_time, "seconds")