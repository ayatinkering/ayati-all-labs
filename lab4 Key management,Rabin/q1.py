# ============================================================
# LAB 4 - QUESTION 1
#
# SECURECORP
#
# QUESTION:
# SecureCorp has Finance, HR and Supply Chain systems.
# They need secure communication using RSA and Diffie-Hellman.
# The company also needs key management so that keys can be generated, stored, and revoked.
#
# WHAT WE ARE DOING:
# 1. Create RSA keys for each system.
# 2. Use RSA to encrypt and decrypt a message.
# 3. Use Diffie-Hellman to create a shared secret.
# 4. Store the systems and their keys.
# 5. Revoke a system's key.
#
# This is a simple lab demonstration, not a real enterprise KMS.
# ============================================================

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import secrets


# ------------------------------------------------------------
# RSA KEY GENERATION
# ------------------------------------------------------------

def make_rsa_key():                                      # generate RSA keys
    pri = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    pub = pri.public_key()                               # get public key

    return pub, pri


# ------------------------------------------------------------
# RSA ENCRYPTION
# ------------------------------------------------------------

def rsa_encrypt(msg, pub):                               # encrypt message
    try:
        return pub.encrypt(
            msg.encode(),
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    except Exception as e:
        print("ERROR:", e)
        return None


# ------------------------------------------------------------
# RSA DECRYPTION
# ------------------------------------------------------------

def rsa_decrypt(c, pri):                                 # decrypt message
    try:
        return pri.decrypt(
            c,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        ).decode()

    except Exception as e:
        print("ERROR:", e)
        return None


# ------------------------------------------------------------
# DIFFIE-HELLMAN
# ------------------------------------------------------------

def dh(p, g):                                             # perform DH exchange

    a = secrets.randbelow(p - 2) + 1                    # Alice private key
    b = secrets.randbelow(p - 2) + 1                    # Bob private key

    A = pow(g, a, p)                                     # Alice public key
    B = pow(g, b, p)                                     # Bob public key

    ka = pow(B, a, p)                                    # Alice shared secret
    kb = pow(A, b, p)                                    # Bob shared secret

    return a, b, A, B, ka, kb


# ------------------------------------------------------------
# KEY MANAGEMENT
# ------------------------------------------------------------

keys = {}                                                 # store system keys
revoked = set()                                          # store revoked systems


def add_system(name):                                    # add a new system

    pub, pri = make_rsa_key()

    keys[name] = {
        "public": pub,
        "private": pri
    }

    print(name, "added.")


def revoke_system(name):                                 # revoke a system

    if name not in keys:
        print("ERROR: System not found.")
        return

    revoked.add(name)

    print(name, "has been revoked.")


# ------------------------------------------------------------
# MAIN PROGRAM
# ------------------------------------------------------------

print("SECURECORP SECURITY SYSTEM")

print("\nADDING SYSTEMS")

add_system("Finance")
add_system("HR")
add_system("Supply Chain")


# ------------------------------------------------------------
# RSA COMMUNICATION
# ------------------------------------------------------------

print("\nRSA COMMUNICATION")

sender = input("Sender [Finance]: ") or "Finance"
receiver = input("Receiver [HR]: ") or "HR"

if sender in revoked:
    print("ERROR: Sender is revoked.")

elif receiver in revoked:
    print("ERROR: Receiver is revoked.")

elif receiver not in keys:
    print("ERROR: Receiver does not exist.")

else:

    msg = input("Message [Financial Report]: ") or "Financial Report"

    c = rsa_encrypt(
        msg,
        keys[receiver]["public"]
    )

    if c is not None:

        print("\nCiphertext:")
        print(c.hex())

        plain = rsa_decrypt(
            c,
            keys[receiver]["private"]
        )

        print("Decrypted:")
        print(plain)


# ------------------------------------------------------------
# DIFFIE-HELLMAN
# ------------------------------------------------------------

print("\nDIFFIE-HELLMAN")

p = int(input("Prime p [23]: ") or 23)
g = int(input("Generator g [5]: ") or 5)

a, b, A, B, ka, kb = dh(p, g)

print("\nAlice private:", a)
print("Alice public :", A)

print("\nBob private:", b)
print("Bob public :", B)

print("\nAlice shared secret:", ka)
print("Bob shared secret  :", kb)

if ka == kb:
    print("SUCCESS: Shared secret is same.")


# ------------------------------------------------------------
# KEY REVOCATION
# ------------------------------------------------------------

print("\nKEY REVOCATION")

name = input("System to revoke [HR]: ") or "HR"

revoke_system(name)

print("\nSYSTEM STATUS")

for x in keys:

    if x in revoked:
        print(x, "-> REVOKED")
    else:
        print(x, "-> ACTIVE")