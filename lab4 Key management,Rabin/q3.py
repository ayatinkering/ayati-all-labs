# ============================================================
# LAB 4 - ADDITIONAL QUESTION 1
#
# DIGIRIGHTS INC. - ELGAMAL DRM
#
# QUESTION:
# DigiRights uses ElGamal to protect digital content.
# Create a centralized system that can:
#
# 1. Generate ElGamal keys.
# 2. Store the keys.
# 3. Manage digital content.
# 4. Give customers access to content.
# 5. Give time-limited access.
# 6. Revoke access.
# 7. Revoke/renew the master key.
# 8. Maintain logs.
#
# WHAT WE ARE DOING:
#
# Content + Customer + Permission
#
# The program checks whether a customer is allowed to
# access a particular piece of content.
# ============================================================

import secrets
from datetime import datetime, timedelta


# ------------------------------------------------------------
# SIMPLE PRIME CHECK
# ------------------------------------------------------------

def prime(n):                                           # check if number is prime

    if n < 2:
        return False

    for i in range(2, int(n ** 0.5) + 1):

        if n % i == 0:
            return False

    return True


# ------------------------------------------------------------
# ELGAMAL KEY GENERATION
# ------------------------------------------------------------

def make_keys():                                        # generate master keys

    p = 467                                             # small prime for lab
    g = 2                                               # generator

    x = secrets.randbelow(p - 2) + 1                   # private key

    y = pow(g, x, p)                                    # public key

    return p, g, y, x


# ------------------------------------------------------------
# ELGAMAL ENCRYPTION
# ------------------------------------------------------------

def encrypt(m, p, g, y):                                # encrypt one number

    k = secrets.randbelow(p - 2) + 1                   # random key

    c1 = pow(g, k, p)                                   # first ciphertext

    s = pow(y, k, p)                                    # shared secret

    c2 = (m * s) % p                                    # second ciphertext

    return c1, c2


# ------------------------------------------------------------
# ELGAMAL DECRYPTION
# ------------------------------------------------------------

def decrypt(c1, c2, p, x):                              # decrypt one number

    s = pow(c1, x, p)                                   # shared secret

    inv = pow(s, -1, p)                                 # modular inverse

    m = (c2 * inv) % p                                  # original number

    return m


# ------------------------------------------------------------
# KEY + CONTENT + ACCESS STORAGE
# ------------------------------------------------------------

p, g, y, x = make_keys()                                # master key pair

content = {}                                            # store content
access = {}                                             # store permissions
logs = []                                               # store operations

master_revoked = False                                  # master key status


# ------------------------------------------------------------
# ADD CONTENT
# ------------------------------------------------------------

def add_content(cid, text, creator):                    # add digital content

    content[cid] = {
        "text": text,
        "creator": creator
    }

    logs.append("CONTENT ADDED: " + cid)

    print("Content added.")


# ------------------------------------------------------------
# GRANT ACCESS
# ------------------------------------------------------------

def grant(user, cid, minutes):                          # give temporary access

    if cid not in content:
        print("ERROR: Content does not exist.")
        return

    expiry = datetime.now() + timedelta(
        minutes=minutes
    )

    access[(user, cid)] = {
        "allowed": True,
        "expiry": expiry
    }

    logs.append(
        "ACCESS GRANTED: " + user + " -> " + cid
    )

    print("Access granted.")


# ------------------------------------------------------------
# CHECK ACCESS
# ------------------------------------------------------------

def check(user, cid):                                   # check permission

    if (user, cid) not in access:
        return False

    a = access[(user, cid)]

    if not a["allowed"]:
        return False

    if datetime.now() > a["expiry"]:
        return False

    return True


# ------------------------------------------------------------
# REVOKE ACCESS
# ------------------------------------------------------------

def revoke_access(user, cid):                           # remove permission

    if (user, cid) not in access:
        print("ERROR: Access does not exist.")
        return

    access[(user, cid)]["allowed"] = False

    logs.append(
        "ACCESS REVOKED: " + user + " -> " + cid
    )

    print("Access revoked.")


# ------------------------------------------------------------
# ACCESS CONTENT
# ------------------------------------------------------------

def get_content(user, cid):                             # request content

    if master_revoked:
        print("ERROR: Master key is revoked.")
        return

    if cid not in content:
        print("ERROR: Content does not exist.")
        return

    if not check(user, cid):
        print("ACCESS DENIED.")
        return

    print("\nACCESS GRANTED")
    print("Content:", content[cid]["text"])

    logs.append(
        "CONTENT ACCESSED: " + user + " -> " + cid
    )


# ------------------------------------------------------------
# MAIN
# ------------------------------------------------------------

print("DIGIRIGHTS DRM SYSTEM")

print("\nMASTER PUBLIC KEY")

print("p =", p)
print("g =", g)
print("y =", y)


creator = input("\nCreator [Alice]: ") or "Alice"

cid = input("Content ID [movie1]: ") or "movie1"

text = input("Content [Secret Movie]: ") or "Secret Movie"

add_content(cid, text, creator)


print("\nCUSTOMER ACCESS")

user = input("Customer [Bob]: ") or "Bob"

minutes = int(
    input("Access time in minutes [10]: ") or 10
)

grant(user, cid, minutes)


print("\nCONTENT REQUEST")

get_content(user, cid)


print("\nREVOKE ACCESS")

choice = input("Revoke access? (y/n): ")

if choice.lower() == "y":
    revoke_access(user, cid)


print("\nTRY ACCESS AGAIN")

get_content(user, cid)


print("\nAUDIT LOG")

for x in logs:
    print(x)