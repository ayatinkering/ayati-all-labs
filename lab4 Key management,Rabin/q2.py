# ============================================================
# LAB 4 - QUESTION 2
#
# HEALTHCARE INC. - RABIN KEY MANAGEMENT
#
# QUESTION:
# Create a centralized key management service for hospitals
# and clinics using the Rabin cryptosystem.
#
# The system must:
# 1. Generate Rabin public/private keys.
# 2. Distribute keys.
# 3. Revoke keys.
# 4. Renew keys.
# 5. Store keys.
# 6. Maintain audit logs.
#
# WHAT WE ARE DOING:
# Think of this program as a central key cupboard.
# Each hospital/clinic gets its own Rabin key pair.
# ============================================================

import secrets
from datetime import datetime


# ------------------------------------------------------------
# PRIME CHECK
# ------------------------------------------------------------

def prime(n):                                           # check if n is prime

    if n < 2:
        return False

    for i in range(2, int(n ** 0.5) + 1):

        if n % i == 0:
            return False

    return True


# ------------------------------------------------------------
# GENERATE RABIN PRIME
# ------------------------------------------------------------

def make_prime():                                      # generate p or q

    while True:

        x = secrets.randbelow(500) + 100

        if x % 4 == 3 and prime(x):
            return x


# ------------------------------------------------------------
# RABIN KEY GENERATION
# ------------------------------------------------------------

def rabin_keys():                                      # generate Rabin keys

    p = make_prime()                                    # first prime
    q = make_prime()                                    # second prime

    while p == q:
        q = make_prime()

    n = p * q                                          # public modulus

    return n, p, q


# ------------------------------------------------------------
# LOGGING
# ------------------------------------------------------------

logs = []                                               # store audit logs


def log(action, name):                                  # record an operation

    t = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    logs.append(
        t + " | " + action + " | " + name
    )


# ------------------------------------------------------------
# CENTRAL KEY DATABASE
# ------------------------------------------------------------

keys = {}                                                # store all facility keys


# ------------------------------------------------------------
# ADD FACILITY
# ------------------------------------------------------------

def add_facility(name):                                 # generate facility keys

    n, p, q = rabin_keys()

    keys[name] = {
        "n": n,
        "p": p,
        "q": q,
        "status": "ACTIVE"
    }

    log("KEY GENERATED", name)

    print(name, "keys generated.")


# ------------------------------------------------------------
# DISTRIBUTE KEY
# ------------------------------------------------------------

def distribute(name):                                   # show facility keys

    if name not in keys:
        print("ERROR: Facility not found.")
        return

    if keys[name]["status"] == "REVOKED":
        print("ERROR: Key is revoked.")
        return

    print("\nPublic key:")
    print("n =", keys[name]["n"])

    print("\nPrivate key:")
    print("p =", keys[name]["p"])
    print("q =", keys[name]["q"])

    log("KEY DISTRIBUTED", name)


# ------------------------------------------------------------
# REVOKE KEY
# ------------------------------------------------------------

def revoke(name):                                       # revoke facility key

    if name not in keys:
        print("ERROR: Facility not found.")
        return

    keys[name]["status"] = "REVOKED"

    log("KEY REVOKED", name)

    print(name, "key revoked.")


# ------------------------------------------------------------
# RENEW KEY
# ------------------------------------------------------------

def renew(name):                                        # create new key pair

    if name not in keys:
        print("ERROR: Facility not found.")
        return

    n, p, q = rabin_keys()

    keys[name] = {
        "n": n,
        "p": p,
        "q": q,
        "status": "ACTIVE"
    }

    log("KEY RENEWED", name)

    print(name, "key renewed.")


# ------------------------------------------------------------
# MAIN
# ------------------------------------------------------------

print("HEALTHCARE RABIN KEY MANAGEMENT")

count = int(input("Number of facilities [3]: ") or 3)

for i in range(count):

    name = input(
        "Facility " + str(i + 1) + " [Hospital]: "
    )

    if name == "":
        name = "Hospital" + str(i + 1)

    add_facility(name)


print("\nKEY DISTRIBUTION")

name = input("Facility [Hospital1]: ") or "Hospital1"

distribute(name)


print("\nKEY REVOCATION")

name = input("Facility to revoke [Hospital1]: ") or "Hospital1"

revoke(name)


print("\nKEY RENEWAL")

name = input("Facility to renew [Hospital1]: ") or "Hospital1"

renew(name)


print("\nAUDIT LOG")

for x in logs:
    print(x)


print("\nCURRENT STATUS")

for name in keys:

    print(
        name,
        "->",
        keys[name]["status"]
    )