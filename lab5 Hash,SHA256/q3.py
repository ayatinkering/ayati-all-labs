# ============================================================
# LAB 5 - QUESTION 3
#
# QUESTION:
# Compare MD5, SHA-1 and SHA-256.
#
# We need to:
# 1. Generate random strings.
# 2. Hash every string using MD5.
# 3. Hash every string using SHA-1.
# 4. Hash every string using SHA-256.
# 5. Measure computation time.
# 6. Detect collisions.
#
# COLLISION:
# Two different messages produce the same hash.
#
# Example:
#
# message 1 → ABC → hash X
# message 2 → XYZ → hash X
#
# Then X is a collision.
# ============================================================

import hashlib
import random
import string
import time


# ------------------------------------------------------------
# RANDOM STRING
# ------------------------------------------------------------

def random_string(n=20):                              # create random text

    chars = string.ascii_letters + string.digits

    return ''.join(random.choice(chars) for _ in range(n))


# ------------------------------------------------------------
# COLLISION CHECK
# ------------------------------------------------------------

def find_collisions(data):                            # find duplicate hashes

    seen = {}                                          # store hash → original message

    collisions = 0                                    # count collisions

    for msg, h in data:

        if h in seen and seen[h] != msg:

            collisions += 1                           # collision found

        else:

            seen[h] = msg

    return collisions


# ------------------------------------------------------------
# MAIN
# ------------------------------------------------------------

print("HASH PERFORMANCE COMPARISON")

n = int(
    input("Number of random strings [50]: ") or 50
)

if n < 1:

    print("ERROR: Number must be greater than 0.")

else:

    msgs = []                                         # store random messages

    for i in range(n):

        msgs.append(
            random_string()
        )


    # --------------------------------------------------------
    # MD5
    # --------------------------------------------------------

    start = time.perf_counter()                       # start timer

    md5_data = []                                     # store MD5 results

    for msg in msgs:

        h = hashlib.md5(
            msg.encode()
        ).hexdigest()

        md5_data.append((msg, h))

    md5_time = time.perf_counter() - start            # calculate time


    # --------------------------------------------------------
    # SHA-1
    # --------------------------------------------------------

    start = time.perf_counter()

    sha1_data = []

    for msg in msgs:

        h = hashlib.sha1(
            msg.encode()
        ).hexdigest()

        sha1_data.append((msg, h))

    sha1_time = time.perf_counter() - start


    # --------------------------------------------------------
    # SHA-256
    # --------------------------------------------------------

    start = time.perf_counter()

    sha256_data = []

    for msg in msgs:

        h = hashlib.sha256(
            msg.encode()
        ).hexdigest()

        sha256_data.append((msg, h))

    sha256_time = time.perf_counter() - start


    # --------------------------------------------------------
    # COLLISION CHECK
    # --------------------------------------------------------

    md5_collision = find_collisions(md5_data)

    sha1_collision = find_collisions(sha1_data)

    sha256_collision = find_collisions(sha256_data)


    # --------------------------------------------------------
    # RESULTS
    # --------------------------------------------------------

    print("\nRESULTS")

    print("\nMD5")
    print("Time:", md5_time, "seconds")
    print("Collisions:", md5_collision)

    print("\nSHA-1")
    print("Time:", sha1_time, "seconds")
    print("Collisions:", sha1_collision)

    print("\nSHA-256")
    print("Time:", sha256_time, "seconds")
    print("Collisions:", sha256_collision)


    print("\nNOTE:")
    print("No collision in this small random dataset")
    print("does NOT mean the algorithm is collision-free.")