# ============================================================
# LAB 5 - QUESTION 1
#
# QUESTION:
# Implement a user-defined hash function.
#
# Requirements:
# 1. Start with hash value 5381.
# 2. For every character:
#       hash = hash * 33 + ASCII value
# 3. Use bitwise operations for mixing.
# 4. Keep the final hash inside 32 bits.
#
# WHAT WE ARE DOING:
# We take a string.
# Each character changes the current hash value.
# At the end we use & 0xFFFFFFFF to keep only 32 bits.
#
# Example:
# "HELLO"
#      ↓
#  character by character
#      ↓
#  final 32-bit hash
# ============================================================


def my_hash(s):                                      # create our own hash function

    h = 5381                                         # initial hash value

    for c in s:                                      # process every character

        h = ((h * 33) + ord(c)) & 0xFFFFFFFF        # multiply, add ASCII, keep 32 bits

        h = h ^ (h >> 16)                            # bitwise mixing

    return h                                          # return final hash


# ------------------------------------------------------------
# MAIN PROGRAM
# ------------------------------------------------------------

print("USER DEFINED HASH FUNCTION")

s = input("Enter message [Hello]: ") or "Hello"

h = my_hash(s)

print("\nMessage:")
print(s)

print("\nHash in decimal:")
print(h)

print("\nHash in HEX:")
print(hex(h))