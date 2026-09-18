# ============================================================
# CRYPTOGRAPHY / INFORMATION SECURITY LAB MASTER TEMPLATE
# ============================================================
#
# THIS FILE IS A MASTER TEMPLATE FOR OPEN-BOOK LAB QUESTIONS.
#
# Common question patterns covered:
#
# 1. RSA Encryption / Decryption
# 2. RSA Key Generation
# 3. AES-128 Encryption / Decryption
# 4. DES Encryption / Decryption
# 5. SHA-256 Hashing
# 6. Custom Hashing
# 7. RSA Digital Signatures
# 8. ElGamal Encryption
# 9. Diffie-Hellman Key Exchange
# 10. File Reading / Writing
# 11. Timestamps
# 12. Integrity Verification
# 13. Tampering Demonstration
# 14. Role-Based Access Control (RBAC)
# 15. Student / Faculty / HoD
# 16. Doctor / Nurse / Admin
# 17. Patient / Doctor / Auditor
# 18. AES + RSA hybrid encryption
# 19. Menu-driven security systems
#
# ------------------------------------------------------------
# HOW TO USE THIS FILE IN THE EXAM
# ------------------------------------------------------------
#
# DO NOT RUN EVERYTHING.
#
# Read the question and identify what it asks for.
#
# If question says:
#
# "RSA encryption"          -> use BLOCK 1
# "RSA key parameters"      -> use BLOCK 1
# "AES-128"                 -> use BLOCK 2
# "DES"                     -> use BLOCK 3
# "SHA-256"                 -> use BLOCK 4
# "custom hash"             -> use BLOCK 5
# "digital signature"       -> use BLOCK 6
# "ElGamal"                 -> use BLOCK 7
# "Diffie-Hellman"          -> use BLOCK 8
# "file"                    -> use BLOCK 9
# "timestamp"               -> use BLOCK 10
# "integrity verification" -> use BLOCK 11
# "tampering"               -> use BLOCK 12
# "RBAC / roles"            -> use BLOCK 13
# "menu driven"             -> use BLOCK 14
#
# Then combine the required blocks.
#
# ------------------------------------------------------------
# VERY IMPORTANT MEMORY TABLE
# ------------------------------------------------------------
#
# ENCRYPTION:
#     Purpose = hide information
#
# HASHING:
#     Purpose = detect modification
#
# DIGITAL SIGNATURE:
#     Purpose = prove authenticity + detect modification
#
# RSA:
#     Public key  -> encryption
#     Private key -> decryption
#
# RSA SIGNATURE:
#     Private key -> SIGN
#     Public key  -> VERIFY
#
# AES / DES:
#     Same secret/shared key is used for encryption/decryption
#
# SHA-256:
#     data -> fixed-size hash
#
# RBAC:
#     Different roles get different permissions
#
# ============================================================


# ============================================================
# INSTALLATION
# ============================================================
#
#
#     pip install pycryptodome
#
# Then imports look like:
#
#     from Crypto.Cipher import AES
#     from Crypto.Cipher import DES
#     from Crypto.PublicKey import RSA
#
# ============================================================


# ============================================================
# BLOCK 0 — COMMON IMPORTS
# ============================================================
#
# Keep only the imports needed by your question.
#
# ============================================================

import hashlib                         # SHA-256 / MD5 / SHA-1
import os                              # random bytes
import time                            # performance measurement
from datetime import datetime          # timestamps

from Crypto.PublicKey import RSA       # RSA key generation
from Crypto.Cipher import PKCS1_OAEP   # RSA encryption/decryption
from Crypto.Cipher import AES          # AES encryption/decryption
from Crypto.Cipher import DES          # DES encryption/decryption
from Crypto.Util.Padding import pad, unpad   # padding for AES/DES

from Crypto.Signature import pkcs1_15  # RSA digital signature
from Crypto.Hash import SHA256         # SHA-256 for RSA signatures

# ------------------------------------------------------------
# IF YOUR QUESTION DOES NOT NEED SOMETHING:
#
# You can delete that import.
#
# Example:
# Only DES question?
# Delete AES, RSA, signature imports if not needed.
# ------------------------------------------------------------


# ============================================================
# BLOCK 1 — RSA KEY GENERATION + RSA ENCRYPTION/DECRYPTION
# ============================================================
#
# USE THIS BLOCK WHEN THE QUESTION SAYS:
#
#     "Generate RSA key pair"
#     "Display n, e, d"
#     "Encrypt using RSA public key"
#     "Decrypt using RSA private key"
#     "RSA encryption and decryption"
#
# ------------------------------------------------------------
# IMPORTANT:
#
# RSA:
#
#     PUBLIC KEY  = (n, e)
#     PRIVATE KEY = (n, d)
#
# Encryption:
#
#     public key -> encrypt
#
# Decryption:
#
#     private key -> decrypt
#
# ------------------------------------------------------------

def generate_rsa_keys():
    # Generate a new RSA key pair
    key = RSA.generate(2048)

    # Get the public key
    public_key = key.publickey()

    # Return both keys
    return key, public_key


def rsa_encrypt(data, public_key):
    # Create RSA encryption object using PUBLIC key
    cipher = PKCS1_OAEP.new(public_key)

    # Encrypt the data
    encrypted = cipher.encrypt(data)

    # Return ciphertext
    return encrypted


def rsa_decrypt(encrypted, private_key):
    # Create RSA decryption object using PRIVATE key
    cipher = PKCS1_OAEP.new(private_key)

    # Decrypt ciphertext
    decrypted = cipher.decrypt(encrypted)

    # Return original data
    return decrypted


# ------------------------------------------------------------
# RSA EXAMPLE
# ------------------------------------------------------------
#
# DELETE THIS EXAMPLE IF YOUR QUESTION DOES NOT REQUIRE IT.
# ------------------------------------------------------------

def rsa_example():

    # Generate RSA keys
    private_key, public_key = generate_rsa_keys()

    # Display RSA parameters
    print("n =", private_key.n)       # RSA modulus
    print("e =", private_key.e)       # public exponent
    print("d =", private_key.d)       # private exponent

    # Change this message according to the question
    message = input("Enter message: ").encode()

    # Encrypt using public key
    encrypted = rsa_encrypt(message, public_key)

    print("Encrypted =", encrypted.hex())

    # Decrypt using private key
    decrypted = rsa_decrypt(encrypted, private_key)

    print("Decrypted =", decrypted.decode())


# ------------------------------------------------------------
# EXAM HINT:
#
# If question gives:
#
#     "RECEIVE 2500 FROM 1042"
#
# simply use:
#
#     message = "RECEIVE 2500 FROM 1042".encode()
#
# If it comes from a file:
#
#     with open("encryption_message.txt", "rb") as f:
#         message = f.read()
#
# ------------------------------------------------------------


# ============================================================
# BLOCK 2 — AES-128 ENCRYPTION / DECRYPTION
# ============================================================
#
# USE WHEN QUESTION SAYS:
#
#     AES
#     AES-128
#     encrypt file using AES
#     decrypt using AES key
#     shared AES key
#     IV
#
# ------------------------------------------------------------
# AES-128:
#
#     key = 16 bytes
#
# Example:
#
#     b"1234567890123456"
#
# CBC mode also needs:
#
#     IV = 16 bytes
#
# ------------------------------------------------------------

def aes_encrypt(data, key, iv):
    # Create AES cipher using CBC mode
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Pad data because AES works on blocks
    padded_data = pad(data, AES.block_size)

    # Encrypt padded data
    encrypted = cipher.encrypt(padded_data)

    # Return ciphertext
    return encrypted


def aes_decrypt(encrypted, key, iv):
    # Create AES cipher using same key and IV
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Decrypt ciphertext
    decrypted_padded = cipher.decrypt(encrypted)

    # Remove padding
    decrypted = unpad(decrypted_padded, AES.block_size)

    # Return plaintext
    return decrypted


def aes_example():

    # AES-128 key MUST be exactly 16 bytes
    key = input("Enter AES-128 key (16 characters): ").encode()

    # Check key size
    if len(key) != 16:
        print("ERROR: AES-128 key must be exactly 16 bytes.")
        return

    # IV must be 16 bytes for AES
    iv = input("Enter IV (16 characters): ").encode()

    if len(iv) != 16:
        print("ERROR: AES IV must be exactly 16 bytes.")
        return

    # Input message
    message = input("Enter message: ").encode()

    # Encrypt
    encrypted = aes_encrypt(message, key, iv)

    print("Encrypted =", encrypted.hex())

    # Decrypt
    decrypted = aes_decrypt(encrypted, key, iv)

    print("Decrypted =", decrypted.decode())


# ------------------------------------------------------------
# EXAM HINT:
#
# If question says:
#
#     "AES-128"
#
# use:
#
#     16-byte key
#     16-byte IV
#
# ------------------------------------------------------------
#
# If question gives the key:
#
#     key = b"1234567890123456"
#
# If question gives IV:
#
#     iv = b"abcdefghijklmnop"
#
# If question says "take from user":
#
#     key = input("Enter key: ").encode()
#
# ------------------------------------------------------------


# ============================================================
# BLOCK 3 — DES ENCRYPTION / DECRYPTION
# ============================================================
#
# USE WHEN QUESTION SAYS:
#
#     DES
#     DES encryption
#     academic records using DES
#     encrypt using shared DES key
#
# ------------------------------------------------------------
# DES:
#
#     key = 8 bytes
#     IV  = 8 bytes in CBC mode
#
# ------------------------------------------------------------

def des_encrypt(data, key, iv):
    # Create DES cipher using CBC mode
    cipher = DES.new(key, DES.MODE_CBC, iv)

    # Add padding
    padded_data = pad(data, DES.block_size)

    # Encrypt
    encrypted = cipher.encrypt(padded_data)

    return encrypted


def des_decrypt(encrypted, key, iv):
    # Create DES cipher using same key and IV
    cipher = DES.new(key, DES.MODE_CBC, iv)

    # Decrypt
    decrypted_padded = cipher.decrypt(encrypted)

    # Remove padding
    decrypted = unpad(decrypted_padded, DES.block_size)

    return decrypted


def des_example():

    # DES key must be exactly 8 bytes
    key = input("Enter DES key (8 characters): ").encode()

    if len(key) != 8:
        print("ERROR: DES key must be exactly 8 bytes.")
        return

    # DES CBC IV must be exactly 8 bytes
    iv = input("Enter IV (8 characters): ").encode()

    if len(iv) != 8:
        print("ERROR: DES IV must be exactly 8 bytes.")
        return

    # Message
    message = input("Enter message: ").encode()

    # Encrypt
    encrypted = des_encrypt(message, key, iv)

    print("Encrypted =", encrypted.hex())

    # Decrypt
    decrypted = des_decrypt(encrypted, key, iv)

    print("Decrypted =", decrypted.decode())


# ------------------------------------------------------------
# EXAM HINT:
#
# If question says:
#
#     "DES symmetric encryption"
#
# remember:
#
#     DES key = 8 bytes
#     DES block = 8 bytes
#
# ------------------------------------------------------------


# ============================================================
# BLOCK 4 — SHA-256 HASHING
# ============================================================
#
# USE WHEN QUESTION SAYS:
#
#     SHA-256
#     hashing
#     integrity
#     hash encrypted data
#     calculate hash of file
#     compare hashes
#
# ============================================================

def sha256_hash(data):
    # Calculate SHA-256 hash
    return hashlib.sha256(data).hexdigest()


def sha256_example():

    # Input message
    message = input("Enter message: ").encode()

    # Calculate hash
    h = sha256_hash(message)

    # Display hash
    print("SHA-256 =", h)


# ------------------------------------------------------------
# EXAM HINT:
#
# If question says:
#
#     "hash encrypted message"
#
# do:
#
#     hash = sha256_hash(encrypted)
#
# NOT:
#
#     hash = sha256_hash(original)
#
# unless the question specifically asks for original data.
# ------------------------------------------------------------


# ============================================================
# BLOCK 5 — CUSTOM HASH FUNCTION
# ============================================================
#
# USE ONLY WHEN THE QUESTION PROVIDES A MATHEMATICAL HASH
# FUNCTION.
#
# Example from your PYQ:
#
#     initial hash = 5381
#
#     for every character:
#
#         hash = hash * 33 + ASCII(character)
#
#     apply bitwise mixing
#
#     keep 32 bits
#
# ------------------------------------------------------------
# IMPORTANT:
#
# If the examiner gives a DIFFERENT mathematical function,
# change ONLY this function according to the question.
#
# Do not blindly use this if another formula is given.
# ============================================================

def custom_hash(data):
    # Initial hash value given by the question
    h = 5381

    # Process every character
    for c in data:

        # Multiply by 33 and add ASCII value
        h = ((h * 33) + ord(c)) & 0xFFFFFFFF

        # Bitwise mixing
        h = h ^ (h >> 16)

    # Return final 32-bit hash
    return h


def custom_hash_example():

    # Input text
    message = input("Enter message: ")

    # Calculate custom hash
    h = custom_hash(message)

    # Display decimal and hexadecimal form
    print("Hash decimal =", h)
    print("Hash hex =", hex(h))


# ============================================================
# BLOCK 6 — RSA DIGITAL SIGNATURE
# ============================================================
#
# USE WHEN QUESTION SAYS:
#
#     digital signature
#     sign SHA-256 hash
#     authenticate sender
#     verify sender
#     RSA signature
#
# ------------------------------------------------------------
# IMPORTANT:
#
# SIGN:
#
#     PRIVATE KEY
#
# VERIFY:
#
#     PUBLIC KEY
#
# ------------------------------------------------------------

def rsa_sign(data, private_key):
    # Create SHA-256 hash object
    h = SHA256.new(data)

    # Sign using RSA PRIVATE key
    signature = pkcs1_15.new(private_key).sign(h)

    # Return signature
    return signature


def rsa_verify(data, signature, public_key):
    # Recalculate SHA-256
    h = SHA256.new(data)

    # Try to verify signature
    try:
        pkcs1_15.new(public_key).verify(h, signature)

        # Signature is correct
        return True

    except:
        # Signature verification failed
        return False


def signature_example():

    # Generate RSA keys
    private_key, public_key = generate_rsa_keys()

    # Message
    message = input("Enter message: ").encode()

    # Create digital signature
    signature = rsa_sign(message, private_key)

    print("Signature =", signature.hex())

    # Verify signature
    valid = rsa_verify(message, signature, public_key)

    if valid:
        print("Signature VALID")
    else:
        print("Signature INVALID")


# ------------------------------------------------------------
# EXAM HINT:
#
# If question says:
#
#     "sign the SHA-256 hash"
#
# Conceptually:
#
#     data
#       ↓
#     SHA-256
#       ↓
#     hash
#       ↓
#     RSA private key
#       ↓
#     signature
#
# The PyCryptodome signature API hashes the supplied data as part
# of the signature operation.
#
# For normal lab questions, rsa_sign(data, private_key) is enough.
#
# ------------------------------------------------------------


# ============================================================
# BLOCK 7 — ELGAMAL ENCRYPTION
# ============================================================
#
# USE WHEN QUESTION SAYS:
#
#     ElGamal
#     authorization code using ElGamal
#     encrypt message using given p, g, x
#
# ------------------------------------------------------------
# STANDARD ELGAMAL:
#
# Private:
#
#     x
#
# Public:
#
#     y = g^x mod p
#
# Encryption:
#
#     choose random k
#
#     c1 = g^k mod p
#
#     shared = y^k mod p
#
#     c2 = m * shared mod p
#
# Decryption:
#
#     shared = c1^x mod p
#
#     m = c2 * inverse(shared) mod p
#
# ============================================================

def elgamal_keygen(p, g, x):
    # Calculate public value
    y = pow(g, x, p)

    # Return public and private values
    return y, x


def elgamal_encrypt(m, p, g, y, k):
    # First ciphertext component
    c1 = pow(g, k, p)

    # Shared secret
    shared = pow(y, k, p)

    # Second ciphertext component
    c2 = (m * shared) % p

    return c1, c2


def elgamal_decrypt(c1, c2, p, x):
    # Recreate shared secret
    shared = pow(c1, x, p)

    # Modular inverse
    inverse = pow(shared, -1, p)

    # Recover message
    m = (c2 * inverse) % p

    return m


def elgamal_example():

    # These values should be replaced with values from question
    p = int(input("Enter p: "))
    g = int(input("Enter g: "))
    x = int(input("Enter private key x: "))

    # Generate public key
    y, x = elgamal_keygen(p, g, x)

    print("Public key y =", y)
    print("Private key x =", x)

    # Message MUST be represented as an integer
    m = int(input("Enter message as integer: "))

    # Random/selected k
    k = int(input("Enter random k: "))

    # Encrypt
    c1, c2 = elgamal_encrypt(m, p, g, y, k)

    print("c1 =", c1)
    print("c2 =", c2)

    # Decrypt
    decrypted = elgamal_decrypt(c1, c2, p, x)

    print("Decrypted =", decrypted)


# ------------------------------------------------------------
# EXAM HINT:
#
# If the question gives:
#
#     p
#     g
#     x
#     authorization code
#
# use those values instead of generating your own.
#
# ------------------------------------------------------------
#
# VERY IMPORTANT:
#
# ElGamal textbook encryption works with INTEGER messages.
#
# If question gives a string:
#
#     "AUTH123"
#
# you need to convert it to an integer, for example:
#
#     m = int.from_bytes(b"AUTH123", "big")
#
# and convert back:
#
#     m.to_bytes(...)
#
# But make sure m < p for toy ElGamal.
#
# ------------------------------------------------------------


# ============================================================
# BLOCK 8 — DIFFIE-HELLMAN KEY EXCHANGE
# ============================================================
#
# USE WHEN QUESTION SAYS:
#
#     Diffie-Hellman
#     DH
#     key exchange
#     shared secret
#
# ============================================================

def diffie_hellman_example():

    # Public parameters
    p = int(input("Enter public prime p: "))
    g = int(input("Enter public generator g: "))

    # Private values
    a = int(input("Enter private value of Alice: "))
    b = int(input("Enter private value of Bob: "))

    # Alice public value
    A = pow(g, a, p)

    # Bob public value
    B = pow(g, b, p)

    # Alice calculates shared secret
    shared_alice = pow(B, a, p)

    # Bob calculates shared secret
    shared_bob = pow(A, b, p)

    print("Alice public =", A)
    print("Bob public =", B)

    print("Alice shared secret =", shared_alice)
    print("Bob shared secret =", shared_bob)

    # Check whether both calculated same secret
    if shared_alice == shared_bob:
        print("Key Exchange Successful")
    else:
        print("Key Exchange Failed")


# ============================================================
# BLOCK 9 — FILE READING / WRITING
# ============================================================
#
# USE WHEN QUESTION SAYS:
#
#     read .txt file
#     store encrypted message in another file
#     store hash in hash.txt
#     upload record
#     retrieve record
#
# ============================================================

def read_text_file(filename):
    # Read text file as bytes
    with open(filename, "rb") as f:
        return f.read()


def write_binary_file(filename, data):
    # Write bytes to file
    with open(filename, "wb") as f:
        f.write(data)


def read_binary_file(filename):
    # Read bytes from file
    with open(filename, "rb") as f:
        return f.read()


def write_text_file(filename, data):
    # Write normal text to file
    with open(filename, "w") as f:
        f.write(data)


def read_text_file_normal(filename):
    # Read normal text from file
    with open(filename, "r") as f:
        return f.read()


# ------------------------------------------------------------
# COMMON FILE PATTERN
# ------------------------------------------------------------
#
# If question says:
#
#     encryption_message.txt
#
# use:
#
#     message = read_text_file("encryption_message.txt")
#
# ------------------------------------------------------------
#
# If question says:
#
#     encrypted.txt
#
# use:
#
#     write_binary_file("encrypted.txt", encrypted)
#
# ------------------------------------------------------------
#
# If question says:
#
#     hash.txt
#
# use:
#
#     write_text_file("hash.txt", hash_value)
#
# ------------------------------------------------------------


# ============================================================
# BLOCK 10 — TIMESTAMP
# ============================================================
#
# USE WHEN QUESTION SAYS:
#
#     timestamp
#     store upload time
#     store verification time
#     record date/time
#
# ============================================================

def get_timestamp():
    # Get current date and time
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# Example:
#
# timestamp = get_timestamp()
# print(timestamp)


# ============================================================
# BLOCK 11 — INTEGRITY VERIFICATION
# ============================================================
#
# USE WHEN QUESTION SAYS:
#
#     verify integrity
#     compare hashes
#     detect tampering
#     check whether file was modified
#
# ============================================================

def verify_integrity(data, stored_hash):
    # Calculate new hash of current data
    new_hash = sha256_hash(data)

    # Compare with stored hash
    if new_hash == stored_hash:
        return True

    return False


def integrity_example():

    # Original data
    data = input("Enter message: ").encode()

    # Calculate and store original hash
    stored_hash = sha256_hash(data)

    print("Stored hash =", stored_hash)

    # Read/check data again
    current_data = input("Enter message again: ").encode()

    # Calculate current hash
    current_hash = sha256_hash(current_data)

    print("Current hash =", current_hash)

    # Compare
    if current_hash == stored_hash:
        print("Integrity Verified")
        print("Message has not been tampered with.")

    else:
        print("Integrity Check Failed")
        print("Message has been tampered with.")


# ------------------------------------------------------------
# EXAM HINT:
#
# This is one of the MOST IMPORTANT patterns.
#
#     original data
#          ↓
#       SHA-256
#          ↓
#      stored hash
#
# Later:
#
#     current data
#          ↓
#       SHA-256
#          ↓
#      current hash
#
# Compare:
#
#     stored hash == current hash
#
# ------------------------------------------------------------


# ============================================================
# BLOCK 12 — TAMPERING DEMONSTRATION
# ============================================================
#
# USE WHEN QUESTION SAYS:
#
#     "Modify one character"
#     "Demonstrate tampering"
#     "Show integrity failure"
#
# ============================================================

def tampering_example():

    # Original message
    original = b"RECEIVE 2500 FROM 1042"

    # Calculate original hash
    original_hash = sha256_hash(original)

    print("Original =", original.decode())
    print("Original hash =", original_hash)

    # Tampered message
    tampered = b"RECEIVE 5000 FROM 1042"

    # Calculate new hash
    tampered_hash = sha256_hash(tampered)

    print("Tampered =", tampered.decode())
    print("Tampered hash =", tampered_hash)

    # Compare
    if original_hash == tampered_hash:
        print("Integrity Verified")

    else:
        print("Integrity Check Failed")
        print("Message has been tampered with.")


# ------------------------------------------------------------
# EXAM HINT:
#
# For your financial PYQ:
#
#     2500 → 5000
#
# For MediSecure:
#
#     change ONE character in encrypted file
#
# The important part is:
#
#     original_hash != tampered_hash
#
# ------------------------------------------------------------


# ============================================================
# BLOCK 13 — RBAC / ROLE-BASED ACCESS CONTROL
# ============================================================
#
# USE WHEN QUESTION SAYS:
#
#     Student / Faculty / HoD
#     Doctor / Nurse / Admin
#     Patient / Doctor / Auditor
#     roles
#     permissions
#     role-based access control
#
# ============================================================

def rbac_example():

    # Ask user for role
    role = input("Enter role: ").strip().lower()

    # Student permissions
    if role == "student":

        print("Student Access")
        print("1. Encrypt record")
        print("2. Sign record")
        print("3. Upload record")
        print("4. View past records")

    # Faculty permissions
    elif role == "faculty":

        print("Faculty Access")
        print("1. View records")
        print("2. Verify signature")
        print("3. Verify hash")
        print("4. Decrypt record")

    # HoD permissions
    elif role == "hod":

        print("HoD Access")
        print("1. View hashes")
        print("2. Verify signatures")

    # Doctor permissions
    elif role == "doctor":

        print("Doctor Access")
        print("1. Enter patient information")
        print("2. Encrypt patient information")
        print("3. Sign patient information")
        print("4. View records")
        print("5. Decrypt records")

    # Nurse permissions
    elif role == "nurse":

        print("Nurse Access")
        print("1. View encrypted records")
        print("2. Verify hash")
        print("3. Verify signature")

    # Admin permissions
    elif role == "admin":

        print("Admin Access")
        print("1. View record ID")
        print("2. View hash")
        print("3. View timestamp")
        print("4. Verify signature")

    # Patient permissions
    elif role == "patient":

        print("Patient Access")
        print("1. Read medical record")
        print("2. Encrypt record")
        print("3. Sign record")
        print("4. Upload record")
        print("5. View uploaded records")

    # Auditor permissions
    elif role == "auditor":

        print("Auditor Access")
        print("1. View filename")
        print("2. View hash")
        print("3. View timestamp")
        print("4. Verify signature")

    else:

        print("Invalid role")


# ------------------------------------------------------------
# EXAM HINT:
#
# DO NOT give every role every operation.
#
# Example:
#
# Student:
#     encrypt
#     sign
#     upload
#
# Faculty:
#     decrypt
#     verify
#
# HoD:
#     hash
#     signature verification
#
# ------------------------------------------------------------


# ============================================================
# BLOCK 14 — SIMPLE MENU SYSTEM
# ============================================================
#
# USE WHEN QUESTION SAYS:
#
#     "menu-driven Python program"
#
# ============================================================

def simple_menu():

    while True:

        print("\nMENU")
        print("1. Add record")
        print("2. View records")
        print("3. Verify record")
        print("4. Exit")

        choice = input("Enter choice: ")

        if choice == "1":

            print("Add record selected")

            # Put encryption/signing code here

        elif choice == "2":

            print("View records selected")

            # Put viewing code here

        elif choice == "3":

            print("Verify record selected")

            # Put hash/signature verification here

        elif choice == "4":

            print("Exiting...")
            break

        else:

            print("Invalid choice")


# ============================================================
# BLOCK 15 — RECORD STORAGE USING DICTIONARY
# ============================================================
#
# USE WHEN QUESTION SAYS:
#
#     store records
#     list / dictionary / array
#     database structure
#     save metadata
#
# ============================================================

records = []       # list used as simple database


def add_record(record_id, encrypted, hash_value, signature, timestamp):
    # Create dictionary representing one record
    record = {

        "id": record_id,                  # record identifier
        "encrypted": encrypted,           # encrypted data
        "hash": hash_value,               # SHA-256 hash
        "signature": signature,            # RSA signature
        "timestamp": timestamp            # upload time

    }

    # Add record to list
    records.append(record)


def view_records():

    # Check whether records exist
    if len(records) == 0:

        print("No records found")
        return

    # Display each record
    for record in records:

        print("\nRecord ID:", record["id"])
        print("Hash:", record["hash"])
        print("Timestamp:", record["timestamp"])


# ------------------------------------------------------------
# EXAM HINT:
#
# If question says:
#
#     "use any list, array, dictionary or file"
#
# this is enough for a basic lab implementation.
#
# ------------------------------------------------------------


# ============================================================
# BLOCK 16 — COMPLETE AES + SHA + RSA SIGNATURE PIPELINE
# ============================================================
#
# USE THIS FOR QUESTIONS LIKE:
#
#     MediSecure
#     Hospital AES + RSA + SHA
#     Patient uploads encrypted medical record
#
# Pipeline:
#
#     FILE
#       ↓
#     AES
#       ↓
#     CIPHERTEXT
#       ↓
#     SHA-256
#       ↓
#     HASH
#       ↓
#     RSA PRIVATE KEY
#       ↓
#     SIGNATURE
#
# ============================================================

def create_secure_aes_record():

    # --------------------------------------------------------
    # STEP 1 — READ FILE
    # --------------------------------------------------------

    filename = input("Enter medical record filename: ")

    data = read_text_file(filename)

    # --------------------------------------------------------
    # STEP 2 — GET AES KEY
    # --------------------------------------------------------

    key = input("Enter AES-128 key (16 characters): ").encode()

    if len(key) != 16:

        print("ERROR: AES key must be 16 bytes.")
        return None

    # --------------------------------------------------------
    # STEP 3 — GET IV
    # --------------------------------------------------------

    iv = input("Enter IV (16 characters): ").encode()

    if len(iv) != 16:

        print("ERROR: AES IV must be 16 bytes.")
        return None

    # --------------------------------------------------------
    # STEP 4 — AES ENCRYPT
    # --------------------------------------------------------

    encrypted = aes_encrypt(data, key, iv)

    print("Encrypted data =", encrypted.hex())

    # --------------------------------------------------------
    # STEP 5 — SHA-256 OF ENCRYPTED DATA
    # --------------------------------------------------------

    hash_value = sha256_hash(encrypted)

    print("SHA-256 =", hash_value)

    # --------------------------------------------------------
    # STEP 6 — RSA KEY GENERATION
    # --------------------------------------------------------

    private_key, public_key = generate_rsa_keys()

    # --------------------------------------------------------
    # STEP 7 — SIGN ENCRYPTED DATA
    # --------------------------------------------------------

    signature = rsa_sign(encrypted, private_key)

    print("Signature =", signature.hex())

    # --------------------------------------------------------
    # STEP 8 — TIMESTAMP
    # --------------------------------------------------------

    timestamp = get_timestamp()

    print("Timestamp =", timestamp)

    # --------------------------------------------------------
    # STEP 9 — STORE RECORD
    # --------------------------------------------------------

    record = {

        "filename": filename,          # original file name
        "encrypted": encrypted,         # AES ciphertext
        "hash": hash_value,             # SHA-256 hash
        "signature": signature,         # RSA signature
        "iv": iv,                       # AES IV
        "timestamp": timestamp          # upload time

    }

    return record, private_key, public_key, key


# ============================================================
# BLOCK 17 — COMPLETE VERIFY + DECRYPT PIPELINE
# ============================================================
#
# USE FOR:
#
#     MediSecure Doctor
#     EduSecure Faculty
#     HealthSecure Doctor
#
# LOGIC:
#
#     1. Calculate hash again
#     2. Compare hashes
#     3. Verify signature
#     4. ONLY IF BOTH PASS -> decrypt
#
# ============================================================

def verify_and_decrypt_aes_record(record, key, public_key, private_key):

    # --------------------------------------------------------
    # STEP 1 — GET ENCRYPTED DATA
    # --------------------------------------------------------

    encrypted = record["encrypted"]

    # --------------------------------------------------------
    # STEP 2 — RECOMPUTE HASH
    # --------------------------------------------------------

    new_hash = sha256_hash(encrypted)

    # Compare with stored hash
    if new_hash == record["hash"]:

        print("Integrity VERIFIED")

        integrity_ok = True

    else:

        print("Integrity FAILED")

        integrity_ok = False

    # --------------------------------------------------------
    # STEP 3 — VERIFY RSA SIGNATURE
    # --------------------------------------------------------

    signature_ok = rsa_verify(
        encrypted,
        record["signature"],
        public_key
    )

    if signature_ok:

        print("Signature VALID")

    else:

        print("Signature INVALID")

    # --------------------------------------------------------
    # STEP 4 — SECURITY DECISION
    # --------------------------------------------------------
    #
    # DO NOT DECRYPT IF VERIFICATION FAILED.
    # --------------------------------------------------------

    if integrity_ok and signature_ok:

        print("Both checks successful.")
        print("Decryption allowed.")

        # Decrypt
        decrypted = aes_decrypt(
            encrypted,
            key,
            record["iv"]
        )

        print("\nDecrypted medical record:")
        print(decrypted.decode())

    else:

        print("Verification failed.")
        print("Decryption NOT allowed.")


# ============================================================
# BLOCK 18 — COMPLETE DES + SHA + RSA SIGNATURE PIPELINE
# ============================================================
#
# USE FOR:
#
#     EduSecure
#
# Student:
#
#     DES encrypt
#     SHA-256
#     RSA sign
#
# Faculty:
#
#     verify hash
#     verify signature
#     decrypt
#
# HoD:
#
#     view hash
#     verify signature
#
# ============================================================

def create_secure_des_record():

    # --------------------------------------------------------
    # STEP 1 — READ ACADEMIC RECORD
    # --------------------------------------------------------

    filename = input("Enter academic record filename: ")

    data = read_text_file(filename)

    # --------------------------------------------------------
    # STEP 2 — DES KEY
    # --------------------------------------------------------

    des_key = input("Enter DES key (8 characters): ").encode()

    if len(des_key) != 8:

        print("ERROR: DES key must be 8 bytes.")
        return None

    # --------------------------------------------------------
    # STEP 3 — DES IV
    # --------------------------------------------------------

    iv = input("Enter DES IV (8 characters): ").encode()

    if len(iv) != 8:

        print("ERROR: DES IV must be 8 bytes.")
        return None

    # --------------------------------------------------------
    # STEP 4 — DES ENCRYPTION
    # --------------------------------------------------------

    encrypted = des_encrypt(
        data,
        des_key,
        iv
    )

    print("Encrypted record =", encrypted.hex())

    # --------------------------------------------------------
    # STEP 5 — SHA-256
    # --------------------------------------------------------

    hash_value = sha256_hash(encrypted)

    print("SHA-256 =", hash_value)

    # --------------------------------------------------------
    # STEP 6 — RSA KEY PAIR
    # --------------------------------------------------------

    private_key, public_key = generate_rsa_keys()

    # --------------------------------------------------------
    # STEP 7 — RSA DIGITAL SIGNATURE
    # --------------------------------------------------------

    signature = rsa_sign(
        encrypted,
        private_key
    )

    print("Signature =", signature.hex())

    # --------------------------------------------------------
    # STEP 8 — TIMESTAMP
    # --------------------------------------------------------

    timestamp = get_timestamp()

    # --------------------------------------------------------
    # STEP 9 — STORE RECORD
    # --------------------------------------------------------

    record = {

        "filename": filename,          # academic record file
        "encrypted": encrypted,         # DES ciphertext
        "hash": hash_value,             # SHA-256 hash
        "signature": signature,         # RSA signature
        "iv": iv,                       # DES IV
        "timestamp": timestamp          # upload timestamp

    }

    return record, private_key, public_key, des_key


# ============================================================
# BLOCK 19 — FACULTY / DOCTOR VERIFICATION
# ============================================================
#
# This is the common logic for:
#
#     Faculty
#     Doctor
#
# They can generally:
#
#     view encrypted record
#     verify hash
#     verify signature
#     decrypt IF verification succeeds
#
# ============================================================

def verify_and_decrypt_des_record(
        record,
        des_key,
        public_key):

    # Get encrypted record
    encrypted = record["encrypted"]

    # --------------------------------------------------------
    # HASH VERIFICATION
    # --------------------------------------------------------

    new_hash = sha256_hash(encrypted)

    if new_hash == record["hash"]:

        print("Integrity VERIFIED")

        integrity_ok = True

    else:

        print("Integrity FAILED")

        integrity_ok = False

    # --------------------------------------------------------
    # SIGNATURE VERIFICATION
    # --------------------------------------------------------

    signature_ok = rsa_verify(
        encrypted,
        record["signature"],
        public_key
    )

    if signature_ok:

        print("Signature VALID")

    else:

        print("Signature INVALID")

    # --------------------------------------------------------
    # ONLY DECRYPT IF BOTH ARE VALID
    # --------------------------------------------------------

    if integrity_ok and signature_ok:

        print("All checks passed.")
        print("Decrypting record...")

        decrypted = des_decrypt(
            encrypted,
            des_key,
            record["iv"]
        )

        print("\nOriginal academic record:")
        print(decrypted.decode())

    else:

        print("Security verification failed.")
        print("Decryption blocked.")


# ============================================================
# BLOCK 20 — HOD / ADMIN / AUDITOR VIEW
# ============================================================
#
# USE FOR:
#
#     HoD
#     Admin
#     Auditor
#
# They should NOT see plaintext.
#
# They can see things such as:
#
#     record ID
#     filename
#     hash
#     timestamp
#
# and may verify signatures.
#
# ============================================================

def restricted_view(record, public_key):

    print("\nRESTRICTED RECORD VIEW")

    # Display allowed metadata
    print("Filename / ID:", record.get("filename"))
    print("Hash:", record.get("hash"))
    print("Timestamp:", record.get("timestamp"))

    # --------------------------------------------------------
    # DO NOT PRINT:
    #
    #     decrypted plaintext
    #     private key
    #     shared encryption key
    #
    # --------------------------------------------------------

    # Verify signature
    signature_ok = rsa_verify(
        record["encrypted"],
        record["signature"],
        public_key
    )

    if signature_ok:

        print("Signature: VALID")

    else:

        print("Signature: INVALID")


# ============================================================
# BLOCK 21 — NURSE VIEW
# ============================================================
#
# USE FOR:
#
#     HealthSecure Nurse
#
# Nurse can see:
#
#     encrypted data
#     hash
#     signature
#     timestamp
#
# Nurse CANNOT:
#
#     decrypt
#     see plaintext
#     access private key
#
# ============================================================

def nurse_view(record, public_key):

    print("\nNURSE VIEW")

    # Allowed information
    print("Record ID:", record.get("filename"))
    print("Encrypted data:", record["encrypted"].hex())
    print("SHA-256:", record["hash"])
    print("Signature:", record["signature"].hex())
    print("Timestamp:", record["timestamp"])

    # Verify integrity
    new_hash = sha256_hash(record["encrypted"])

    if new_hash == record["hash"]:

        print("Integrity: VALID")

    else:

        print("Integrity: INVALID")

    # Verify signature
    if rsa_verify(
        record["encrypted"],
        record["signature"],
        public_key
    ):

        print("Authenticity: VALID")

    else:

        print("Authenticity: INVALID")

    # IMPORTANT:
    #
    # No decryption code here.
    #
    # Nurse does NOT receive private_key.


# ============================================================
# BLOCK 22 — SIMPLE RBAC MENU FOR EDUsecure
# ============================================================
#
# USE DIRECTLY FOR THE EDUSECURE PYQ.
#
# ------------------------------------------------------------
# Student:
#     encrypt
#     sign
#     upload
#
# Faculty:
#     verify
#     decrypt
#
# HoD:
#     view hash
#     verify signature
#
# ============================================================

def edusecure_menu():

    while True:

        print("\nEDUSECURE")

        print("1. Student")
        print("2. Faculty")
        print("3. HoD")
        print("4. Exit")

        choice = input("Enter choice: ")

        # ----------------------------------------------------
        # STUDENT
        # ----------------------------------------------------

        if choice == "1":

            print("\nSTUDENT")

            print("1. Upload encrypted record")
            print("2. View uploaded records")
            print("3. Back")

            student_choice = input("Enter choice: ")

            if student_choice == "1":

                print("Student can encrypt and sign records.")

                # Put create_secure_des_record() here.

            elif student_choice == "2":

                view_records()

        # ----------------------------------------------------
        # FACULTY
        # ----------------------------------------------------

        elif choice == "2":

            print("\nFACULTY")

            print("1. View records")
            print("2. Verify and decrypt")
            print("3. Back")

            faculty_choice = input("Enter choice: ")

            if faculty_choice == "1":

                view_records()

            elif faculty_choice == "2":

                print("Faculty can verify and decrypt.")

                # Put verification + DES decryption here.

        # ----------------------------------------------------
        # HOD
        # ----------------------------------------------------

        elif choice == "3":

            print("\nHOD")

            print("1. View hashes")
            print("2. Verify signatures")
            print("3. Back")

            hod_choice = input("Enter choice: ")

            if hod_choice == "1":

                view_records()

            elif hod_choice == "2":

                print("HoD can verify signatures.")

        # ----------------------------------------------------
        # EXIT
        # ----------------------------------------------------

        elif choice == "4":

            print("Exiting...")
            break

        else:

            print("Invalid choice.")


# ============================================================
# BLOCK 23 — SIMPLE RBAC MENU FOR HEALTHSECURE
# ============================================================
#
# USE DIRECTLY FOR:
#
#     HealthSecure
#
# Doctor:
#     enter patient information
#     encrypt
#     sign
#     decrypt
#
# Nurse:
#     view encrypted data
#     verify hash
#     verify signature
#
# Admin:
#     view ID
#     view hash
#     view timestamp
#     verify signature
#
# ============================================================

def healthsecure_menu():

    while True:

        print("\nHEALTHSECURE")

        print("1. Doctor")
        print("2. Nurse")
        print("3. Admin")
        print("4. Exit")

        choice = input("Enter choice: ")

        # ----------------------------------------------------
        # DOCTOR
        # ----------------------------------------------------

        if choice == "1":

            print("\nDOCTOR")

            print("1. Enter patient information")
            print("2. Encrypt and store record")
            print("3. View records")
            print("4. Verify and decrypt")
            print("5. Back")

            doctor_choice = input("Enter choice: ")

            if doctor_choice == "1":

                print("Enter patient information.")

                # Example dictionary
                patient = {

                    "name": input("Name: "),          # patient name
                    "age": input("Age: "),            # patient age
                    "gender": input("Gender: "),      # patient gender
                    "blood": input("Blood group: "),  # blood group
                    "diagnosis": input("Diagnosis: ") # diagnosis

                }

                print("Patient information stored.")

            elif doctor_choice == "2":

                print("Doctor can encrypt and sign.")

                # Put encryption/signing code here.

            elif doctor_choice == "3":

                view_records()

            elif doctor_choice == "4":

                print("Doctor can verify and decrypt.")

                # Put verify_and_decrypt code here.

        # ----------------------------------------------------
        # NURSE
        # ----------------------------------------------------

        elif choice == "2":

            print("\nNURSE")

            print("1. View encrypted records")
            print("2. Verify integrity")
            print("3. Verify signature")
            print("4. Back")

            nurse_choice = input("Enter choice: ")

            if nurse_choice == "1":

                print("Nurse can view encrypted data.")

            elif nurse_choice == "2":

                print("Nurse can calculate SHA-256.")

            elif nurse_choice == "3":

                print("Nurse can verify Doctor signature.")

        # ----------------------------------------------------
        # ADMIN
        # ----------------------------------------------------

        elif choice == "3":

            print("\nADMIN")

            print("1. View record metadata")
            print("2. Verify signature")
            print("3. Back")

            admin_choice = input("Enter choice: ")

            if admin_choice == "1":

                print("Admin can see:")
                print("Record ID")
                print("Hash")
                print("Timestamp")

            elif admin_choice == "2":

                print("Admin can verify signature.")

        # ----------------------------------------------------
        # EXIT
        # ----------------------------------------------------

        elif choice == "4":

            print("Exiting...")
            break

        else:

            print("Invalid choice.")


# ============================================================
# BLOCK 24 — COMPLETE FINANCIAL ADVISOR PYQ
# ============================================================
#
# QUESTION PATTERN:
#
#     Read encryption_message.txt
#     Generate RSA keys
#     Show n, e, d
#     Encrypt plaintext
#     Decrypt plaintext
#     Custom hash
#     Store hash in hash.txt
#     Verify integrity
#     Tamper with message
#     Detect modification
#
# ============================================================

def financial_advisor_pypq():

    # --------------------------------------------------------
    # STEP 1 — READ MESSAGE
    # --------------------------------------------------------

    filename = "encryption_message.txt"

    message = read_text_file_normal(filename)

    print("Original message:")
    print(message)

    # --------------------------------------------------------
    # STEP 2 — RSA KEY GENERATION
    # --------------------------------------------------------

    private_key, public_key = generate_rsa_keys()

    # --------------------------------------------------------
    # STEP 3 — DISPLAY RSA PARAMETERS
    # --------------------------------------------------------

    print("\nRSA PARAMETERS")

    print("n =", private_key.n)
    print("e =", private_key.e)
    print("d =", private_key.d)

    # --------------------------------------------------------
    # STEP 4 — RSA ENCRYPTION
    # --------------------------------------------------------

    encrypted = rsa_encrypt(
        message.encode(),
        public_key
    )

    print("\nEncrypted message:")
    print(encrypted.hex())

    # --------------------------------------------------------
    # STEP 5 — RSA DECRYPTION
    # --------------------------------------------------------

    decrypted = rsa_decrypt(
        encrypted,
        private_key
    )

    print("\nDecrypted message:")
    print(decrypted.decode())

    # --------------------------------------------------------
    # STEP 6 — CUSTOM HASH
    # --------------------------------------------------------

    original_hash = custom_hash(message)

    print("\nOriginal hash:")
    print(original_hash)

    # --------------------------------------------------------
    # STEP 7 — STORE HASH
    # --------------------------------------------------------

    write_text_file(
        "hash.txt",
        str(original_hash)
    )

    print("Hash stored in hash.txt")

    # --------------------------------------------------------
    # STEP 8 — READ MESSAGE AGAIN
    # --------------------------------------------------------

    current_message = read_text_file_normal(filename)

    # Calculate new hash
    current_hash = custom_hash(current_message)

    # Read stored hash
    stored_hash = int(
        read_text_file_normal("hash.txt")
    )

    # --------------------------------------------------------
    # STEP 9 — INTEGRITY CHECK
    # --------------------------------------------------------

    if current_hash == stored_hash:

        print("\nIntegrity Verified")
        print("Message has not been tampered with.")

    else:

        print("\nIntegrity Check Failed")
        print("Message has been tampered with.")

    # --------------------------------------------------------
    # STEP 10 — TAMPERING
    # --------------------------------------------------------
    #
    # IMPORTANT:
    # This actually modifies the file.
    #
    # Change 2500 to 5000.
    # --------------------------------------------------------

    tampered_message = current_message.replace(
        "2500",
        "5000"
    )

    write_text_file(
        filename,
        tampered_message
    )

    print("\nFile tampered.")
    print("Changed 2500 -> 5000")

    # --------------------------------------------------------
    # STEP 11 — CHECK AGAIN
    # --------------------------------------------------------

    changed_message = read_text_file_normal(filename)

    changed_hash = custom_hash(changed_message)

    # Compare with ORIGINAL stored hash
    if changed_hash == stored_hash:

        print("Integrity Verified")

    else:

        print("Integrity Check Failed")
        print("Message has been tampered with.")


# ============================================================
# BLOCK 25 — HOSPITAL AES + RSA + ELGAMAL PYQ
# ============================================================
#
# QUESTION PATTERN:
#
#     Create file
#     AES encrypt file
#     Store ciphertext
#     RSA encrypt AES key
#     ElGamal authorization code
#     SHA hash encrypted AES message
#     Verify hash
#     If valid -> decrypt
#     If invalid -> don't decrypt
#
# ============================================================

def hospital_aes_rsa_elgamal():

    # --------------------------------------------------------
    # STEP 1 — CREATE / READ FILE
    # --------------------------------------------------------

    filename = input("Enter filename: ")

    content = input("Enter file content: ")

    write_text_file(
        filename,
        content
    )

    # Read file
    data = read_text_file(filename)

    # --------------------------------------------------------
    # STEP 2 — AES KEY + IV
    # --------------------------------------------------------

    aes_key = input(
        "Enter AES-128 key (16 characters): "
    ).encode()

    if len(aes_key) != 16:

        print("ERROR: AES key must be 16 bytes.")
        return

    iv = input(
        "Enter AES IV (16 characters): "
    ).encode()

    if len(iv) != 16:

        print("ERROR: AES IV must be 16 bytes.")
        return

    # --------------------------------------------------------
    # STEP 3 — AES ENCRYPTION
    # --------------------------------------------------------

    encrypted = aes_encrypt(
        data,
        aes_key,
        iv
    )

    print("\nAES encrypted message:")
    print(encrypted.hex())

    # Store encrypted message
    write_binary_file(
        "encrypted.txt",
        encrypted
    )

    # --------------------------------------------------------
    # STEP 4 — RSA KEY GENERATION
    # --------------------------------------------------------

    private_key, public_key = generate_rsa_keys()

    # Display RSA values
    print("\nRSA n =", private_key.n)
    print("RSA e =", private_key.e)
    print("RSA d =", private_key.d)

    # --------------------------------------------------------
    # STEP 5 — RSA ENCRYPT AES KEY
    # --------------------------------------------------------

    encrypted_aes_key = rsa_encrypt(
        aes_key,
        public_key
    )

    write_binary_file(
        "encrypted_aes_key.txt",
        encrypted_aes_key
    )

    print("\nEncrypted AES key:")
    print(encrypted_aes_key.hex())

    # --------------------------------------------------------
    # STEP 6 — ELGAMAL AUTHORIZATION CODE
    # --------------------------------------------------------
    #
    # Replace these with values GIVEN BY THE QUESTION.
    # --------------------------------------------------------

    p = int(input("\nElGamal p: "))
    g = int(input("ElGamal g: "))
    x = int(input("ElGamal private x: "))

    y, x = elgamal_keygen(
        p,
        g,
        x
    )

    authorization = int(
        input("Authorization code as integer: ")
    )

    k = int(
        input("ElGamal random k: ")
    )

    c1, c2 = elgamal_encrypt(
        authorization,
        p,
        g,
        y,
        k
    )

    print("\nElGamal public y =", y)
    print("ElGamal encrypted authorization:")
    print("c1 =", c1)
    print("c2 =", c2)

    # --------------------------------------------------------
    # STEP 7 — HASH AES CIPHERTEXT
    # --------------------------------------------------------

    hash_value = sha256_hash(
        encrypted
    )

    print("\nSHA-256 of AES ciphertext:")
    print(hash_value)

    # Store hash
    write_text_file(
        "hash.txt",
        hash_value
    )

    # --------------------------------------------------------
    # STEP 8 — READ ENCRYPTED FILE AGAIN
    # --------------------------------------------------------

    current_encrypted = read_binary_file(
        "encrypted.txt"
    )

    # Calculate new hash
    new_hash = sha256_hash(
        current_encrypted
    )

    # Read stored hash
    stored_hash = read_text_file_normal(
        "hash.txt"
    )

    # --------------------------------------------------------
    # STEP 9 — INTEGRITY CHECK
    # --------------------------------------------------------

    if new_hash != stored_hash:

        print("\nIntegrity FAILED")
        print("Do NOT decrypt.")
        return

    print("\nIntegrity VERIFIED")

    # --------------------------------------------------------
    # STEP 10 — RSA DECRYPT AES KEY
    # --------------------------------------------------------

    recovered_aes_key = rsa_decrypt(
        encrypted_aes_key,
        private_key
    )

    print("Recovered AES key:")
    print(recovered_aes_key)

    # --------------------------------------------------------
    # STEP 11 — AES DECRYPT
    # --------------------------------------------------------

    decrypted = aes_decrypt(
        current_encrypted,
        recovered_aes_key,
        iv
    )

    print("\nDecrypted original file content:")
    print(decrypted.decode())


# ============================================================
# BLOCK 26 — PERFORMANCE COMPARISON
# ============================================================
#
# USE WHEN QUESTION SAYS:
#
#     compare MD5 / SHA-1 / SHA-256
#     computation time
#     collision detection
#     generate 50-100 strings
#
# ============================================================

def hash_performance():

    # Number of test strings
    n = int(
        input("Number of random strings [50]: ") or "50"
    )

    # Generate random strings
    data_list = []

    for i in range(n):

        # Generate 16 random bytes
        data = os.urandom(16)

        data_list.append(data)

    # Algorithms
    algorithms = {

        "MD5": hashlib.md5,
        "SHA-1": hashlib.sha1,
        "SHA-256": hashlib.sha256

    }

    # Test each algorithm
    for name, function in algorithms.items():

        # Start timer
        start = time.perf_counter()

        hashes = []

        for data in data_list:

            h = function(data).hexdigest()

            hashes.append(h)

        # End timer
        end = time.perf_counter()

        # Check collisions
        collision_count = (
            len(hashes) - len(set(hashes))
        )

        print("\nAlgorithm:", name)
        print("Time:", end - start, "seconds")
        print("Collisions:", collision_count)


# ------------------------------------------------------------
# EXAM HINT:
#
# If question asks for 50-100 strings:
#
#     n = 50
#
# or:
#
#     n = 100
#
# Use:
#
#     os.urandom()
#
# to generate random data.
#
# ------------------------------------------------------------


# ============================================================
# BLOCK 27 — COMPLETE "VERIFY THEN DECRYPT" MASTER PATTERN
# ============================================================
#
# MEMORIZE THIS LOGIC.
#
# This is useful in:
#
#     HealthSecure
#     MediSecure
#     EduSecure
#     Hospital questions
#     File transfer questions
#
# ============================================================

def verify_then_decrypt(
        encrypted,
        stored_hash,
        signature,
        public_key):

    # --------------------------------------------------------
    # HASH CHECK
    # --------------------------------------------------------

    new_hash = sha256_hash(
        encrypted
    )

    if new_hash == stored_hash:

        integrity_ok = True
        print("Integrity VERIFIED")

    else:

        integrity_ok = False
        print("Integrity FAILED")

    # --------------------------------------------------------
    # SIGNATURE CHECK
    # --------------------------------------------------------

    signature_ok = rsa_verify(
        encrypted,
        signature,
        public_key
    )

    if signature_ok:

        print("Signature VALID")

    else:

        print("Signature INVALID")

    # --------------------------------------------------------
    # FINAL DECISION
    # --------------------------------------------------------

    if integrity_ok and signature_ok:

        print("Both checks passed.")
        print("Decryption is allowed.")

        return True

    else:

        print("Security verification failed.")
        print("Decryption is NOT allowed.")

        return False


# ============================================================
# BLOCK 28 — COMMON INPUT CONVERSION HELPERS
# ============================================================
#
# USE WHEN THE QUESTION GIVES DATA IN:
#
#     text
#     hexadecimal
#     integer
#
# ============================================================

def text_to_bytes(text):
    # Convert normal text to bytes
    return text.encode()


def bytes_to_hex(data):
    # Convert bytes to hexadecimal string
    return data.hex()


def hex_to_bytes(text):
    # Convert hexadecimal string to bytes
    return bytes.fromhex(text)


def decimal_to_hex(number):
    # Convert decimal integer to hexadecimal
    return hex(number)


def hex_to_decimal(text):
    # Convert hexadecimal string to decimal
    return int(text, 16)


# ------------------------------------------------------------
# QUICK CONVERSION TABLE
#
# Text -> bytes:
#
#     "hello".encode()
#
# Bytes -> text:
#
#     data.decode()
#
# Bytes -> hex:
#
#     data.hex()
#
# Hex -> bytes:
#
#     bytes.fromhex(h)
#
# Decimal -> hex:
#
#     hex(n)
#
# Hex -> decimal:
#
#     int(h, 16)
#
# ------------------------------------------------------------


# ============================================================
# BLOCK 29 — COMMON ERROR HANDLING
# ============================================================
#
# USE THIS WHEN YOU DON'T WANT THE PROGRAM TO CRASH.
#
# ============================================================

def safe_aes_decrypt(encrypted, key, iv):

    try:

        decrypted = aes_decrypt(
            encrypted,
            key,
            iv
        )

        return decrypted

    except Exception as e:

        print("AES decryption error:", e)

        return None


def safe_rsa_decrypt(encrypted, private_key):

    try:

        decrypted = rsa_decrypt(
            encrypted,
            private_key
        )

        return decrypted

    except Exception as e:

        print("RSA decryption error:", e)

        return None


# ------------------------------------------------------------
# EXAM HINT:
#
# If your teacher expects:
#
#     "display error and continue"
#
# use try/except.
#
# ------------------------------------------------------------


# ============================================================
# BLOCK 30 — QUICK REFERENCE: WHAT TO CHANGE
# ============================================================
#
# This section is for EXAM USE.
#
# ------------------------------------------------------------
#
# QUESTION SAYS:
#
# "Financial transaction"
#
# Change:
#
#     filename = "encryption_message.txt"
#
# Custom hash:
#
#     use custom_hash()
#
# ------------------------------------------------------------
#
# QUESTION SAYS:
#
# "Academic records"
#
# Use:
#
#     DES
#     SHA-256
#     RSA signature
#     Student / Faculty / HoD
#
# ------------------------------------------------------------
#
# QUESTION SAYS:
#
# "Medical record using AES"
#
# Use:
#
#     AES
#     SHA-256
#     RSA signature
#     Patient / Doctor / Auditor
#
# ------------------------------------------------------------
#
# QUESTION SAYS:
#
# "Patient information with Doctor / Nurse / Admin"
#
# Use:
#
#     RSA encryption
#     SHA-256
#     RSA signature
#     RBAC
#
# ------------------------------------------------------------
#
# QUESTION SAYS:
#
# "AES + RSA"
#
# Usually:
#
#     AES -> encrypt actual data
#     RSA -> encrypt/protect AES key
#
# ------------------------------------------------------------
#
# QUESTION SAYS:
#
# "tampering"
#
# Do:
#
#     original hash
#     modify data
#     new hash
#     compare
#
# ------------------------------------------------------------
#
# QUESTION SAYS:
#
# "integrity failed -> don't decrypt"
#
# Use:
#
#     if hash_valid:
#         decrypt
#     else:
#         print("Integrity failed")
#
# ------------------------------------------------------------
#
# QUESTION SAYS:
#
# "authentication"
#
# Usually:
#
#     RSA digital signature
#
# ------------------------------------------------------------
#
# QUESTION SAYS:
#
# "confidentiality"
#
# Usually:
#
#     encryption
#
# ------------------------------------------------------------
#
# QUESTION SAYS:
#
# "integrity"
#
# Usually:
#
#     SHA-256
#
# ------------------------------------------------------------
#
# QUESTION SAYS:
#
# "authorization"
#
# Usually:
#
#     RBAC
#
# ============================================================


# ============================================================
# BLOCK 31 — EXAM DECISION TREE
# ============================================================
#
# When you get ANY question, ask these questions:
#
# ------------------------------------------------------------
#
# Q1. WHAT IS THE DATA?
#
# Example:
#
#     patient record
#     academic record
#     transaction
#     authorization code
#     text file
#
# ------------------------------------------------------------
#
# Q2. WHAT ENCRYPTION ALGORITHM?
#
#     RSA?
#     AES?
#     DES?
#
# Use the corresponding block.
#
# ------------------------------------------------------------
#
# Q3. DOES IT SAY HASH?
#
# YES:
#
#     use SHA-256
#
# Unless a mathematical/custom hash is explicitly provided.
#
# ------------------------------------------------------------
#
# Q4. DOES IT SAY DIGITAL SIGNATURE?
#
# YES:
#
#     private key -> sign
#     public key -> verify
#
# ------------------------------------------------------------
#
# Q5. DOES IT SAY INTEGRITY?
#
# YES:
#
#     calculate hash
#     compare hashes
#
# ------------------------------------------------------------
#
# Q6. DOES IT SAY TAMPER/MODIFY?
#
# YES:
#
#     modify one character
#     hash again
#     demonstrate mismatch
#
# ------------------------------------------------------------
#
# Q7. DOES IT HAVE ROLES?
#
# YES:
#
#     create RBAC menu.
#
# ------------------------------------------------------------
#
# Q8. DOES IT SAY FILE?
#
# YES:
#
#     open()
#     read()
#     write()
#
# ------------------------------------------------------------
#
# Q9. DOES IT SAY TIMESTAMP?
#
# YES:
#
#     datetime.now()
#
# ------------------------------------------------------------
#
# Q10. DOES IT SAY "ONLY DECRYPT IF VERIFIED"?
#
# YES:
#
#     if integrity_ok and signature_ok:
#         decrypt()
#     else:
#         don't decrypt
#
# ============================================================


# ============================================================
# BLOCK 32 — CIA TRIAD CHEAT SHEET
# ============================================================
#
# CIA = Confidentiality, Integrity, Availability
#
# In your cryptography questions:
#
# ------------------------------------------------------------
#
# CONFIDENTIALITY
#
#     Encryption
#
#     AES / DES / RSA
#
#     Prevent unauthorized people from reading data.
#
# ------------------------------------------------------------
#
# INTEGRITY
#
#     SHA-256
#
#     Detect whether data was modified.
#
# ------------------------------------------------------------
#
# AUTHENTICITY
#
#     Digital signature
#
#     RSA private key -> sign
#     RSA public key  -> verify
#
# ------------------------------------------------------------
#
# AUTHORIZATION
#
#     RBAC
#
#     Decides what Student / Faculty / HoD etc. can do.
#
# ============================================================


# ============================================================
# BLOCK 33 — FINAL SECURITY PIPELINE TO MEMORIZE
# ============================================================
#
#
#                 ORIGINAL DATA
#                      |
#                      v
#                AES / DES / RSA
#                      |
#                      v
#                  CIPHERTEXT
#                      |
#                +-----+-----+
#                |           |
#                v           v
#             SHA-256     RSA PRIVATE
#                |           |
#                v           v
#              HASH       SIGNATURE
#                |           |
#                +-----+-----+
#                      |
#                  STORE ALL
#                      |
#        +-------------+-------------+
#        |                           |
#        v                           v
#   RECEIVER GETS               STORED VALUES
#        |
#        +---- SHA-256 ----> NEW HASH
#        |
#        +---- RSA PUBLIC -> VERIFY SIGNATURE
#                                    |
#                              +-----+-----+
#                              |           |
#                             VALID      INVALID
#                              |
#                         HASH VALID?
#                              |
#                       +------+------+
#                       |             |
#                      YES            NO
#                       |             |
#                   DECRYPT          STOP
#                       |
#                       v
#                   PLAINTEXT
#
# ============================================================


# ============================================================
# MAIN
# ============================================================
#
# DO NOT automatically run every block.
#
# In the exam, replace this section with the function that
# matches the question.
#
# Examples:
#
#     financial_advisor_pypq()
#
# OR:
#
#     hospital_aes_rsa_elgamal()
#
# OR:
#
#     edusecure_menu()
#
# OR:
#
#     healthsecure_menu()
#
# ============================================================

if __name__ == "__main__":

    print("CRYPTOGRAPHY MASTER TEMPLATE")
    print()
    print("Choose a demo:")
    print("1. RSA")
    print("2. AES")
    print("3. DES")
    print("4. SHA-256")
    print("5. Custom Hash")
    print("6. RSA Signature")
    print("7. ElGamal")
    print("8. Diffie-Hellman")
    print("9. Integrity + Tampering")
    print("10. Hash Performance")
    print("11. Financial Advisor PYQ")
    print("12. Hospital AES + RSA + ElGamal PYQ")

    choice = input("\nEnter choice: ")

    if choice == "1":
        rsa_example()

    elif choice == "2":
        aes_example()

    elif choice == "3":
        des_example()

    elif choice == "4":
        sha256_example()

    elif choice == "5":
        custom_hash_example()

    elif choice == "6":
        signature_example()

    elif choice == "7":
        elgamal_example()

    elif choice == "8":
        diffie_hellman_example()

    elif choice == "9":
        tampering_example()

    elif choice == "10":
        hash_performance()

    elif choice == "11":
        financial_advisor_pypq()

    elif choice == "12":
        hospital_aes_rsa_elgamal()

    else:
        print("Invalid choice.")