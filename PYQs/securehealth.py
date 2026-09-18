# ============================================================
# HEALTHSECURE
# ============================================================
#
# QUESTION:
#
# A hospital wants a secure patient-information system.
#
# There are 3 roles:
#
#       DOCTOR
#       NURSE
#       ADMIN
#
# The system must provide:
#
# 1. RSA public/private keys
# 2. Encryption of patient information
# 3. SHA-256 hashing
# 4. RSA digital signatures
# 5. Role-Based Access Control (RBAC)
# 6. Patient record storage
# 7. Timestamps
# 8. Integrity verification
# 9. Authenticity verification
# 10. Different permissions for Doctor, Nurse and Admin
#
#
# ============================================================
# WHAT ARE WE ACTUALLY DOING?
# ============================================================
#
# DOCTOR:
#
# Patient information
#       ↓
# Encrypt
#       ↓
# Encrypted patient data
#       ↓
# SHA-256
#       ↓
# Hash
#
# Doctor's PRIVATE KEY
#       ↓
# Digital Signature
#
# Then store:
#
#     Patient ID
#     Patient name
#     Encrypted data
#     Hash
#     Signature
#     Timestamp
#
#
# NURSE:
#
# Can see encrypted data.
# Can calculate the hash again.
# Can verify the signature.
#
# BUT:
#
# Nurse cannot access the private key.
# Nurse cannot decrypt the patient data.
#
#
# ADMIN:
#
# Can see:
#     Patient ID
#     Patient name
#     Hash
#     Timestamp
#
# Admin can verify the signature.
#
# Admin cannot decrypt the patient data.
#
#
# ============================================================
# RBAC
# ============================================================
#
# RBAC = Role-Based Access Control.
#
# Instead of asking:
#
#     "Is this person allowed?"
#
# We check their ROLE.
#
# Doctor:
#     CREATE
#     VIEW
#     DECRYPT
#     VERIFY
#
# Nurse:
#     VIEW ENCRYPTED
#     VERIFY
#
# Admin:
#     VIEW LIMITED INFORMATION
#     VERIFY
#
# ============================================================

import base64
import hashlib
from datetime import datetime

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ============================================================
# RSA KEY GENERATION
# ============================================================
#
# Doctor needs a public/private RSA key pair.
#
# PUBLIC KEY:
#     Can be shared.
#
# PRIVATE KEY:
#     Must remain secret.
#
# Doctor uses:
#
#     Public key  → encryption
#     Private key → decryption + signing
#
# ============================================================

def make_keys():                                      # generate Doctor RSA keys

    pri = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    pub = pri.public_key()                            # get public key

    return pub, pri


# ============================================================
# PATIENT DATA
# ============================================================
#
# We store patient information in a dictionary.
#
# Example:
#
# {
#     "name": "Rahul",
#     "age": "25",
#     "gender": "Male",
#     "blood_group": "O+",
#     "diagnosis": "Fever"
# }
#
# ============================================================

def get_patient_data():                               # collect patient information

    data = {}

    data["name"] = input("Patient name: ")
    data["age"] = input("Age: ")
    data["gender"] = input("Gender: ")
    data["blood_group"] = input("Blood group: ")
    data["diagnosis"] = input("Diagnosis: ")
    data["other"] = input("Other medical details: ")

    return data


# ============================================================
# CONVERT PATIENT DATA TO TEXT
# ============================================================

def patient_to_text(data):                            # convert dictionary to string

    text = ""

    for key in data:

        text += key + ": " + data[key] + "\n"

    return text


# ============================================================
# AES ENCRYPTION
# ============================================================
#
# RSA cannot directly encrypt a large patient record.
#
# So:
#
#     1. Generate random AES key.
#     2. Encrypt patient data using AES.
#     3. Encrypt AES key using Doctor's RSA public key.
#
# This is called HYBRID ENCRYPTION.
#
# RSA is still responsible for protecting the AES key.
#
# ============================================================

def encrypt_data(text, pub):                          # encrypt patient information

    data = text.encode()                              # convert text to bytes

    aes_key = AESGCM.generate_key(
        bit_length=256
    )                                                 # random AES key

    aes = AESGCM(aes_key)                             # create AES object

    nonce = AESGCM.generate_key(
        bit_length=128
    )                                                 # temporary value - replaced below

    # AES-GCM requires a 12-byte nonce.
    # We generate it using the secure random module.
    import os

    nonce = os.urandom(12)                            # random 12-byte nonce

    encrypted = aes.encrypt(
        nonce,
        data,
        None
    )                                                 # encrypt patient data


    # --------------------------------------------------------
    # Encrypt AES key using RSA public key
    # --------------------------------------------------------

    encrypted_key = pub.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(
                algorithm=hashes.SHA256()
            ),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return encrypted, encrypted_key, nonce


# ============================================================
# SHA-256
# ============================================================
#
# Hash is calculated on the ENCRYPTED patient data.
#
# If encrypted data changes:
#
#     new hash != stored hash
#
# Therefore we know that the stored encrypted data
# may have been modified.
#
# ============================================================

def get_hash(data):                                   # calculate SHA-256

    return hashlib.sha256(data).hexdigest()


# ============================================================
# DIGITAL SIGNATURE
# ============================================================
#
# Doctor signs the SHA-256 hash using the PRIVATE KEY.
#
# PRIVATE KEY → SIGN
#
# ============================================================

def sign_hash(h, pri):                                # sign hash with private key

    return pri.sign(
        h.encode(),
        padding.PSS(
            mgf=padding.MGF1(
                hashes.SHA256()
            ),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )


# ============================================================
# VERIFY DIGITAL SIGNATURE
# ============================================================
#
# PUBLIC KEY → VERIFY
#
# If verification succeeds:
#
#     signature is VALID
#
# Otherwise:
#
#     signature is INVALID
#
# ============================================================

def verify_signature(h, sig, pub):                    # verify Doctor signature

    try:

        pub.verify(
            sig,
            h.encode(),
            padding.PSS(
                mgf=padding.MGF1(
                    hashes.SHA256()
                ),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        return True

    except Exception:

        return False


# ============================================================
# DECRYPT PATIENT DATA
# ============================================================
#
# Only Doctor is allowed to call this function.
#
# First:
#
#     RSA private key decrypts AES key.
#
# Then:
#
#     AES key decrypts patient information.
#
# ============================================================

def decrypt_data(encrypted, encrypted_key, nonce, pri):     # decrypt patient data

    try:

        aes_key = pri.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(
                    algorithm=hashes.SHA256()
                ),
                algorithm=hashes.SHA256(),
                label=None
            )
        )                                                 # recover AES key


        aes = AESGCM(aes_key)                             # create AES object

        data = aes.decrypt(
            nonce,
            encrypted,
            None
        )                                                 # decrypt patient data

        return data.decode()

    except Exception:

        print("ERROR: Decryption failed.")

        return None


# ============================================================
# CREATE PATIENT RECORD
# ============================================================
#
# Doctor creates the patient record.
#
# We store:
#
#     ID
#     Name
#     encrypted data
#     encrypted AES key
#     nonce
#     hash
#     signature
#     timestamp
#
# ============================================================

def create_record(records, pub, pri):                  # Doctor creates record

    print("\nENTER PATIENT INFORMATION")

    data = get_patient_data()

    text = patient_to_text(data)

    encrypted, encrypted_key, nonce = encrypt_data(
        text,
        pub
    )

    h = get_hash(encrypted)                            # SHA-256 of encrypted data

    sig = sign_hash(
        h,
        pri
    )                                                  # Doctor signs hash

    rid = input("Record ID: ")                         # patient record ID

    if rid == "":
        print("ERROR: Record ID cannot be empty.")
        return

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    records[rid] = {

        "name": data["name"],                          # store patient name

        "encrypted": encrypted,                        # encrypted patient data

        "encrypted_key": encrypted_key,                # RSA encrypted AES key

        "nonce": nonce,                                # AES-GCM nonce

        "hash": h,                                     # SHA-256 hash

        "signature": sig,                              # Doctor digital signature

        "timestamp": timestamp                         # creation time
    }

    print("\nRecord stored successfully.")

    print("Record ID:", rid)

    print("Timestamp:", timestamp)


# ============================================================
# DOCTOR VIEW RECORD
# ============================================================
#
# Doctor can:
#
#     1. View encrypted record.
#     2. Check hash.
#     3. Verify signature.
#     4. Decrypt only if both checks pass.
#
# ============================================================

def doctor_view(records, pub, pri):                    # Doctor views record

    rid = input("Enter record ID: ")

    if rid not in records:

        print("ERROR: Record not found.")

        return

    r = records[rid]

    print("\nRECORD")
    print("ID:", rid)
    print("Patient:", r["name"])
    print("Timestamp:", r["timestamp"])

    print("\nEncrypted data:")
    print(base64.b64encode(
        r["encrypted"]
    ).decode())

    # --------------------------------------------------------
    # Integrity check
    # --------------------------------------------------------

    new_hash = get_hash(
        r["encrypted"]
    )                                                   # calculate hash again

    print("\nStored hash:")
    print(r["hash"])

    print("\nNew hash:")
    print(new_hash)

    if new_hash == r["hash"]:

        print("INTEGRITY: VALID")

    else:

        print("INTEGRITY: INVALID")

        return


    # --------------------------------------------------------
    # Signature check
    # --------------------------------------------------------

    valid = verify_signature(
        r["hash"],
        r["signature"],
        pub
    )

    if valid:

        print("SIGNATURE: VALID")

    else:

        print("SIGNATURE: INVALID")

        return


    # --------------------------------------------------------
    # Decrypt
    # --------------------------------------------------------

    print("\nBoth checks passed.")

    plain = decrypt_data(
        r["encrypted"],
        r["encrypted_key"],
        r["nonce"],
        pri
    )

    if plain is not None:

        print("\nPATIENT INFORMATION")

        print(plain)


# ============================================================
# NURSE VIEW
# ============================================================
#
# Nurse is NOT given the private key.
#
# Nurse can:
#
#     View encrypted data
#     View hash
#     View signature
#     View timestamp
#     Verify hash
#     Verify signature
#
# Nurse CANNOT:
#
#     Decrypt patient information.
#
# ============================================================

def nurse_view(records, pub):                          # Nurse views encrypted records

    rid = input("Enter record ID: ")

    if rid not in records:

        print("ERROR: Record not found.")

        return

    r = records[rid]

    print("\nNURSE VIEW")

    print("Record ID:", rid)

    print("Patient:", r["name"])

    print("Encrypted data:")

    print(
        base64.b64encode(
            r["encrypted"]
        ).decode()
    )

    print("\nStored SHA-256:")
    print(r["hash"])

    print("\nSignature:")
    print(
        base64.b64encode(
            r["signature"]
        ).decode()
    )

    print("\nTimestamp:")
    print(r["timestamp"])


    # --------------------------------------------------------
    # Integrity verification
    # --------------------------------------------------------

    new_hash = get_hash(
        r["encrypted"]
    )

    if new_hash == r["hash"]:

        print("\nINTEGRITY: VALID")

    else:

        print("\nINTEGRITY: INVALID")


    # --------------------------------------------------------
    # Signature verification
    # --------------------------------------------------------

    if verify_signature(
        r["hash"],
        r["signature"],
        pub
    ):

        print("SIGNATURE: VALID")

    else:

        print("SIGNATURE: INVALID")


    print("\nNOTE: Nurse does not have the Doctor's private key.")

    print("Therefore Nurse cannot decrypt the patient data.")


# ============================================================
# ADMIN VIEW
# ============================================================
#
# Admin has the least amount of patient information.
#
# Admin can see:
#
#     Record ID
#     Patient name
#     SHA-256 hash
#     Timestamp
#
# Admin can verify:
#
#     Doctor's signature
#
# Admin CANNOT:
#
#     decrypt patient information
#
# ============================================================

def admin_view(records, pub):                          # Admin views limited information

    rid = input("Enter record ID: ")

    if rid not in records:

        print("ERROR: Record not found.")

        return

    r = records[rid]

    print("\nADMIN VIEW")

    print("Record ID:", rid)

    print("Patient name:", r["name"])

    print("SHA-256:", r["hash"])

    print("Timestamp:", r["timestamp"])


    # --------------------------------------------------------
    # Signature verification
    # --------------------------------------------------------

    valid = verify_signature(
        r["hash"],
        r["signature"],
        pub
    )

    if valid:

        print("\nDIGITAL SIGNATURE: VALID")

    else:

        print("\nDIGITAL SIGNATURE: INVALID")


    print("\nAdmin cannot decrypt patient information.")


# ============================================================
# SHOW ALL RECORDS
# ============================================================

def show_records(records):                             # display available records

    if len(records) == 0:

        print("No records available.")

        return

    print("\nAVAILABLE RECORDS")

    for rid in records:

        r = records[rid]

        print(
            rid,
            "->",
            r["name"],
            "->",
            r["timestamp"]
        )


# ============================================================
# DOCTOR MENU
# ============================================================

def doctor_menu(records, pub, pri):                    # Doctor RBAC menu

    while True:

        print("\n================ DOCTOR ================")

        print("1. Add patient")

        print("2. View patient record")

        print("3. View all records")

        print("4. Logout")


        ch = input("Choice: ")


        if ch == "1":

            create_record(
                records,
                pub,
                pri
            )


        elif ch == "2":

            doctor_view(
                records,
                pub,
                pri
            )


        elif ch == "3":

            show_records(records)


        elif ch == "4":

            break


        else:

            print("ERROR: Invalid choice.")


# ============================================================
# NURSE MENU
# ============================================================

def nurse_menu(records, pub):                           # Nurse RBAC menu

    while True:

        print("\n================ NURSE ================")

        print("1. View encrypted record")

        print("2. View all records")

        print("3. Logout")


        ch = input("Choice: ")


        if ch == "1":

            nurse_view(
                records,
                pub
            )


        elif ch == "2":

            show_records(records)


        elif ch == "3":

            break


        else:

            print("ERROR: Invalid choice.")


# ============================================================
# ADMIN MENU
# ============================================================

def admin_menu(records, pub):                           # Admin RBAC menu

    while True:

        print("\n================ ADMIN ================")

        print("1. View record information")

        print("2. View all records")

        print("3. Logout")


        ch = input("Choice: ")


        if ch == "1":

            admin_view(
                records,
                pub
            )


        elif ch == "2":

            show_records(records)


        elif ch == "3":

            break


        else:

            print("ERROR: Invalid choice.")


# ============================================================
# MAIN PROGRAM
# ============================================================
#
# First generate the Doctor's RSA keys.
#
# Then create an empty record database.
#
# Then ask which role is logging in.
#
# ============================================================

print("================================================")
print("              HEALTHSECURE")
print("================================================")

print("\nGenerating Doctor RSA key pair...")

pub, pri = make_keys()                                 # Doctor public/private keys

records = {}                                           # store patient records

print("RSA keys generated successfully.")


# ============================================================
# LOGIN / ROLE SELECTION
# ============================================================

while True:

    print("\n================================================")

    print("SELECT ROLE")

    print("1. Doctor")

    print("2. Nurse")

    print("3. Admin")

    print("4. Exit")

    print("================================================")


    role = input("Choice: ")


    # --------------------------------------------------------
    # DOCTOR
    # --------------------------------------------------------

    if role == "1":

        doctor_menu(
            records,
            pub,
            pri
        )


    # --------------------------------------------------------
    # NURSE
    # --------------------------------------------------------

    elif role == "2":

        nurse_menu(
            records,
            pub
        )


    # --------------------------------------------------------
    # ADMIN
    # --------------------------------------------------------

    elif role == "3":

        admin_menu(
            records,
            pub
        )


    # --------------------------------------------------------
    # EXIT
    # --------------------------------------------------------

    elif role == "4":

        print("Exiting HealthSecure.")

        break


    else:

        print("ERROR: Invalid role.")