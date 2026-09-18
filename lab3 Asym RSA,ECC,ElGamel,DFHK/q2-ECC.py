from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os


def generate_ecc_keys():                              # generate ECC key pair
    private_key = ec.generate_private_key(
        ec.SECP256R1()
    )                                                 # generate private key

    public_key = private_key.public_key()             # generate public key

    return private_key, public_key


def derive_key(shared_secret):                        # derive AES key from ECDH
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"ECC-LAB"
    ).derive(shared_secret)                           # derive 256-bit AES key


def encrypt_ecc(message, public_key):                 # ECC encryption
    ephemeral_private = ec.generate_private_key(
        ec.SECP256R1()
    )                                                 # temporary private key

    ephemeral_public = ephemeral_private.public_key() # temporary public key

    shared_secret = ephemeral_private.exchange(
        ec.ECDH(),
        public_key
    )                                                 # perform ECDH

    aes_key = derive_key(shared_secret)               # derive AES key

    nonce = os.urandom(12)                            # random AES-GCM nonce

    aes = AESGCM(aes_key)                             # create AES-GCM object

    ciphertext = aes.encrypt(
        nonce,
        message,
        None
    )                                                 # encrypt message

    return (
        ephemeral_public,
        nonce,
        ciphertext
    )                                                 # return ECC ciphertext parts


def decrypt_ecc(ephemeral_public, nonce, ciphertext, private_key):
    shared_secret = private_key.exchange(
        ec.ECDH(),
        ephemeral_public
    )                                                 # recreate shared secret

    aes_key = derive_key(shared_secret)               # derive same AES key

    aes = AESGCM(aes_key)                             # create AES-GCM object

    return aes.decrypt(
        nonce,
        ciphertext,
        None
    )                                                 # decrypt message


print("ECC ENCRYPTION AND DECRYPTION")

message = input("Enter message: ")                    # plaintext message

try:

    plaintext = message.encode()                     # convert message to bytes

    private_key, public_key = generate_ecc_keys()    # generate ECC keys

    print("\nECC keys generated.")
    print("Curve: secp256r1")

    ephemeral_public, nonce, ciphertext = encrypt_ecc(
        plaintext,
        public_key
    )                                                 # encrypt message

    print("\nCiphertext HEX:")
    print(ciphertext.hex())

    print("\nNonce HEX:")
    print(nonce.hex())

    decrypted = decrypt_ecc(
        ephemeral_public,
        nonce,
        ciphertext,
        private_key
    )                                                 # decrypt message

    print("\nDecrypted:")
    print(decrypted.decode(errors="replace"))

    if decrypted == plaintext:
        print("\nVerification: SUCCESS")
    else:
        print("\nVerification: FAILED")

except Exception as e:
    print("ERROR:", e)