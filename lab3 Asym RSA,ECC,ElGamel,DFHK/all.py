#                     ASYMMETRIC KEY TERMINOLOGY
#
# P  = Plaintext
# C  = Ciphertext
#
# PU = Public Key
# PR = Private Key
#
# Alice:
#   PU_A = Alice public key
#   PR_A = Alice private key
#
# Bob:
#   PU_B = Bob public key
#   PR_B = Bob private key
#
# RSA
#   Asymmetric / public-key cryptosystem
#
#   p = first prime
#   q = second prime
#   n = modulus
#   phi = Euler's totient
#   e = public exponent
#   d = private exponent
#   M/P = plaintext/message
#   C = ciphertext
#
#                         RSA KEY GENERATION
#
# STEP 1:
#
#   Choose large primes:
#
#       p
#       q
#
# STEP 2:
#
#   n = p*q
#
# STEP 3:
#
#   phi(n) = (p-1)(q-1)
#
# STEP 4:
#
# Choose e such that:
#
#   1 < e < phi(n)
#
#   gcd(e, phi(n)) = 1
#
# STEP 5:
#
# Find d:
#
#   e*d ≡ 1 (mod phi(n))
#
# Therefore:
#
#   d = modular_inverse(e, phi(n))
#
# PUBLIC KEY:
#
#   (e,n)
#
# PRIVATE KEY:
#
#   (d,n)
#
# p and q must be kept secret in actual RSA.
#

#                             RSA ENCRYPTION
#
#   C = M^e mod n
#
# Inputs:
#
#   M
#   e
#   n
#

#                             RSA DECRYPTION

#
#   M = C^d mod n
#
# Inputs:
#
#   C
#   d
#   n
#
#                        RSA IMPORTANT CONDITION

#
#   e*d ≡ 1 mod phi(n)
#
# This means: e*d = k*phi(n) + 1
#
# for some integer k.
#

#                       RSA PLAINTEXT CONDITION

#
# Plaintext should satisfy:
#
#   0 <= M < n
#
# If message is larger than n:
#   divide into blocks.
#

#                        RSA EXAM WORKFLOW

#
# Given p, q, e, M:
#
#   1. n = p*q
#   2. phi = (p-1)*(q-1)
#   3. Check gcd(e,phi) == 1
#   4. d = inverse(e,phi)
#   5. Public key = (e,n)
#   6. Private key = (d,n)
#   7. C = pow(M,e,n)
#
# If decrypting:
#
#   M = pow(C,d,n)
#
# Python pow(a,b,n) calculates:
#
#   a^b mod n
#
# efficiently.
#
#                                RABIN
#   RSA:
#       C = M^e mod n
#
#   RABIN:
#       C = M^2 mod n
#
# Rabin uses fixed exponent:
#
#   e = 2
#
#                             ELGAMAL
#
# TYPE:
#   Asymmetric public-key cryptosystem
#
# SECURITY BASIS:
#   Discrete logarithm problem
#
# MAIN VARIABLES:
#
#   p  = prime
#   e1 = primitive root / generator
#   d  = receiver private key
#   e2 = public-key component
#   r  = sender's random integer
#   P  = plaintext
#   C1,C2 = ciphertext pair
#
#                       ELGAMAL KEY GENERATION
#
# Choose:
#
#   p
#   e1
#   d
#
# Calculate:
#
#   e2 = e1^d mod p
#
# PUBLIC KEY:
#
#   (p,e1,e2)
#
# PRIVATE KEY:
#
#   d
#
#                       ELGAMAL ENCRYPTION
#
# Choose RANDOM r.
#
# Calculate:
#
#   C1 = e1^r mod p
#
#   C2 = P * (e2^r) mod p
#
# Ciphertext:
#
#   (C1,C2)
#
# IMPORTANT:
#   ElGamal ciphertext has TWO components.
#
#                       ELGAMAL DECRYPTION
#
# Formula:
#
#   P = C2 * inverse(C1^d mod p) mod p
#
# OR:
#
#   P = C2 * MI(C1^d) mod p
#
# where MI = modular inverse.
#

#                       DIFFIE-HELLMAN (DHKE)
#
#   DHKE itself is primarily a KEY EXCHANGE mechanism.
#
# It does NOT simply mean "encrypt message with public key".
#

#                     DH GLOBAL PARAMETERS
#
# Publicly known:
#
#   q     = large prime
#   alpha = primitive root modulo q
#
# These are NOT secret.
#
#                       ALICE / BOB VARIABLES

#
# Alice chooses PRIVATE:
#
#   XA
#
# Bob chooses PRIVATE:
#
#   XB
#
# Alice calculates PUBLIC:
#
#   YA = alpha^XA mod q
#
# Bob calculates PUBLIC:
#
#   YB = alpha^XB mod q
#
# They exchange YA and YB.
#
#                         DH SECRET KEY

#
# Alice calculates:
#
#   KA = YB^XA mod q
#
# Bob calculates:
#
#   KB = YA^XB mod q
#
# Both get:
#
#   KA = KB
#
# Why?
#
#   KA = (alpha^XB)^XA mod q
#      = alpha^(XB*XA) mod q
#
#   KB = (alpha^XA)^XB mod q
#      = alpha^(XA*XB) mod q
#
# Therefore:
#
#   KA = KB
#

#                     ALGORITHM IDENTIFICATION TRICK
# =============================================================================
#
# If question gives:
#
#   p, q, e, plaintext
#       -> RSA
#
# If question says:
#
#   "Rabin", p, q, plaintext/ciphertext
#       -> square + square roots + CRT
#
# If question gives:
#
#   p, e1, d, r, P
#       -> ElGamal
#
# If question gives:
#
#   q, alpha, XA, XB
#       -> DHKE
#
# If question gives:
#
#   64-bit block / 64-bit key / 16 rounds
#       -> DES
#
# If question gives:
#
#   128-bit block / AES-128/192/256
#       -> AES
#
#                         LENGTHS TO MEMORIZE
#
# DES:
#
#   Block        = 64 bits
#   Key input    = 64 bits
#   Effective key= 56 bits
#   Parity       = 8 bits
#   Rounds       = 16
#   Round key    = 48 bits
#   L/R          = 32 bits
#   Expansion    = 32 -> 48
#   S-box        = 6 -> 4
#   8 S-boxes    = 48 -> 32
#
# AES:
#
#   Block        = 128 bits
#   State        = 4x4 bytes
#   State        = 16 bytes
#   Round key    = 128 bits
#
#   AES-128:
#       key = 128
#       rounds = 10
#       words = 4 -> 44
#       round keys = 11
#
#   AES-192:
#       key = 192
#       rounds = 12
#       words = 6 -> 52
#       round keys = 13
#
#   AES-256:
#       key = 256
#       rounds = 14
#       words = 8 -> 60
#       round keys = 15
#
#
# RSA:
#   p,q -> n -> phi -> e -> d
#   C=M^e mod n
#   M=C^d mod n
#
# RABIN:
#   C=P^2 mod n
#   4 ROOTS
#   CRT
#
# ELGAMAL:
#   e2=e1^d
#   C1=e1^r
#   C2=P*e2^r
#   decrypt using inverse(C1^d)
#
# DH:
#   YA=a^XA
#   YB=a^XB
#   K=YB^XA=YA^XB
#
