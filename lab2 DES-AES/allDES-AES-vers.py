#
# DES:
#   Block size        = 64 bits
#   Input             = 64 bits
#   Given cipher key  = 64 bits
#   Effective key     = 56 bits
#   Parity bits       = 8 bits
#   Number of rounds  = 16
#   Round key         = 48 bits
#   L and R           = 32 bits each
#
# AES:
#   Block size        = 128 bits
#   State             = 4 x 4 bytes = 16 bytes = 128 bits
#
#   AES-128:
#       Key size     = 128 bits
#       Rounds       = 10
#       Words in key = 4
#       Expanded key = 44 words
#       Round keys   = 11
#
#   AES-192:
#       Key size     = 192 bits
#       Rounds       = 12
#       Words in key = 6
#       Expanded key = 52 words
#       Round keys   = 13
#
#   AES-256:
#       Key size     = 256 bits
#       Rounds       = 14
#       Words in key = 8
#       Expanded key = 60 words
#       Round keys   = 15
#
#       AES round key is ALWAYS 128 bits.
#       Number of round keys = Nr + 1
#
# byte = 8 bits
# word = 4 bytes
# DES block = 8 bytes
# AES block = 16 bytes
#
#   1 hex digit = 4 bits
#   2 hex digits = 1 byte
#   4 hex digits = 16 bits
#   8 hex digits = 32 bits
#
#   x XOR 0 = x
#   x XOR x = 0
#
# DES uses XOR heavily.
# AES AddRoundKey is effectively XOR.
#
# gcd(a,b): greatest common divisor of a and b.
#
# CONFIDENTIALITY:
#   Encrypt using RECEIVER'S PUBLIC KEY.
#   Decrypt using RECEIVER'S PRIVATE KEY.
#
# AUTHENTICATION / SIGNATURE:
#   Sign using SENDER'S PRIVATE KEY.
#   Verify using SENDER'S PUBLIC KEY.
#
#                       ONE-WAY FUNCTION
#
# Easy to calculate:
#
#   y = f(x)
#
# Difficult to reverse:
#
#   x = f^(-1)(y)
#
# TRAPDOOR ONE-WAY FUNCTION:
#
#   Easy to reverse if secret trapdoor information is known.
#
# RSA:
#   based on modular exponentiation / factorization-related hardness
#
# ElGamal / DH:
#   based on discrete logarithm problem
#
#   Version     Key       Rounds Nr     Initial words     Expanded words
#
#   AES-128     128       10         4                 44
#   AES-192     192       12         6                 52
#   AES-256     256       14         8                 60
#
# Round key:
#   ALWAYS 128 bits = 16 bytes = 4 words
#
# Number of round keys:
#
#   Nr + 1
#
#
# Five modes
# ECB:
#   independent blocks
#
# CBC:
#   previous C -> XOR P -> encrypt
#
# CFB:
#   previous C -> encrypt -> XOR P
#
# OFB:
#   previous OUTPUT -> encrypt -> XOR P
#
# CTR:
#   counter -> encrypt -> XOR P
#
s="hi"
b=b"hi"
n=10

s.encode()	        #normal text → bytes
bytes.fromhex(s)	#HEX string → bytes
b.hex()	            #bytes → HEX string
int(s, 16)	        #HEX number → decimal
hex(n)	            #decimal → HEX

'''
AES	Key size	HEX characters
AES-128	16 bytes	32
AES-192	24 bytes	48
AES-256	32 bytes	64
'''