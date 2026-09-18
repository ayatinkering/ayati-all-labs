# ============================================================
# LAB 5 - QUESTION 2
#
# CLIENT PROGRAM
#
# The client:
# 1. Creates a message.
# 2. Calculates its own hash.
# 3. Sends the message to server.
# 4. Receives server's hash.
# 5. Compares both hashes.
#
# SAME HASH:
#       Data is intact.
#
# DIFFERENT HASH:
#       Data was changed/corrupted.
# ============================================================

import socket
import hashlib


# ------------------------------------------------------------
# HASH FUNCTION
# ------------------------------------------------------------

def get_hash(data):                                  # calculate SHA-256
    return hashlib.sha256(data).hexdigest()


# ------------------------------------------------------------
# CLIENT
# ------------------------------------------------------------

msg = input("Enter message [Hello Server]: ") or "Hello Server"

data = msg.encode()                                  # convert text to bytes

local_hash = get_hash(data)                          # calculate local hash


print("\nClient hash:")
print(local_hash)


# ------------------------------------------------------------
# CONNECT TO SERVER
# ------------------------------------------------------------

client = socket.socket()                              # create TCP socket

client.connect(("127.0.0.1", 5000))                   # connect to server


# Send message
client.send(data)                                    # send message to server


# Receive server hash
server_hash = client.recv(4096).decode()              # receive hash


print("\nServer hash:")
print(server_hash)


# ------------------------------------------------------------
# VERIFY DATA
# ------------------------------------------------------------

if local_hash == server_hash:                         # compare both hashes

    print("\nSUCCESS: Data integrity verified.")

else:

    print("\nERROR: Data was corrupted or modified.")


client.close()                                        # close connection