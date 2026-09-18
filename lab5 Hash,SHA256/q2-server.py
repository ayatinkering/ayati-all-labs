# ============================================================
# LAB 5 - QUESTION 2
#
# SERVER PROGRAM
#
# QUESTION:
# Use socket programming to demonstrate data integrity.
#
# Client sends data to server.
# Server calculates hash of received data.
# Server sends hash back.
# Client compares the server hash with its own hash.
#
# SAME HASH     -> DATA IS INTACT
# DIFFERENT     -> DATA WAS CHANGED/CORRUPTED
# ============================================================

import socket
import hashlib


# ------------------------------------------------------------
# HASH FUNCTION
# ------------------------------------------------------------

def get_hash(data):                                  # calculate SHA-256 hash
    return hashlib.sha256(data).hexdigest()


# ------------------------------------------------------------
# SERVER
# ------------------------------------------------------------

server = socket.socket()                             # create TCP socket

server.bind(("127.0.0.1", 5000))                     # server address and port

server.listen(1)                                     # wait for one client

print("SERVER STARTED")
print("Waiting for client...")


conn, addr = server.accept()                          # accept client connection

print("Client connected:", addr)


# Receive message from client
data = conn.recv(4096)                                # receive data

print("\nReceived data:")
print(data.decode())


# Calculate hash
h = get_hash(data)                                    # hash received data

print("\nServer hash:")
print(h)


# Send hash back
conn.send(h.encode())                                 # send hash to client


conn.close()                                          # close client connection
server.close()                                        # close server