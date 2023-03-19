import socket
import pickle
import Encryption
import math

# Generate server's encryption keys
encryptionKeys = Encryption.generateKeys()

# Set up UDP server
localIP = "127.0.0.1"
localPort = 20001
bufferSize = 4096
msgFromServer = "Hello UDP Server"
UDPServerSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
UDPServerSocket.bind((localIP, localPort))
print("UDP server up and listening")

# Send server's public key and get client's public key
clientKey = None
decryptedMessage = None
while clientKey is None:
    message, address = UDPServerSocket.recvfrom(bufferSize)
    message, clientPublicKey = pickle.loads(message)
    print('Message from client:', message)

    # Send server's public key to client
    message = pickle.dumps((msgFromServer, encryptionKeys[1]))
    UDPServerSocket.sendto(message, address)

    # Store client's public key
    clientKey = clientPublicKey

# Receive and decrypt messages from client
while decryptedMessage != 'exit':
    message, address = UDPServerSocket.recvfrom(bufferSize)
    cryptedMessage = int.from_bytes(message, byteorder='big')
    decryptedMessage = Encryption.decryptMessage(cryptedMessage, encryptionKeys[0])
    print('Crypted message from client:', cryptedMessage)
    print('Decrypted message from client:', decryptedMessage)
    print('Client IP Address:', address)

    # Send a reply to the client
    encryptedMessage = Encryption.encryptMessage(msgFromServer, clientKey)
    numberOfBytes = math.ceil(encryptedMessage.bit_length() / 8)
    message = encryptedMessage.to_bytes(numberOfBytes, byteorder='big')
    UDPServerSocket.sendto(message, address)
