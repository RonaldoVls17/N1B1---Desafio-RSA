import socket
import Encryption
import math
import pickle

encryptionKeys    = Encryption.generateKeys()
requestKeys       = str.encode('Requesting server public key' )
msgFromClient     = None
bufferSize        = 4096
privateKey        = encryptionKeys[0]
publicKey         = encryptionKeys[1]
serverAddressPort = ("127.0.0.1", 20001)

# Create a UDP socket at client side
UDPClientSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)

#Getting server public key and sharing client public key
requestData                   = pickle.dumps((requestKeys, publicKey))
UDPClientSocket.sendto(requestData, serverAddressPort)
data1, server_address         = UDPClientSocket.recvfrom(bufferSize)
firstServerMessage, serverKey = pickle.loads(data1)
print(firstServerMessage)
print('')
print('server public key => ', serverKey)

#Acutally exchanging information
while (msgFromClient != 'exit'):
    msgFromClient    = input("\nDigite sua mensagem: ")
    encryptedMessage = Encryption.encryptMessage(msgFromClient, serverKey)
    numberOfBytes    = math.ceil(encryptedMessage.bit_length()/8)
    bytesToSend      = encryptedMessage.to_bytes(numberOfBytes, byteorder='big')

    # Send to server using created UDP socket
    UDPClientSocket.sendto(bytesToSend, serverAddressPort)
    cryptedMessage            = int.from_bytes(serverData, byteorder='big')
    decryptedMessage          = Encryption.decryptMessage(cryptedMessage, privateKey)
    print('')
    print('Crypted Message from server: ',cryptedMessage)
    print('')
    print('Decrypted Message from server: ',decryptedMessage)
