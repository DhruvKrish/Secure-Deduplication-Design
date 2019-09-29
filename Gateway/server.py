# server.py 
import socket                                         
import time
import fcntl, os

#Pickledb is the local Key-Value Database used to store the Fingerprint Database
import pickledb

#import hashes
#import encrypt

import jsonpickle

# create a socket object
serversocket = socket.socket(
	        socket.AF_INET, socket.SOCK_STREAM) 

# get local machine name
host = socket.gethostname()                           

port = 12345                                        

# bind to the port
serversocket.bind((host, port))                                  

#fcntl.fcntl(serversocket, fcntl.F_SETFL, os.O_NONBLOCK)
# queue up to 5 requests
serversocket.listen(5)                                           

while True:
	# establish a connection
	clientsocket,addr = serversocket.accept()      

	print("Got a connection from %s" % str(addr))
	print "----------------------------------------"
	currentTime = time.ctime(time.time()) + "\r\n"
	clientsocket.send(currentTime.encode('ascii'))

	purpose=clientsocket.recv(1)

	if purpose=="s":
		details_jp=clientsocket.recv(1024)
		details=jsonpickle.decode(details_jp)	
		#print details[0]
		#print details[1]
		filehere=details[1]
		userID=details[0]
		hashhere=details[2]

		print "Hash of file received and checking in metadata service for entry"	

		#Load the database. True=> database writable.
		db = pickledb.load('examples.db', True)
		#print db

	

		#Checking whether a hash of file (key in database) already present
		check=db.get(hashhere)
	
		#imported from functions.py. Check that file for further details.
		from functions_final import addToDatabase,PoWCheck

		if check is None:
			clientsocket.send("compute") 
			addToDatabase(filehere, hashhere, userID,clientsocket)
		else: 	
			clientsocket.send("respond") 
			PoWCheck(filehere, hashhere, userID,clientsocket)

	elif purpose=="r":
		
		hashhere=clientsocket.recv(64)
		userID=clientsocket.recv(100)
		#print userID

		#Load the database. True=> database writable.
		db = pickledb.load('examples.db', True)

		#Checking whether a hash of file (key in database) already present
		check=db.get(hashhere)['IDs']
		#print check

		approval=0
		for current in check:
			if current==userID:
				approval=1
			
		clientsocket.send(str(approval))

	clientsocket.close()
