# client.py  
import socket
import fcntl, os

import jsonpickle

import hashes

#File with client functions
import functions_client

#Amazon Web Service SDK for python is boto3 (Provides API for S3,DynamoDB services)
import boto3



import encrypt

#key store retrieve
import pickledb

#For config file
import ConfigParser

#ConfigParser helper function
def ConfigSectionMap(section,Config):
    dict1 = {}
    options = Config.options(section)
    for option in options:
        try:
            dict1[option] = Config.get(section, option)
            if dict1[option] == -1:
                DebugPrint("skip: %s" % option)
        except:
            print("exception on %s!" % option)
            dict1[option] = None
    return dict1


# create a socket object
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 

# get local machine name
#host = socket.gethostname()                           

port = 12345

#config setup
Config = ConfigParser.ConfigParser()
Config.read("client_config.ini")

# connection to docker ip on the port.
s.connect((ConfigSectionMap("Docker",Config)['docker ip'], port))    
#s.connect((host, port))                            
#fcntl.fcntl(s, fcntl.F_SETFL, os.O_NONBLOCK)

# Receive no more than 1024 bytes
tm = s.recv(200)

purpose=raw_input("Store or read file?:(s/r) ")
s.send(purpose)

userID=raw_input("Enter your UserID: ")

if purpose=="s":
	
	
	#Assuming file is present
	filehere=raw_input("Enter name of file: ")

	#Hashing file
	#Get 64 byte hash
	hashhere=hashes.hash_64(filehere)
	
	print "Sending hash of file to Gateway"
	#serialize these
	details=[userID,filehere,hashhere]	
	details_jp=jsonpickle.encode(details)

	s.send(details_jp)
	todo=s.recv(7)	

	if todo=="compute":
	
		functions_client.compute_store(filehere,hashhere, userID, s)
	
	else:
		functions_client.verify_dedup(filehere,hashhere,s)

	verdict=s.recv(1024)
	print verdict
	
	
elif purpose=="r":
	
	filehere=raw_input("Enter name of file to read: ")

	#Get hashere and key
	keystore = pickledb.load('keystore.db', True)

	hashhere=keystore.get(filehere)['hash']
	key=keystore.get(filehere)['key']
	
	#Send hash and userID to gateway
	s.send(hashhere)
	s.send(userID)

	approval=s.recv(1)

	if approval=='0':
		print "You don't own the data!"
	
	else:
		print "Reading data"

		#Config!
		BUCKET=ConfigSectionMap("AWS",Config)['bucket']

		s3 = boto3.client(
		    's3',
		    aws_access_key_id=ConfigSectionMap("AWS",Config)['access key'],
		    aws_secret_access_key=ConfigSectionMap("AWS",Config)['secret access key']
		)
		# Getting the object:
		print("Getting S3 object and writing to file Recievedd...")
		# Note how we're using the same ``KEY`` we
		# created earlier.
		response = s3.get_object(Bucket=BUCKET,
				         Key=hashhere,
				         SSECustomerKey=key,
				         SSECustomerAlgorithm='AES256')
		print("Done")
		f=open('Recievedd.enc','w')
		f.write(response['Body'].read())
		f.close()
		encrypt.decrypt_file('Recievedd.enc',key)
									

# Close the socket when done
s.close                     
print("The time that the server responded is %s" % tm.decode('ascii'))
