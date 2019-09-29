#Pickledb is the local Key-Value Database used to store the Fingerprint Database
import pickledb

#Amazon Web Service SDK for python is boto3 (Provides API for S3,DynamoDB services)
import boto3


import os

#File with bloom filter implemented in
import bloomless

import math

#Hash libraries
import hashlib
import hmac

#Library used to serialize objects
import jsonpickle

import random

#File with encryption functions
import encrypt

#Hash of whole file functions
import hashes

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

#Function to read files in chunks
def read_in_chunks(file_object, chunk_size=1024):
    """Lazy function (generator) to read a file piece by piece.
    Default chunk size: 1k."""
    while True:
        data = file_object.read(4)
        if not data:
            break
        yield data



def addToDatabase(filehere, hashhere, userID,clientsocket):
	print "No entry found"
	print "----------------------------------------"
	print "Receiving metadata"
	#Recieve metadata as an array
	#aarray_jp=""	
	#data=clientsocket.recv(999999)
	#while data!="":		
		#aarray_jp+=data
		#data=clientsocket.recv(4096)

	#Get metasize
	metasize=clientsocket.recv(32)
	metasize = int(metasize, 2)
	#Recieve metadata
	aarray_jp=""
	chunksize = 1024
    	while metasize > 0:
        	if metasize < chunksize:
            		chunksize = metasize
        	aarray_jp += clientsocket.recv(chunksize)
        	metasize -= chunksize
	
	#print aarray_jp

	aarray=jsonpickle.decode(aarray_jp)
	

	db = pickledb.load('examples.db', True)

	#Store metadata in database with key as hash of file
	db.set(hashhere,aarray)

	
	#print db.get(hashhere)
	print "Recieved metadata! Storing in metadata service!"
	print "xxxxxxxxxxxxxxxxxxxxxxxxx\n\n\n"
	clientsocket.send("You're the first user to upload! You own it! Your encrypted file has been stored in the cloud!")

def PoWCheck(filehere, hashhere, userID,clientsocket):
	print "Entry found"
	print "----------------------------------------"
	
	#config setup
    	Config = ConfigParser.ConfigParser()
    	Config.read("gateway_config.ini")

	#random request number
	print "Computing random challenges"
	J=int(ConfigSectionMap("performance parameters",Config)['challengenum'])
	pos=[]	

	db = pickledb.load('examples.db', True)
	size=db.get(hashhere)['size']

	for i in range(J):
		pos.append(random.randint(0,(size-1)/int(ConfigSectionMap("performance parameters",Config)['chunk size'])))

	print "Sending to client"
	print "Challenges: "
	print pos
	print "----------------------------------------"
	#Send array of random indices to client
	pos_jp=jsonpickle.encode(pos)
	clientsocket.send(pos_jp)

	print "Recieving response"
	#Recieve response
	res_jp=clientsocket.recv(1024)
	res=jsonpickle.decode(res_jp)

	
	print "Retrieving bloomfilter from metadata service"
	bfjp=db.get(hashhere)['bloomfilter']
	bf = jsonpickle.decode(bfjp)
	
	

	print "Checking responses"
	own=1
	for i in range(J):
		print i
		print pos[i]*int(ConfigSectionMap("performance parameters",Config)['chunk size'])
		print res[i]
		#t=format(hashlib.sha256(res[i]).hexdigest())
		#e=format(hmac.new(str(pos[i]),t,hashlib.sha256).hexdigest())
		print bf.query(res[i])
		if bf.query(res[i]) is False:
			clientsocket.send( "NOT OWNER!!") 
			own=0
			break
	if own==1:
		print "Done. All challenges successful!"
		print "----------------------------------------"
		clientsocket.send("You OWN it!! Moving on to PDP!")
		
		print "Retrieving K' from metadata service"
		#Get K_dash
		K_dash_jp=db.get(hashhere)['K_dash_jp']
		K_dash=jsonpickle.decode(K_dash_jp)
		IV_jp=db.get(hashhere)['IV_jp']
		IV=jsonpickle.decode(IV_jp)

		tog=[K_dash,IV]
		tog_jp=jsonpickle.encode(tog)
		
		print "Sending K' to new uploader"
		print "----------------------------------------"
		clientsocket.send(tog_jp)

		print "Retrieving MD' from metadata service"
		#Retrieve MD' from metadata service
		MD_dash=db.get(hashhere)['MD_dash']

		print "Receiving MD' from client"
		#Recieve MD' from client
		MD_dash_2_jp=clientsocket.recv(1024)
		MD_dash_2=jsonpickle.decode(MD_dash_2_jp)
		
		print "Verifying the two"
		if MD_dash==MD_dash_2:
			print "Verified!"
			print "xxxxxxxxxxxxxxxxxxxxxxxxx"
			clientsocket.send("Successful! Your data is getting deduplicated and userID is getting added!")
			
			aarray=db.get(hashhere)
			aarray['IDs'].append(userID)
			db.set(hashhere,aarray)

		else:
			clientsocket.send("Failed! The data has been tampered with! Adding a new entry!")
			addToDatabase(filehere, hashhere, userID,clientsocket)
		
