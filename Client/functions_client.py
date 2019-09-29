#Pickledb is the local Key-Value Database used to store the Fingerprint Database
import pickledb

#Amazon Web Service SDK for python is boto3 (Provides API for S3,DynamoDB services)
import boto3

#For urandom
import os
#Key store retrieve
import pickledb

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



#Function to read files in chunks
def read_in_chunks(file_object, chunk_size=1024):
    """Lazy function (generator) to read a file piece by piece.
    Default chunk size from config file"""
    #config setup
    Config = ConfigParser.ConfigParser()
    Config.read("client_config.ini")
    
    while True:
        data = file_object.read(chunk_size)
        if not data:
            break
        yield data


def compute_store(filehere, hashhere, userID,s):

	print "No copy of file in cloud! Adding as first copy!"
	print "----------------------------------------"		

	#default key (will need to randomize it)
	key = os.urandom(16)
	key=key.encode('hex')

	#Load the keystore. True=> writable.
	keystore = pickledb.load('keystore.db', True)

	value={'hash':hashhere,'key':key}

	#Store pair in keystore
	keystore.set(filehere,value)
		
	#encrypts file and saves it in a file called filehere + ".enc"=y
	iv=encrypt.encrypt_file_return_iv(filehere, key)

		

	#MD'=H(y)
	MD_dash=hashes.hash_64(filehere+".enc")
	#print MD_dash
	
	statinfo=os.stat(filehere)
	filesize=statinfo.st_size

	#config setup
	Config = ConfigParser.ConfigParser()
	Config.read("client_config.ini")

	chunknum=int(filesize/int(ConfigSectionMap("performance parameters",Config)['chunk size']))

	bloomsize=int(math.ceil(-(chunknum*math.log1p(float(ConfigSectionMap("performance parameters",Config)['fpr'])-1))/(math.log1p(1)*math.log1p(1))))

	print bloomsize
	#INITIALIZE BLOOM FILTER
	#bloom_size=math.ceil(statinfo.st_size/1024)
	bf = bloomless.BloomFilter(bloomsize,int(math.ceil((bloomsize*math.log1p(1))/chunknum)))
		

	f = open(filehere+".enc")
	i=0
	for piece in read_in_chunks(f,int(ConfigSectionMap("performance parameters",Config)['chunk size'])):
	    	t=format(hashlib.sha256(piece).hexdigest())
		e=format(hmac.new(str(i),t,hashlib.sha256).hexdigest())
		bf.add(e)
		i=i+1;

	#Compute hash_thirtytwo
	hash_thirtytwo=hashes.hash_32(filehere)

	#compute k'=E(k) using hash2
	K_dash=encrypt.encrypt(key,hash_thirtytwo)

	bfjp = jsonpickle.encode(bf)
	K_dash_jp= jsonpickle.encode(K_dash)
	iv_jp=jsonpickle.encode(iv)

		
		
	users=[userID]

	aarray={'bloomfilter':bfjp,'IDs':users,'size':filesize,'MD_dash':MD_dash,'K_dash_jp':K_dash_jp,'IV_jp':iv_jp}		

	aarray_jp=jsonpickle.encode(aarray)
	#print aarray_jp
		
	metasize=len(aarray_jp)
	#Send metasize
	metasize = bin(metasize)[2:].zfill(32)
	s.send(metasize)	

	print "Sending metadata"
	s.send(aarray_jp)

	#config setup
	Config = ConfigParser.ConfigParser()
	Config.read("client_config.ini")

	#AWS variables
	BUCKET = ConfigSectionMap("AWS",Config)['bucket']
	s3 = boto3.client(
		    's3',
		    aws_access_key_id=ConfigSectionMap("AWS",Config)['access key'],
		    aws_secret_access_key=ConfigSectionMap("AWS",Config)['secret access key']
		)
	
	#Store file recieved in cloud
	data = open(filehere+".enc", 'rb')
	print("Uploading encrypted file as S3 object")
	s3.put_object(Bucket=BUCKET,
		Key=hashhere,
		Body=data,
		SSECustomerKey=key,
        SSECustomerAlgorithm='AES256')
	print("Done")
	print "----------------------------------------"


def verify_dedup(filehere,hashhere,s):
	
	#config setup
	Config = ConfigParser.ConfigParser()
	Config.read("client_config.ini")

	print "Copy present in cloud! Verifying ownership!"
	print "----------------------------------------"
	print "Recieving challenges"
	pos_jp=s.recv(1024)
	pos=jsonpickle.decode(pos_jp)

	print "Computing response"
	res=[]
	f = open(filehere+".enc", 'rb')
	J=int(ConfigSectionMap("performance parameters",Config)['challengenum'])
	#read file positions and make res[]
	for i in range(J):
		f.seek(pos[i]*int(ConfigSectionMap("performance parameters",Config)['chunk size']),0)
		block=f.read(int(ConfigSectionMap("performance parameters",Config)['chunk size']))
		t=format(hashlib.sha256(block).hexdigest())
		e=format(hmac.new(str(pos[i]),t,hashlib.sha256).hexdigest())
		res.append(e)
		
	print "Sending response: "
	print res
	print "----------------------------------------"
	res_jp=jsonpickle.encode(res)
	s.send(res_jp)

	proceed=s.recv(1024)
	if proceed=="You OWN it!! Moving on to PDP!":
		tog_jp=s.recv(1024)
		tog=jsonpickle.decode(tog_jp)
		print "Recieving K'"
		#Procure K'
		K_dash=tog[0]
		IV=tog[1]
			
		print "Computing MD'"
		#Get 32 bit hash of file
		hash_thirtytwo=hashes.hash_32(filehere)
			
		#Decode K' -> K
		K=encrypt.decrypt(K_dash,hash_thirtytwo)

		#Encrypt file
		encrypt.encrypt_file_use_iv(filehere, K, IV)

		#MD'=H(y)
		MD_dash_2=hashes.hash_64(filehere+".enc")
			
		print "Sending MD' to gateway for verification"
		MD_dash_2_jp=jsonpickle.encode(MD_dash_2)
		#Send to client for verification
		s.send(MD_dash_2_jp)
	
		value={'hash':hashhere,'key':K}
		keystore = pickledb.load('keystore.db', True)

		keystore.set(filehere,value)
		


