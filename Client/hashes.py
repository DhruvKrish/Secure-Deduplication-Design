#Required for cryptographic hashes. Used for sha-256 here.
import hashlib

def hash_64(filehere):
	# BUF_SIZE is totally arbitrary, change for requirement.
	BUF_SIZE = 65536  # lets read stuff in 64kb chunks!

	#hash object
	sha256 = hashlib.sha256()

	with open(filehere, 'rb') as f:
	    while True:
		data = f.read(BUF_SIZE)
		if not data:
		    break
		#append read data
		sha256.update(data)

	return format(sha256.hexdigest())


def hash_32(filehere):
	# BUF_SIZE is totally arbitrary, change for requirement.
	BUF_SIZE = 65536  # lets read stuff in 64kb chunks!

	#hash object
	sha256 = hashlib.sha256()

	with open(filehere, 'rb') as f:
	    while True:
		data = f.read(BUF_SIZE)
		if not data:
		    break
		#append read data
		sha256.update(data)

	return format(sha256.digest())
