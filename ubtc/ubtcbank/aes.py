# -*- coding: utf-8 -*-
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Hash import MD5
from base64 import b64encode, b64decode
 
 
class AES_Encrypt(object):
	'''
	Encrypt's and decrypts data using the AES algorithm.
	I ported the code to python 3 and made a handy class. Much
	thanks to http://codeghar.wordpress.com. He saved me a lot of work ;)
	Important: The plaintext data is utf-8 encoded ;)
	'''
 
	def __init__(self, password):
		# AES is a block cipher so you need to define the size of block.
		# Valid options are 16, 24, and 32 bytes
		self.BLOCK_SIZE = 32
 
		# Your input has to fit into a block of BLOCK_SIZE.
		# To make sure the last block to encrypt fits
		# in the block, you may need to pad the input.
		# This padding must later be removed after decryption so a standard padding would help.
		# Based on advice from Using Padding in Encryption,
		# the idea is to separate the padding into two concerns: interrupt and then pad
		# First you insert an interrupt character and then a padding character
		# On decryption, first you remove the padding character until
		# you reach the interrupt character
		# and then you remove the interrupt character
		self.INTERRUPT = '1'
		self.PAD = '0'
		
		# AES requires a shared key, which is used to encrypt and decrypt data
		# It MUST be of length 16, 24, or 32 chars (bytes)
		# Make sure it is as random as possible
		# (although the example below is certainly not random)
		# Based on comments from lighthill,
		# you should use os.urandom() or Crypto.Random to generate random secret key
		# I also use the GRC Ultra High Security Password Generator to generate a secret key
		
		# Please note: 2 to the power of 56 is now considered insecure in the
		# face of custom-built parallel computers and distributed key guessing efforts.
		self.SECRET_KEY = self.__get_secret_key(password)
		
		# Initialization Vector (IV) should also always be provided
		# With the same key but different IV, the same data is encrypted differently
		# IV is similar to a 'salt' used in hashing
		# It MUST be of length 16
		# Based on comments from lighthill,
		# you should NEVER use the same IV if you use MODE_OFB
		# In any case, especially if you are encrypting, say data to be store in a database,
		# you should try to use a different IV for different data sets,
		# even if you use the same secret key
		self.IV = '12345678abcdefgh'
		
		# Now you must choose a 'mode'. Options are available from Module AES.
		# Although the default is MODE_ECB, it's highly recommended not to use it.
		# For more information on different modes, read Block cipher modes of operation.
		
		self.cipher_for_encryption = AES.new(self.SECRET_KEY, AES.MODE_CBC, self.IV)
		self.cipher_for_decryption = AES.new(self.SECRET_KEY, AES.MODE_CBC, self.IV)

		# So you now have cipher objects
		# Each operation that you perform on these objects alters its state
		# So mostly you would want to perform a single operation on it each time
		# For encrypting something, create a cipher object and encrypt the data
		# For decrypting, create another cipher object and pass it the data to be decrypted
		# This is the reason I called the cipher objects
		# 'cipher_for_encryption' and 'cipher_for_decryption'

		# Since you need to pad your data before encryption,
		# create a padding function as well
		# Similarly, create a function to strip off the padding after decryption
 
	def __str__():
		return '''AES_Encrypt Object with block size=%s, interrupt=%s, pad=%s,
                   secret key=%s and iv=%s''' % (self.BLOCK_SIZE, self.INTERRUPT, self.PAD,
                                                  self.SECRET_KEY, self.IV)
   
	def __add_padding(self, data, interrupt, pad, block_size):
	 	new_data = bytes(data + interrupt)
		pad_string = bytes(pad * (block_size - (len(new_data) % block_size)))
		return new_data + pad_string
 
	# We get a byte string and should encode it first before we apply our string function rstrip()
	def __strip_padding(self, data, interrupt, pad):
		return data.decode('utf-8').rstrip(pad).rstrip(interrupt)
 
	# We create a md5 hash of the sha-256 hash of our password
	# since a md5 hash is exactly 32 bytes long,  it perfectly fits the AES keysize
	def __get_secret_key(self, password):
		sha = SHA256.new(password.encode('utf-8')).hexdigest()
		return MD5.new(sha.encode('utf-8')).hexdigest()
 
	def aes_encrypt(self, plaintext_data):
		plaintext_padded = self.__add_padding(plaintext_data,
                                              self.INTERRUPT, self.PAD, self.BLOCK_SIZE)
		encrypted = self.cipher_for_encryption.encrypt(plaintext_padded)
		return b64encode(encrypted)
   
	def aes_decrypt(self, encrypted_data):
		decoded_encrypted_data = b64decode(encrypted_data)
		decrypted_data = self.cipher_for_decryption.decrypt(decoded_encrypted_data)
		return self.__strip_padding(decrypted_data, self.INTERRUPT, self.PAD)
 
 
#a = AES_Encrypt('key')
#plaintext = 'foobar'
#enc = a.aes_encrypt(plaintext)
#print enc
#dec = (a.aes_decrypt(enc))
#if dec == plaintext:
#    print('Decripting and encrypting the plaintext:"%s" worked!' % dec)
