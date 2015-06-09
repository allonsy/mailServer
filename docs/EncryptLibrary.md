# How to Compile the EncryptMail Library
* The EncryptMail Library

##Build instructions:
* Clone the repository or untar the cabal sdist tar.gz file
* dependencies for the EncryptMail Library:
  * bytestring
  * cipher-aes
  * cryptohash
  * time (no cabal install needed)
  * random (no cabal install needed)

* To build, from the root of the mailServer directory, run:
  * `cabal configure --enable-tests`
  * `cabal build`

#What's going on behind the scenes?
* This Library defines a few structs, such as Mail, EncyptedMail, and MailHeader which are used throughout the package
* it provides accessor and lens-like functions to access and modify these structs
* This library has functions that encrypts and decrypts rsa encoded Integers
* it also encodes and decode AES encryption
* It unifies RSA and AES in the data type: encrypted packet which is the basic unit of asymmetric cryptography
  * the RSA portion encrypts the AES key in Integer form
  * the AES key is used to encrypt the actual message
* There are also functions to encrypt emails
* also included: 
* functions to sign functions (take the hash and then encrypt the hash with your private key)
* functions to verify signatures
* functions to decrypt and then verify emails
* sending and receiving AES encrypted packets over the network
  * In order to do this, first, the data is encrypted, then, the length of the ciphertext is calculated and sent to the other end
  * then, the actual cipher text is sent
  * this is done because in the cipher text, the combination "\r\n" might be appear, falsely telling the other end that a command has ended
  * this way, the other end knows when the command is finished
  * for someone snooping, it is pretty trivial to calculate the length of each ciphertext so we aren't compromising security
  
