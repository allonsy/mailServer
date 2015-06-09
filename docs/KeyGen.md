# KeyGen Instructions
* in order to use any of the encryption, my libraries need a special format of key
* use the keyGen utility to generate such keys

##Build instructions:
* Clone the repository or untar the cabal sdist tar.gz file
* dependencies for the KeyGen Executable:
  * bytestring
  * cipher-aes
  * cryptohash
  * time (no cabal install needed)
  * random (no cabal install needed)
* To build, from the root of the mailServer directory, run:
  * `cabal configure --enable-tests`
  * `cabal build KeyGen`


##Executing instructions
* To run the KeyGen executable, run: `dist/build/KeyGen/KeyGen`
* Enter your name and email when prompted
* the keys are stored in $yourname.priv and $yourname.pub where $yourname is your full name (might have spaces)

#What's going on in the program?
* The program is finding very large prime numbers
* it verifies that these are primes using a succession of miller rabin tests
* it then computes the totient of the product of those two numbers
* this then becomes the modulus (n value) of the key
* then, we choose a small public exponent that is coprime to this totient, usually 65537
* Then we calculate the modular inverse of this exponent with respect to the n value
* the small exponent and n -value go into the public key and the modular inverse and n value make up the private key
