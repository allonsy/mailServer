# mailServer By Alec Snyder
* an End-to-End encrypted mail server implemented in haskell
* github link: github link: https://github.com/allonsy/mailServer
* email: alsnyder@uchicago.edu or linuxbash8@gmail.com

## Build instructions:
* Clone the repository or untar the cabal sdist tar.gz file
* dependencies for the EncryptMail Library:
  * bytestring
  * cipher-aes
  * cryptohash
  * time (no cabal install needed)
  * random (no cabal install needed)
* dependencies for the Server executable:
  * bytestring, cipher-aes, cryptohash, random, time (same as library)
  * readline
  * directory
  * containers
  * network
* dependencies for the Client executable:
  * same as Server
* dependencies for the key generation executable:
  * same as the EncryptMail Library
* dependencies for the testing module:
  * a unix system with /dev/zero any unix system out there pretty much
  * random
  * hspec
  * QuickCheck

* To build, from the root of the mailServer directory, run:
  * `cabal configure --enable-tests`
  * `cabal build`


## Executing instructions
* To run the KeyGen executable, run: `dist/build/KeyGen/KeyGen`
* To run the Server executable, run: `dist/build/Server/Server`
  * You may given it an optional argument of what port to run on
  * the default is 6667
* To run the client executable, run: `dist/build/Client/Client`
  * You may give it optional arguments : the first one is the address of the mailServer and the second one is the port
  * if no arguments are given, it defaults to the defaults set up when the Client is first run
* to run the tests, run:
  * `cd test`
  * `chmod +x runTests.txt`
  * `chmod +x runTestServer.txt`
  * `./runTestServer.txt`
  * then, in a separate terminal, run: `./runTests.txt`
  * `cd ..`
  * `cabal test`

## For More information, in the doc directory, each executable has an assocated Readme which outlines more specifically what to run
