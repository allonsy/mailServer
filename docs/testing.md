# How to run the Testing suite
* The encrypted mail Client/Server unit tester

##Build instructions:
* Clone the repository or untar the cabal sdist tar.gz file
* dependencies for the testing module:
  * a unix system with /dev/zero any unix system out there pretty much
  * random
  * hspec
  * QuickCheck

* To build, from the root of the mailServer directory, run:
  * `cabal configure --enable-tests`
  * `cabal build`


##Executing instructions
* to run the tests, run:
  * `cd test`
  * `chmod +x runTests.txt`
  * `./runTests.txt`
  * `cd ..`
  * `cabal test`
  * If something goes wrong with the script, check any of the .err files in test/testNserver where N is any number from 1 to 4


#What's going on behind the scenes?
* The runTests executable creates a server instance and 4 clients
* it first initializes the server and each client with a basic prebuilt db file
* client 1,2, and 3 are normal clients
* client 4 is a malicious client who is trying to break in to the server
* runTests then gives each client a set of commands to run and then sends their output to txt files
* in the haskell source file: TestMail.hs, first, the encryption libraries are tested using the quickcheck and arbitrary libraries
* then, TestMail looks through the output of each client and ensures that we see the output that we should be expecting
