# How to run the Server Application
* The encrypted mail Server

##Build instructions:
* Clone the repository or untar the cabal sdist tar.gz file
* dependencies for the Server executable:
  * bytestring, cipher-aes, cryptohash, random, time (same as library)
  * readline
  * directory
  * containers
  * network

* To build, from the root of the mailServer directory, run:
  * `cabal configure --enables-tests`
  * `cabal build Server`


##Executing instructions
* To run the Server executable, run: `dist/build/Server/Server`
  * You may given it an optional argument of what port to run on
  * the default is 6667
* when you start up the server, if no database is found ("server.db") it creates one for you
* enter the information for the server when prompted
* after initial generation, you may modify the database through the small TUI
* the database is largely a map between username strings and public keys
* you may add a user by entering a username and filename for a public key for the user
* you may delete users by entering the username for the user
* you may modify users by first entering the username for the user and then the new username (could be the same) and the filename for the new public key (could be the same)
* enter "4" to quit the server gracefully


#What's going on behind the scenes?
* Look at the protocol.pdf to see how the server authenticates and communicates with users securely
* Basically, the server has a large map that maps usernames to a list of encrypted mail structs
* the list of mail is arranged in a stack so the top element is the newest and has the highest ID
* When a user sends an email, that email is pushed onto the appropriate mail stack for the right user
* When a client requests messages, the client asks for "Retr 4" where 4 is a stand in for any number
* This means the client wants all email that has an id greater than 4. So the server pops (not really a pop since the email isn't removed) all emails until the id is <= 4
* clients can ask the server for the public key of a given user. In this case, the server retrieves the corresponding public key, signs it, and sends it to the user

