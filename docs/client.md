# How to run the Client Application
* The encrypted mail Client

##Build instructions:
* Clone the repository or untar the cabal sdist tar.gz file
* dependencies for the Client executable:
  * bytestring, cipher-aes, cryptohash, random, time (same as library)
  * readline
  * directory
  * containers
  * network

* To build, from the root of the mailServer directory, run:
  * `cabal configure --enable-tests`
  * `cabal build Client`


##Executing instructions
* To run the Server executable, run: `dist/build/Client/Client`
  * You may given it an optional argument of what server to connect to and a port
  * if no "client.db" is found, the client will ask you for demographic information about you
  * client.db contains defaults for the server address and port if no command line arguments are given
* after initial generation, you may navigate the interface via the TUI
* to Send emails, enter `:send`
* to update the database (retrieve any new emails from the server), enter `:upd`
* to display all emails, enter: `:disp`
  * all unread emails have "***" before and after them
  * To take a look at a specific email, look at the number in the display menu, it will look something like this : "[3]"
  * Take than number, say x and run `:show x` where x is that number
  * to reply to an email, run `:re x` where x is the number you want to reply to
  * The client will automatically download and import public keys from the server as needed
  * however, should you wish to manually import a key, run `:import` and follow the prompts to import the key
  * enter `:q` to exit


#What's going on behind the scenes?
* Look at the protocol.pdf to see how the client authenticates and communicates with the server securely
* The client keeps track of a large user struct that has demographic info about the user and a large stack of emails
* as emails come in, all emails are decrypted and their signatures verified
* the client will only tell you when signatures failed, if no errors are reported, then the message has passed verification
* if the client for some reason cannot find a public key necesary for encrypting or verification, it will tell you and you may import the key manually
* As emails come in, they are put on the stack of emails, with the newest and largest id on top
* if the client wants to update, it simply asks the server for the number of the newest email
* if that number is higher than the highest email number on the client stack, then the client knows that emails need to be imported
* the client then sends a Retr command asking for all emails with ids larger than the largest id number of the client email stack
* it then receives this list of emails and decodes each one and pushes it onto the client stack.
* when displaying all emails, it sorts the email stack into threads, according to the subject line
* it also maintains a map with known usernames to public keys which cache imported public keys
* when an unkown key is needed, it asks the server for this key and then verifies the resulting key against the known server's public key.
