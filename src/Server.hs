{- Alec Snyder
- mailServer Server
- github: https://github.com/allonsy/mailServer
-}
module Main where

import Control.Concurrent.MVar
import Control.Concurrent
import Control.Exception
import Data.ByteString.Char8 (ByteString)
import Data.Map.Strict hiding (map)
import EncryptMail
import Network
import System.Console.Readline (readline)
import System.Directory
import System.Environment
import System.IO
import System.Random


data ServerDB = ServerDB { serverName :: String
                         , hname :: String --full location: skynet.linuxd.org, 121.134.43.122, etc...
                         , privKey :: Key --private key of server
                         , pubKey :: Key --public key of user
                         , users :: Map String UserEntry --map with usernames as keys and userEntries as values
                         } 
    deriving (Show, Read)

data UserEntry = UserEntry { username :: String --username of this user
                            ,pkey :: Key --public key of this user
                            ,mail :: [EncryptedEmail] --list of all mail this user has received
                            }
    deriving(Show, Read)

--read in server database file and return it
initServer :: IO ServerDB
initServer = do
    dbExists <- doesFileExist "server.db"
    if(dbExists)
        then do
            dbStr <- readFile "server.db"
            let db = read dbStr
            return db
        else createNewDB

--if no database exists, ask user for primary info and return resulting db
createNewDB :: IO ServerDB
createNewDB = do
    putStrLn "It looks like you haven't started this server before, please enter some information to initialize the database"
    nam <- consoleLine "Please enter the server name (eg. skynet): "
    hn <- consoleLine "Please enter the address of the server (eg. skynet.uchicago.edu): "
    prkeyFile <- consoleLine "Please enter the filename for the private key of the server: "
    prkey <- readKey prkeyFile
    pukeyFile <- consoleLine "Please enter the filename for the public key of the server: "
    pukey <- readKey pukeyFile
    putStrLn "Client database initialized"
    let newDB = ServerDB nam hn prkey pukey empty
    return newDB

--read from the console, cast away the Maybe wrapper
consoleLine :: String -> IO String
consoleLine pr = do
    res <- readline pr
    case res of
        Nothing -> error "EOF received, closing"
        Just r -> return r

--appends a given mail message onto the list of mail for this user
--returns the new UserEntry
appendMail :: EncryptedEmail -> UserEntry -> UserEntry
appendMail m use = UserEntry (username use) (pkey use) (m : mail use)

--interactive menu to modify user db
interMenu :: MVar ServerDB -> IO ()
interMenu db = do
    putStrLn "What would you like to do?"
    putStrLn "enter 1 to add a user"
    putStrLn "enter 2 to delete a user"
    putStrLn "enter 3 to modify a user"
    putStrLn "enter 4 to quit"
    endInput <- isEOF
    if(endInput)
        then writeDB db
        else do
            sel <- getLine
            let choice = read sel
            case choice of
                1 -> addUser db
                2 -> delUser db
                3 -> modUser db
                4 -> writeDB db
                _ -> putStrLn "Choice not recognized" >> interMenu db

--add a user
addUser :: MVar ServerDB -> IO ()
addUser var = do
    putStrLn "What is the username of the new User?"
    nameUser <- getLine
    putStrLn $ "What is the filename for the public key of user: " ++ nameUser
    fname <- getLine
    sanity <- doesFileExist fname
    if sanity
        then do
            db <- takeMVar var
            pub <- readKey fname
            let newDB = insert nameUser (UserEntry nameUser pub []) (users db)
            putMVar var $ ServerDB (serverName db) 
                                   (hname db) 
                                   (privKey db) 
                                   (pubKey db) 
                                   newDB
            putStrLn "User added"
            interMenu var
        else do
            putStrLn "File name doesn't exist"
            addUser var

--delete a user
delUser :: MVar ServerDB -> IO ()
delUser var = do
    putStrLn "What is the username of the User?"
    newName <- getLine
    putStrLn "Are you sure? (y/n) "
    sanity <- getLine
    if (sanity == "y")
        then do
            db <- takeMVar var
            let newDB = delete newName (users db)
            putMVar var $ ServerDB (serverName db) 
                                   (hname db) 
                                   (privKey db) 
                                   (pubKey db) 
                                   newDB
            putStrLn "User deleted"
            interMenu var
        else interMenu var

--modify a users username or public key
modUser :: MVar ServerDB -> IO ()
modUser var = do
    putStrLn "What is the username of the target User?"
    oldName <- getLine
    putStrLn "What is the new username for the user?"
    newName <- getLine
    putStrLn $ "What is the filename for the public key of user: " ++ oldName
    fname <- getLine
    sanity <- doesFileExist fname
    if sanity
        then do
            pub <- readKey fname
            db <- takeMVar var
            let newDB = adjust (\_ -> UserEntry newName pub []) oldName (users db)
            putMVar var $ ServerDB (serverName db) (hname db) (privKey db) (pubKey db) newDB
            putStrLn "user modified"
            interMenu var
        else do
            putStrLn "File name doesn't exist"
            modUser var

--write the given db to the file "server.db"
writeDB :: MVar ServerDB -> IO ()
writeDB var = do
    db <- readMVar var
    writeFile "server2.db" (show db)
    renameFile "server2.db" "server.db"
    return ()

--performs SSL like handshake, no client authentication yet
--sends server public key
--then receives the shared AES key that the client generates
performHandshake :: MVar ServerDB -> Handle -> IO ByteString
performHandshake var hand = do
    db <- readMVar var
    hPutStrLn hand $ show (pubKey db)
    keyIntStr <- hGetLine hand
    let keyInt = read keyIntStr
    let decKey = integerToKey $ rsadecrypt (privKey db) keyInt
    return decKey

--performs SSL-like handshake and autheticates client
--after SSL handshake occurs, it sends the user a random nonce
--encrypted with the users public key
--the user decrypts with his private key and returns the correct random number
--if successful, the client is authenticated and is allowed to exectute db queries

clientAuth :: MVar ServerDB -> Handle -> IO ()
clientAuth var hand = do
    key <- performHandshake var hand
    useStr <- recvFromClient key hand
    db <- readMVar var
    let use = Data.Map.Strict.lookup useStr (users db)
    case use of
        Nothing -> return ()
        Just user -> do
            g <- getStdGen
            let (r,newGen) = randomR(1,115792089237316195423570985008687907853269984665640564039457584007913129639936) g :: (Integer, StdGen)
            let sending = rsaencrypt (pkey user) r
            sendToClient (show sending) key hand
            ret <- recvFromClient key hand
            if ((read ret) == r)
                then do
                    sendToClient "OK" key hand
                    loopRecv var key user hand key newGen
                else do
                    putStrLn "auth failure"
                    sendToClient "auth failure" key hand
                    hClose hand
                    return ()
    where
        loopRecv v k u h ke g = do
            mess <- recvFromClient k h
            newG <- parseMessage mess v u h ke g
            loopRecv v k u h ke newG

--parses the command into the first part and the rest and calls functions
--based on what it parses
parseMessage :: String -> MVar ServerDB -> UserEntry -> Handle -> ByteString -> StdGen -> IO StdGen
parseMessage mess var use hand key gen = runner where
    comm = fst $ splitCommand mess
    cont = snd $ splitCommand mess
    runner
        | comm == "Send" = do
            em <- recvFromClient key hand
            storeMail (read (em)) var (cont)
            sendToClient "OK" key hand
            return gen
        | comm == "Upd" = do
            db <- readMVar var
            num <- getBiggestId db use
            sendToClient (show num) key hand
            return gen
        | comm == "Retr" = do
            let num = read cont
            mailList <- getMail var use num
            sendToClient (show mailList) key hand
            return gen
        | comm == "Import" = do
            sendPubKey cont var key hand
            return gen
        | otherwise = do
            putStrLn $ "Command not found: " ++ comm
            return gen

--given a username, it send the public key for that user signed by the
--server's key pair
sendPubKey :: String -> MVar ServerDB -> ByteString -> Handle -> IO ()
sendPubKey useStr var key hand = do
    db <- readMVar var
    let use = Data.Map.Strict.lookup (fst (break (=='@') useStr)) (users db)
    case use of
        Nothing -> sendToClient "No User" key hand >> return ()
        Just u -> do
                    sendToClient "OK" key hand
                    sendToClient (show (pkey u)) key hand
                    sendToClient (show (signMessage (show (pkey u)) (privKey db))) key hand
                    return ()
            
--Given an encrypted email from a client and a target user for this email
--it stores this email in the correct mailbox and updates the db
storeMail :: EncryptedEmail -> MVar ServerDB -> String -> IO ()
storeMail m var use = do
    putStrLn "receiving message"
    db <- takeMVar var
    let useName = fst $ break (=='@') use
    case (Data.Map.Strict.lookup (useName) (users db)) of
        Nothing -> do
            putStrLn $ "User: " ++ use ++ " not found"
            putMVar var db >> return ()
        Just upUse -> do
            biggestId <- getBiggestId db upUse
            let newMail = EncryptedEmail (biggestId + 1) 
                                         (encHdr m) 
                                         (encContents m) 
                                         (encSig m)
            
            let newMap = adjust (appendMail newMail) 
                                (useName) 
                                (users db)
            
            let newDB = ServerDB (serverName db) 
                                 (hname db) 
                                 (privKey db) 
                                 (pubKey db) 
                                 newMap
            putMVar var newDB

--gets the id of the newest email for a given user
--since the emails are stored in a stack
--this is the id top of the stack
getBiggestId :: ServerDB -> UserEntry -> IO Integer
getBiggestId db use = do
    case (Data.Map.Strict.lookup (username use) (users db)) of
        Nothing -> return 0
        Just upUse -> do
            if(mail upUse == [])
                then return 0
            else do
                let biggestId = idEnc (head (mail upUse))
                return biggestId

--given an integer, it returns the list of email for all emails of a given
--user that have id greater than the given integer
getMail :: MVar ServerDB -> UserEntry -> Integer -> IO [EncryptedEmail]
getMail var use clientNum = do
    db <- readMVar var
    case (Data.Map.Strict.lookup (username use) (users db)) of
        Nothing -> return []
        Just upUse -> do
            let userMail = mail upUse
            return $ retMail [] userMail where
                retMail ls [] = ls
                retMail ls (x:xs)
                    | idEnc x > clientNum = retMail (x:ls) xs
                    | otherwise = ls
--splits a string based on space 
-- eg: "hello world" -> ("hello","word")
--it discards the splitting space
splitCommand :: String -> (String, String)
splitCommand str = (fst splitCom, tailSafe (snd splitCom)) where
    splitCom = break (== ' ') str
    tailSafe [] = []
    tailSafe (_:xs) = xs

--runner
main :: IO ()
main = withSocketsDo $ do
    arg <- getArgs
    db <- initServer
    serv <- newMVar db
    
    if(length arg == 1)
        then do
            sock <- listenOn $ Service (arg !! 0)
            _ <- forkIO $ writeLoop serv
            _ <- forkIO $ acceptLoop serv sock
            interMenu serv --start the interactive menu
        else do
            sock <- listenOn $ Service "6667"
            _ <- forkIO $ writeLoop serv
            _ <- forkIO $ acceptLoop serv sock
            interMenu serv --start the interactive menu
    

--accepts connections, formats the handle, and forks it off to the client handler
acceptLoop :: MVar ServerDB -> Socket -> IO ()
acceptLoop var sock = do
    (hand,_,_) <- accept sock
    hSetNewlineMode hand (NewlineMode CRLF CRLF)
    hSetBuffering hand LineBuffering
    _ <- forkFinally (handleClient var hand) (\_ -> hClose hand)
    acceptLoop var sock
    
--passes off the client to clientAuth for authentication and command parsing
handleClient :: MVar ServerDB -> Handle -> IO ()
handleClient var hand = do
    dir <- hGetLine hand
    case dir of
        "ClientAuth" -> clientAuth var hand
        _ -> return ()

--writes db to file every minute
writeLoop :: MVar ServerDB -> IO ()
writeLoop var = do
    threadDelay 60000000
    writeDB var
    writeLoop var
