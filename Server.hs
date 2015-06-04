{- Alec Snyder
- mailServer server file
-}
module Main where

import Encrypt
import System.IO
import Data.Map.Strict hiding (map)
import Control.Exception
import System.Directory
import Control.Concurrent.MVar
import Control.Concurrent
import Network
import System.Random
import Crypto.Cipher.AES
import Data.Char
import Data.ByteString.Char8 hiding (putStrLn, getLine,head,break,readFile,writeFile,hPutStrLn,hGetLine,map)

data ServerDB = ServerDB { serverName :: String
                         , hname :: String
                         , privKey :: Key
                         , pubKey :: Key
                         , users :: Map String UserEntry }
    deriving (Show, Read)

data UserEntry = UserEntry { username :: String
                            ,pkey :: Key
                            ,mail :: [EncryptedEmail] }
    deriving(Show, Read)

readServer :: IO ServerDB
readServer = do
    dbStr <- readFile "server.db"
    let db = read dbStr
    evaluate db --enforce strictness

initServer :: IO ServerDB
initServer = do
    oldDB <- readServer
    let name = serverName oldDB
    priv <- readKey (name ++ ".priv")
    pub <-readKey (name ++ ".pub")
    let newDB = ServerDB name (hname oldDB) priv pub (users oldDB)
    return newDB

appendMail :: EncryptedEmail -> UserEntry -> UserEntry
appendMail m use = UserEntry (username use) (pkey use) (m : mail use)

interMenu :: MVar ServerDB -> IO ()
interMenu db = do
    putStrLn "What would you like to do?"
    putStrLn "enter 1 to add a user"
    putStrLn "enter 2 to delete a user"
    putStrLn "enter 3 to modify a user"
    putStrLn "enter 4 to quit"
    sel <- getLine
    let choice = read sel
    case choice of
        1 -> addUser db
        2 -> delUser db
        3 -> modUser db
        4 -> writeDB db
        _ -> putStrLn "Choice not recognized" >> interMenu db

addUser :: MVar ServerDB -> IO ()
addUser var = do
    putStrLn "What is the username of the new User?"
    name <- getLine
    putStrLn $ "What is the filename for the public key of user: " ++ name
    fname <- getLine
    sanity <- doesFileExist fname
    if sanity
        then do
            db <- takeMVar var
            pub <- readKey fname
            let newDB = insert name (UserEntry name pub []) (users db)
            putMVar var $ ServerDB (serverName db) (hname db) (privKey db) (pubKey db) newDB
            putStrLn "User added"
            interMenu var
        else do
            putStrLn "File name doesn't exist"
            addUser var

delUser :: MVar ServerDB -> IO ()
delUser var = do
    putStrLn "What is the username of the User?"
    name <- getLine
    putStrLn "Are you sure? (y/n) "
    sanity <- getLine
    if (sanity == "y")
        then do
            db <- takeMVar var
            let newDB = delete name (users db)
            putMVar var $ ServerDB (serverName db) (hname db) (privKey db) (pubKey db) newDB
            putStrLn "User deleted"
            interMenu var
        else interMenu var

modUser :: MVar ServerDB -> IO ()
modUser var = do
    putStrLn "What is the username of the target User?"
    name <- getLine
    putStrLn "What is the new username for the user?"
    newName <- getLine
    putStrLn $ "What is the filename for the public key of user: " ++ name
    fname <- getLine
    sanity <- doesFileExist fname
    if sanity
        then do
            pub <- readKey fname
            db <- takeMVar var
            let newDB = adjust (\_ -> UserEntry name pub []) name (users db)
            putMVar var $ ServerDB (serverName db) (hname db) (privKey db) (pubKey db) newDB
            putStrLn "user modified"
            interMenu var
        else do
            putStrLn "File name doesn't exist"
            modUser var


writeDB :: MVar ServerDB -> IO ()
writeDB var = do
    db <- readMVar var
    writeFile "server.db" (show db)
    return ()

performHandshake :: MVar ServerDB -> Handle -> IO ByteString
performHandshake var hand = do
    db <- readMVar var
    hPutStrLn hand $ show (pubKey db)
    keyIntStr <- hGetLine hand
    let keyInt = read keyIntStr
    let decKey = integerToKey $ rsadecrypt (privKey db) keyInt
    return decKey

{- TODO: ADD A WAY TO GRACEFULLY EXIT -}
sendMailClient :: MVar ServerDB -> Handle -> IO ()
sendMailClient var hand = do
    key <- performHandshake var hand
    loopSend var key hand where
        loopSend v k han = do
            use <- recvFromClient k han
            encMailMess <- recvFromClient k han
            storeMail (read encMailMess) v use
            loopSend v k han

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
                    putStrLn $ show r
                    putStrLn $ ret
                    hClose hand
                    return ()
    where
        loopRecv v k u h ke g = do
            mess <- recvFromClient k h
            putStrLn $ "[" ++ mess ++ "]"
            newG <- parseMessage mess v u h ke g
            loopRecv v k u h ke newG

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
            let target = cont
            sendPubKey cont var key hand
            return gen
        | otherwise = do
            putStrLn $ "Command not found: " ++ comm
            return gen

sendPubKey :: String -> MVar ServerDB -> ByteString -> Handle -> IO ()
sendPubKey useStr var key hand = do
    db <- readMVar var
    let use = Data.Map.Strict.lookup useStr (users db)
    case use of
        Nothing -> sendToClient "No User" key hand >> return ()
        Just u -> do
                    sendToClient "OK" key hand
                    sendToClient (show (pkey u)) key hand
                    sendToClient (show (signMessage (show (pkey u)) (privKey db))) key hand
                    return ()
            
{-TODO: failure if user not found to client -}
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
            let newMail = EncryptedEmail (biggestId + 1) (encHdr m) (encContents m) (encSig m)
            let newMap = adjust (appendMail newMail) (useName) (users db)
            let newDB = ServerDB (serverName db) (hname db) (privKey db) (pubKey db) newMap
            putMVar var newDB

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

splitCommand :: String -> (String, String)
splitCommand str = (fst split, tailSafe (snd split)) where
    split = break (== ' ') str
    tailSafe [] = []
    tailSafe (x:xs) = xs

main :: IO ()
main = withSocketsDo $ do
    db <- initServer
    serv <- newMVar db
    
    sock <- listenOn $ Service "6667"
    _ <- forkIO $ writeLoop serv
    _ <- forkIO $ acceptLoop serv sock
    
    interMenu serv

acceptLoop :: MVar ServerDB -> Socket -> IO ()
acceptLoop var sock = do
    (hand,_,_) <- accept sock
    hSetNewlineMode hand (NewlineMode CRLF CRLF)
    hSetBuffering hand LineBuffering
    _ <- forkIO (handleClient var hand) --(\_ -> hClose hand)
    acceptLoop var sock
    

handleClient :: MVar ServerDB -> Handle -> IO ()
handleClient var hand = do
    dir <- hGetLine hand
    case dir of
        "SendAuth" -> sendMailClient var hand
        "ClientAuth" -> clientAuth var hand
        _ -> return ()

writeLoop :: MVar ServerDB -> IO ()
writeLoop var = do
    threadDelay 60000000
    writeDB var
    writeLoop var
