{- Alec Snyder
- Encrypted mail client
-}

module Main where

import Encrypt
import System.IO
import Data.Map.Strict hiding (map,filter)
import Control.Exception
import System.Directory
import Control.Concurrent.MVar
import Control.Concurrent
import Network
import System.Random
import Crypto.Cipher.AES
import Data.Time.Clock
import Data.Char
import Data.ByteString.Char8 hiding (putStrLn, putStr, getLine,head,break,readFile,writeFile,hPutStrLn,hGetLine,map,reverse,filter)

data ClientDB = ClientDB  { username :: String
                      , thisPerson :: Person
                      , biggestMail :: Integer
                      , serverName :: String
                      , serverPort :: String
                      , servKey :: Key
                      , pubKey :: Key
                      , privKey :: Key
                      , aesKey :: ByteString
                      , known :: Map String Key
                      , mail :: [(Bool,Mail)] }
    deriving(Show,Read)

type MailThread = [(Bool, Mail)]

changeMap :: Map String Key -> ClientDB -> ClientDB
changeMap newMap db= ClientDB (username db) (thisPerson db) (biggestMail db) (serverName db) (serverPort db) (servKey db) (pubKey db) (privKey db) (aesKey db) newMap (mail db)

changeMail :: [(Bool,Mail)] -> ClientDB -> ClientDB
changeMail newMail db = ClientDB (username db) (thisPerson db) (biggestMail db) (serverName db) (serverPort db) (servKey db) (pubKey db) (privKey db) (aesKey db) (known db) newMail

changeAes :: ByteString -> ClientDB -> ClientDB
changeAes newKey db = ClientDB (username db) (thisPerson db) (biggestMail db) (serverName db) (serverPort db) (servKey db) (pubKey db) (privKey db) newKey (known db) (mail db)

changeBigNum :: Integer -> ClientDB -> ClientDB
changeBigNum newInt db = ClientDB (username db) (thisPerson db) newInt (serverName db) (serverPort db) (servKey db) (pubKey db) (privKey db) (aesKey db) (known db) (mail db)


printPerson :: Person -> String
printPerson p = name (p) ++ " at " ++ addr (p)

printMail :: Mail -> IO ()
printMail ma= do
    let m = hdr ma
    putStrLn $ "From: " ++ (printPerson (from m))
    putStrLn $ "To: " ++ (to m)
    putStrLn $ "CC: " ++ (show (cc m))
    putStrLn $ "BCC: " ++ (show (bcc m))
    putStrLn $ "Subj: " ++ (subj m)
    putStrLn $ "Begin Message: "
    putStrLn $ content ma
    putStrLn $ "End Message"

printMailThreads :: [MailThread] -> IO ()
printMailThreads db = mapM_ printOneThread db >> putStrLn "" where
    printOneThread th = do
        putStrLn $ subj (hdr (snd (head th)))
        mapM_ printOneEmail th
    printOneEmail (b, m) = do
        if(b)
            then do
                putStrLn $ "\t-" ++ "***" ++ (show (idNum m)) ++ (show (timestamp (hdr m))) ++ (show (name (from (hdr m)))) ++ (show (subj (hdr m))) ++ "***"
            else do
                putStrLn $ "\t-" ++ (show (idNum m)) ++ (show (timestamp (hdr m))) ++ (show (name (from (hdr m)))) ++ (show (subj (hdr m)))

initDB :: StdGen -> IO (ClientDB, StdGen)
initDB g = do
    dbStr <- readFile "client.db"
    let db = read dbStr
    let name = username db
    servPub <- readKey "server.pub"
    pri <- readKey (name ++ ".priv")
    pu <-readKey (name ++ ".pub")
    let newDB = ClientDB name (thisPerson db) (biggestMail db) (serverName db) (serverPort db) servPub pu pri (fst (genAESKey g)) (known db) (mail db)
    return (newDB, snd (genAESKey g))

writeDB :: String -> ClientDB -> IO ()
writeDB path db = do
    let newDB = ClientDB (username db) (thisPerson db) (biggestMail db) (serverName db) (serverPort db) (servKey db) (pubKey db) (privKey db) (pack ("Nothing here...")) (known db) (mail db) --overwrite AES key
    writeFile path (show newDB) 

writeMail :: ClientDB -> IO Mail
writeMail db = do
    putStrLn "Composing email"
    putStrLn "To: "
    recpt <- getLine
    putStrLn "CC: "
    carbonStr <- getLine
    let carbon = read $ "[" ++ carbonStr ++ "]"
    putStrLn "BCC: "
    blindStr <- getLine
    let blind = read $ "[" ++ blindStr ++ "]"
    putStrLn "Subj: "
    su <- getLine
    putStrLn "Please write the contents of the message (end with a period on a line by itself"
    mess <- loopRead ""
    ti <- getCurrentTime
    let header = MailHeader recpt (thisPerson db) carbon blind su ti
    let sign = signMessage ((show header) ++ mess) (privKey db)
    return $ Mail 0 header mess sign where
        loopRead s = do
            line <- getLine
            if (line == "\\.")
                then do
                    loopRead (s ++ ".\n")
                else if(line == ".")
                        then do
                            return s
                     else loopRead (s ++ line ++ "\n")

{- insertMessage :: (Bool,Mail) -> [MailThread] -> [MailThread]
insertMessageThreads m oldDB = ClientDB (username db) (thisPerson db) (biggestMail db) (serverName db) (serverPort db) (servKey db) (pubKey db) (privKey db) (aesKey db) (known db) (m:mail db) (threads db) where
    db = insertMessageThreads m oldDB
-}

insertMessageThreads :: (Bool,Mail) -> [MailThread] -> [MailThread]
insertMessageThreads m thr =  newThreads thr where
    newThreads [] = [[m]]
    newThreads (x:xs)
        | match x m = (m:x):xs
        | otherwise = x : newThreads xs
    match (t:ts) m = (subj (hdr (snd m))) == (subj (hdr (snd t)))

performClientHandshake :: ClientDB -> Handle -> IO ()
performClientHandshake db hand = do
    hPutStrLn hand "ClientAuth"
    serverKey <- hGetLine hand
    if(serverKey == (show (servKey db)))
        then do
            let keyInt = rsaencrypt (servKey db) (keyToInteger (aesKey db))
            hPutStrLn hand (show keyInt)
            let shareKey = aesKey db
            sendToClient (username db) shareKey hand
            intStr <- recvFromClient shareKey hand
            let challenge = read intStr
            let resp = rsadecrypt (privKey db) challenge
            sendToClient (show resp) shareKey hand
            ok <- recvFromClient shareKey hand
            if(ok == "OK")
                then putStrLn "Authentication OK"
            else error "Authentication failure"
    else error "Bad server public key"

updateEmail :: ClientDB -> Handle -> IO ClientDB
updateEmail db hand= do
    let shareKey = aesKey db
    sendToClient "Upd" shareKey hand
    intStr <- recvFromClient shareKey hand
    let top = read intStr
    putStrLn $ "Received email top of " ++ (show top)
    if(top >= biggestMail db)
        then do
            sendToClient ("Retr " ++ (show (biggestMail db))) shareKey hand
            mails <- recvFromClient shareKey hand
            let mailList = read mails
            decMailMaybe <- mapM (decryptEmailClient db hand) mailList
            let decMail = map extractMaybe $ reverse $ filter (/= Nothing) decMailMaybe
            let newBigNum = idNum $ snd $ head decMail
            return $ changeBigNum newBigNum (changeMail (decMail ++ (mail db)) db)
        else return db
    where
        extractMaybe (Just c) = c
            

decryptEmailClient :: ClientDB -> Handle -> EncryptedEmail -> IO (Maybe (Bool,Mail))
decryptEmailClient db hand m = do
    let decHdr = read $ decryptMessage (encHdr m) (pubKey db) :: MailHeader
    let sender = from decHdr
    let use = break (=='@') $ addr sender
    (newDB, k) <- getKey (fst use) db hand
    case k of
        Nothing -> decMessage
        Just key -> do
            let (retMail, verf) = decryptEmail m key (privKey db)
            if(verf == True)
                then decMessage
            else do
                putStrLn "ERROR! MESSAGE VERIFICATION FAILED!"
                putStrLn "DISCARDING MESSAGE"
                return Nothing
    where
        decMessage = return $ Just $ (True, Mail (idEnc m) (read (decryptMessage (encHdr m) k)) ((read (decryptMessage (encContents m) k))) (encSig m))
        k = pubKey db

getKey :: String -> ClientDB -> Handle -> IO (ClientDB,Maybe Key)
getKey use db hand = do
    let possible = Data.Map.Strict.lookup use (known db)
    case possible of
        Nothing -> importKey use db hand
        Just k -> return (db, Just k)
            
    
importKey :: String -> ClientDB -> Handle -> IO (ClientDB,Maybe Key)
importKey use db hand = do
    sendToClient ("import " ++ use) (aesKey db) hand
    recv <- recvFromClient (aesKey db) hand
    if(recv == "OK")
        then do
            kStr <- recvFromClient (aesKey db) hand
            sig <- recvFromClient (aesKey db) hand
            let verf = verifySig kStr (read sig) (servKey db)
            if(verf == True)
                then do
                    let newMap = insert use (read kStr) (known db)
                    let newDB = changeMap newMap db
                    return (newDB, Just (read kStr))
                else do
                    putStrLn $ "Unable to find key for " ++ use ++ ". Please import that key to verify the message"
                    return (db, Nothing)
        else do
            putStrLn $ "Unable to find key for " ++ use ++". Please import that key to verify the message"
            return (db, Nothing)
        

showHelp :: IO ()
showHelp = do
    putStrLn ""
    putStrLn "\":?\" -> Show this help"
    putStrLn "\":upd\" -> refresh email list from server and display emails"
    putStrLn "\":show # \" -> Show email [email number]"
    putStrLn "\":send\" -> send an email"
    putStrLn "\":disp\" -> display emails"
    putStrLn "\":q\" -> quit"
    putStrLn "enter anything else to quit"
    putStrLn ""

showEmail :: ClientDB -> String -> IO ClientDB
showEmail db num = do
    let choice = read num
    let mailList = mail db
    getMail mailList choice where
        getMail [] n = putStrLn "Mail number not found!" >> return db
        getMail (x:xs) n = if (idNum (snd x) == n)
                            then do
                                printMail $ snd x
                                let newMail = replaceMail x (mail db)
                                let newDB = changeMail newMail db
                                return newDB
                            else getMail xs n
        replaceMail m [] = []
        replaceMail m ((a,b):xs)
            | (a,b) == m = ((False,b):xs)
            | otherwise = (a,b) : replaceMail m xs

sendEmail :: ClientDB -> Handle -> StdGen -> IO StdGen
sendEmail db hand gen = do
    toSend <- writeMail db
    let recp = to (hdr toSend)
    let recpPerson = Data.Map.Strict.lookup recp (known db)
    case recpPerson of
        Nothing -> putStrLn "Receiver not found!" >> return gen
        Just p -> do
                    let (encSend, newGen) = encryptEmail toSend p gen
                    sendToClient ("Send" ++ " " ++ recp) (aesKey db) hand
                    sendToClient (show encSend) (aesKey db) hand
                    resp <- recvFromClient (aesKey db) hand
                    if(resp == "OK")
                        then putStrLn "Message sent!"
                        else putStrLn "Message failed to send"
                    return newGen

parseCommand :: String -> (String, String)
parseCommand str = (fst split, tailSafe (snd split)) where
    split = break (== ' ') str
    tailSafe [] = []
    tailSafe (x:xs) = xs

main :: IO ()
main = withSocketsDo $ do
    g <- getStdGen
    (db, newGen) <- initDB g
    writeDB "client.db" db
    
    hand <- connectTo (serverName db) (Service (serverPort db))
    hSetNewlineMode hand (NewlineMode CRLF CRLF)
    hSetBuffering hand LineBuffering
    
    performClientHandshake db hand
    
    --updateEmail db hand
    
    runRepl db hand newGen

runRepl :: ClientDB -> Handle -> StdGen -> IO ()
runRepl db hand g = do
    putStrLn "What would you like to do?"
    putStrLn "Enter \":?\" for a list of commands"
    resStr <- getLine
    let res = parseCommand resStr
    case fst res of
        ":?" -> showHelp >> runRepl db hand g
        ":upd" -> do
                    newDB <- updateEmail db hand
                    runRepl newDB hand g
        ":show" -> do 
                    newDb <- showEmail db (snd (parseCommand (fst res)))
                    runRepl newDb hand g
        ":send" -> do
                    newG <- sendEmail db hand g
                    runRepl db hand newG
        ":q" -> return ()
        _ -> do
            putStrLn "Command not found"
            runRepl db hand g
