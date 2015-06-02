{- Alec Snyder
- Encrypted mail client
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
import Data.Time.Clock
import Data.Char
import Data.ByteString.Char8 hiding (putStrLn, putStr, getLine,head,break,readFile,writeFile,hPutStrLn,hGetLine,map)

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
                      , mail :: [Mail]
                      , threads :: [MailThread] }
    deriving(Show,Read)

type MailThread = [(Bool, Mail)]

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

printMailThreads :: ClientDB -> IO ()
printMailThreads db = mapM_ printOneThread (threads db) >> putStrLn "" where
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
    let newDB = ClientDB name (thisPerson db) (biggestMail db) (serverName db) (serverPort db) servPub pu pri (fst (genAESKey g)) (threads db)
    return (newDB, snd (genAESKey g))

writeDB :: String -> ClientDB -> IO ()
writeDB path db = do
    let newDB = ClientDB (username db) (thisPerson db) (biggestMail db) (serverName db) (serverPort db) (servKey db) (pubKey db) (privKey db) (pack ("Nothing here...")) (threads db) --overwrite AES key
    writeFile path (show newDB) 

writeMail :: ClientDB -> IO Mail
writeMail db = do
    putStr "To: "
    recpt <- getLine
    putStr "CC: "
    carbonStr <- getLine
    let carbon = read $ "[" ++ carbonStr ++ "]"
    putStr "BCC: "
    blindStr <- getLine
    let blind = read $ "[" ++ blindStr ++ "]"
    putStr "Subj: "
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
    
insertMessage :: Mail -> ClientDB -> ClientDB
insertMessage m db = ClientDB (username db) (thisPerson db) (biggestMail db) (serverName db) (serverPort db) (servKey db) (pubKey db) (privKey db) (aesKey db) (newThreads (threads db)) where
    newThreads [] = [[(False,m)]]
    newThreads (x:xs)
        | match x m = ((False,m):x):xs
        | otherwise = x : newThreads xs
    match (t:ts) m = (subj (hdr m)) == (subj (hdr (snd t)))

performClientHandshake :: ClientDB -> Handle -> IO ()
performClientHandshake db hand = do
    hPutStrLn hand "ClientAuth"
    serverKey <- hGetLine hand
    if(serverKey == (show (servKey db)))
        then do
            let keyInt = rsaencrypt (servKey db) (keyToInteger (aesKey db))
            hPutStrLn hand (show keyInt)
            let shareKey = aesKey db
            putStrLn $ show shareKey
            sendToClient (username db) shareKey hand
            putStrLn $ "Sending user" ++ (username db)
            intStr <- recvFromClient shareKey hand
            let challenge = read intStr
            putStrLn $ "received " ++ (show challenge)
            let resp = rsadecrypt (privKey db) challenge
            putStrLn $ "decoded " ++ (show resp)
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
    if(top >= biggestMail db)
        then do
            sendToClient ("Retr " ++ (show (biggestMail db))) shareKey hand
            mails <- recvFromClient shareKey hand
            let mail = read mails
            let decMail = map (\x -> decryptEmail 

showHelp :: IO ()
showHelp = do
    putStrLn "\":?\" -> Show this help"
    putStrLn "\":upd\" -> refresh email list from server and display emails"
    putStrLn "\":show # \" -> Show email [email number]"
    putStrLn "\":send\" -> send an email"
    putStrLn "enter anything else to quit"

showEmail :: ClientDB -> String -> IO ()
showEmail db num = do
    let choice = read num
    let mailList = mail db
    getMail mailList choice where
        getMail [] n = putStrLn "Mail number not found!"
        getMail (x:xs) n = if (idNum x == n)
                            then do
                                printMail x
                            else getMail xs n

sendEmail :: ClientDB -> Handle -> StdGen -> IO StdGen
sendEmail db hand gen = do
    toSend <- writeMail db
    let recp = to (hdr toSend)
    let recpPerson = lookup recp (known db)
    case recpPerson of
        Nothing -> putStrLn "Receiver not found!"
        Just p -> do
                    let (encSend, newGen) = encryptEmail toSend p gen
                    sendToClient "Send" (aesKey db) hand
                    sendToClient (show encSend) (aesKey db) hand
                    return newGen
    

main :: IO ()
main = withSocketsDo $ do
    g <- getStdGen
    (db, newGen) <- initDB g
    writeDB "client.db" db
    
    hand <- connectTo (serverName db) (Service (serverPort db))
    hSetNewlineMode hand (NewlineMode CRLF CRLF)
    hSetBuffering hand LineBuffering
    
    performClientHandshake db hand
    
    updateEmail db hand
    
    runRepl db hand newGen

runRepl :: ClientDB -> Handle -> StdGen -> IO ()
runRepl db hand g = do
    putStrLn "What would you like to do?"
    putStrLn "Enter \":?\" for a list of commands"
    parseCommand res <- getLine
    case fst res of
        ":?" -> showHelp >> runRepl db hand g
        ":upd" -> do
                    newDB <- updateEmail db hand g
                    runRepl newDB hand
        ":show" -> showEmail db (snd (parseCommand res)) >> runRepl db hand g
        ":send" -> do
                    newG <- sendEmail db hand
                    runRepl db hand newG
        _ -> return ()
