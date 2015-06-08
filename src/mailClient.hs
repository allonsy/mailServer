{- Alec Snyder
- Encrypted mail client
-}

module Main where

import EncryptMail
import System.IO
import Data.Map.Strict hiding (map,filter)
import Control.Exception
import System.Directory
import Network
import System.Random
import Data.Time.Clock
import System.Console.Readline (readline)
import Data.ByteString.Char8 (pack,ByteString)

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
    putStrLn ""
    putStrLn $ "From: " ++ (printPerson (from m))
    putStrLn $ "To: " ++ (to m)
    putStrLn $ "CC: " ++ (show (cc m))
    putStrLn $ "BCC: " ++ (show (bcc m))
    putStrLn $ "Subj: " ++ (subj m)
    putStrLn $ "Begin Message: "
    putStrLn $ content ma
    putStrLn $ "End Message"
    putStrLn ""

printMailThreads :: [MailThread] -> IO ()
printMailThreads db = mapM_ printOneThread db >> putStrLn "" where
    printOneThread th = do
        putStrLn $ subj (hdr (snd (head th)))
        mapM_ printOneEmail th
    printOneEmail (b, m) = do
        if(b)
            then do
                putStrLn $ "\t-" ++ "***" ++ "["++ (show (idNum m)) ++ "] " ++ (show (timestamp (hdr m))) ++ " from: " ++ (show (name (from (hdr m)))) ++ " subj: " ++ (show (subj (hdr m))) ++ "***"
            else do
                putStrLn $ "\t-" ++ "["++ (show (idNum m)) ++ "] " ++ (show (timestamp (hdr m))) ++ " from: " ++ (show (name (from (hdr m)))) ++ " subj: " ++ (show (subj (hdr m)))

consoleLine :: String -> IO String
consoleLine pr = do
    res <- readline pr
    case res of
        Nothing -> error "EOF received, closing"
        Just r -> return r

initDB :: StdGen -> IO (ClientDB, StdGen)
initDB g = do
    dbExists <- doesFileExist "client.db"
    if(dbExists)
        then do
            dbStr <- readFile "client.db"
            let db = read dbStr
            let newDB = changeAes (fst (genAESKey g)) db
            return (newDB, snd (genAESKey g))
        else createNewDB g

createNewDB :: StdGen -> IO (ClientDB,StdGen)
createNewDB g = do
    putStrLn "It looks like you haven't started this client before, please enter some information to initialize the database"
    use <- consoleLine "Please enter you username (eg. alsnyder): "
    nam <- consoleLine "Please enter your full name: "
    ad <- consoleLine "Please enter you full email address: "
    let servAddr = tail $ snd $ break (=='@') ad
    port <- consoleLine $ "Please enter the port for server " ++ servAddr ++ ": "
    skeyFile <- consoleLine "Please enter the file name for the server's public key: "
    skey <- readKey skeyFile
    prkeyFile <- consoleLine "Please enter the file name for your private key: "
    prkey <- readKey prkeyFile
    pkeyFile <- consoleLine "Please enter the file name for you public key: "
    puKey <- readKey pkeyFile
    let newAES = fst (genAESKey g)
    putStrLn "Client database initialized"
    let newDB = ClientDB use (Person nam ad) 0 servAddr port skey puKey prkey newAES (fromList [(ad,puKey)]) []
    return (newDB, snd (genAESKey g))

writeDB :: ClientDB -> IO ()
writeDB db = do
    let newDB = ClientDB (username db) (thisPerson db) (biggestMail db) (serverName db) (serverPort db) (servKey db) (pubKey db) (privKey db) (pack ("Nothing here...")) (known db) (mail db) --overwrite AES key
    writeFile "clientTemp.db" (show newDB)
    renameFile "clientTemp.db" "client.db" 

writeMail :: ClientDB -> IO [(String,Mail)]
writeMail db = do
    putStrLn "Composing email"
    recpt <- consoleLine "To: "
    carbonStr <- consoleLine "CC: "
    putStrLn "pass 1"
    putStrLn $ "[" ++ carbonStr ++ "]"
    let carbon = listify $ filter (/=' ') carbonStr
    putStrLn $ "pass 2" ++ (show carbon)
    blindStr <- consoleLine "BCC: "
    let blind = listify $ filter (/=' ') blindStr
    su <- consoleLine "Subj: "
    putStrLn "Please write the contents of the message (end with a period on a line by itself"
    mess <- loopRead ""
    ti <- getCurrentTime
    let header = MailHeader recpt (thisPerson db) carbon blind su ti
    let sign = signMessage ((show header) ++ mess) (privKey db)
    let normalMail = Mail 0 header mess sign
    let normalRecpts = recpt:carbon
    let normalEmails = map (\x -> (x,changeMailBCC normalMail [])) normalRecpts
    let bccEmails = map (\x -> (x,changeMailBCC normalMail [x])) blind
    return (normalEmails ++ bccEmails) where
        loopRead s = do
            line <- consoleLine ""
            if (line == "\\.")
                then do
                    loopRead (s ++ ".\n")
                else if(line == ".")
                        then do
                            return s
                     else loopRead (s ++ line ++ "\n")
        listify str
            | str == "" = []
            | snd (break (==',') str) == "" = [fst (break (==',') str)]
            | otherwise = fst (break (==',') str) : listify (tail (snd (break (==',') str)))
        
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
    match (t:_) ma = (subj (hdr (snd ma))) == (subj (hdr (snd t)))

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
    if(top > biggestMail db)
        then do
            sendToClient ("Retr " ++ (show (biggestMail db))) shareKey hand
            mails <- recvFromClient shareKey hand
            let mailList = read mails :: [EncryptedEmail]
            (decMailMaybe,newDB) <- passMap db hand mailList []
            let decMail = map extractMaybe $ filter (/= Nothing) decMailMaybe
            putStrLn $ "importing " ++ (show (top - (biggestMail newDB))) ++ " email(s)"
            return $ changeBigNum top $ changeMail (decMail ++ (mail newDB)) newDB
        else putStrLn "No New mail" >> return db
    where
        extractMaybe (Just c) = c
        passMap d han [] accum = return (accum,d)
        passMap d han (x:xs) accum = do
            (addon,newDB) <- decryptEmailClient d hand x
            passMap newDB han xs (addon : accum)

decryptEmailClient :: ClientDB -> Handle -> EncryptedEmail -> IO ((Maybe (Bool,Mail)),ClientDB)
decryptEmailClient db hand m = do
    let decHdr = read $ decryptMessage (encHdr m) (privKey db) :: MailHeader
    let sender = from decHdr
    (newDB, ke) <- getKey (addr sender) db hand
    case ke of
        Nothing -> decMessage newDB
        Just key -> do
            let (retMail, verf) = decryptEmail m key (privKey db)
            if(verf == True)
                then return $ (Just (True, retMail),newDB) --decMessage newDB
            else do
                putStrLn "ERROR! MESSAGE VERIFICATION FAILED!"
                putStrLn "DISCARDING MESSAGE"
                return (Nothing,newDB)
    where
        decMessage newDB = return $ (Just $ (True, Mail (idEnc m) (read (decryptMessage (encHdr m) k)) ((read (decryptMessage (encContents m) k))) (encSig m)), newDB)
        k = privKey db

getKey :: String -> ClientDB -> Handle -> IO (ClientDB,Maybe Key)
getKey use db hand = do
    let possible = Data.Map.Strict.lookup use (known db)
    case possible of
        Nothing -> importKey use db hand
        Just k -> return (db, Just k)
            
    
importKey :: String -> ClientDB -> Handle -> IO (ClientDB,Maybe Key)
importKey use db hand = do
    sendToClient ("Import " ++ use) (aesKey db) hand
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
                    putStrLn $ "imported key for " ++ use
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
    putStrLn "\":re # \" -> reply to an email"
    putStrLn "\":disp\" -> display emails"
    putStrLn "\":import\" -> import a public key from disc"
    putStrLn "\":q\" -> quit"
    putStrLn "enter anything else to quit"
    putStrLn ""

showEmail :: ClientDB -> String -> IO ClientDB
showEmail db num = do
    let choice = read num
    let mailList = mail db
    getMail mailList choice where
        getMail [] _ = putStrLn "Mail number not found!" >> return db
        getMail (x:xs) n = if (idNum (snd x) == n)
                            then do
                                printMail $ snd x
                                let newMail = replaceMail x (mail db)
                                let newDB = changeMail newMail db
                                return newDB
                            else getMail xs n
        replaceMail _ [] = []
        replaceMail m ((a,b):xs)
            | (a,b) == m = ((False,b):xs)
            | otherwise = (a,b) : replaceMail m xs

sendEmailMenu :: ClientDB -> Handle -> StdGen -> IO (StdGen,ClientDB)
sendEmailMenu db hand gen = do
    toSend <- writeMail db
    sendOff toSend gen db where
        sendOff [] g d = return (g,d)
        sendOff (x:xs) g d = do
            (newG,newDB) <- sendEmail x d hand g
            sendOff xs newG newDB


sendEmail :: (String,Mail) -> ClientDB -> Handle -> StdGen -> IO (StdGen,ClientDB)
sendEmail (recp,toSend) db hand gen = do
    (newDB ,recpPerson) <- getKey recp db hand
    case recpPerson of
        Nothing -> putStrLn ("Receiver " ++ recp ++ " not found!") >> return (gen,newDB)
        Just p -> do
                    let (encSend, newGen) = encryptEmail toSend p gen
                    sendToClient ("Send" ++ " " ++ recp) (aesKey db) hand
                    sendToClient (show encSend) (aesKey db) hand
                    resp <- recvFromClient (aesKey db) hand
                    if(resp == "OK")
                        then putStrLn "Message sent!"
                        else putStrLn "Message failed to send"
                    return (newGen,newDB)

reply :: String -> ClientDB -> Handle -> StdGen -> IO (StdGen,ClientDB)
reply numStr db hand gen = do
    let num = read numStr
    if(num > biggestMail db)
    then do
        putStrLn "Number not valid"
        return (gen,db)
    else do
        let reMail = getMailbyNum (mail db) num
        putStrLn "Please write the contents of the reply (end with a period on a line by itself"
        mess <- loopRead ""
        let sender = from (hdr reMail)
        let reStr = "BEGIN REPLY:\n" ++ mess ++ "END REPLY\n"
        let newContent = reStr ++ (content reMail)
        let newHdr = MailHeader (addr (from (hdr reMail))) (thisPerson db) (cc (hdr reMail)) (bcc (hdr reMail)) (subj (hdr reMail)) (timestamp (hdr reMail))
        let signature = signMessage ((show newHdr) ++ newContent) (privKey db)
        let newMail = (addr sender,Mail (idNum reMail) newHdr newContent signature)
        sendEmail newMail db hand gen
    where
        loopRead s = do
                line <- consoleLine ""
                if (line == "\\.")
                    then do
                        loopRead (s ++ ".\n")
                    else if(line == ".")
                            then do
                                return s
                         else loopRead (s ++ line ++ "\n")
        getMailbyNum (x:[]) _= snd x
        getMailbyNum (x:xs) n
            | idNum (snd x) == n = snd x
            | otherwise = getMailbyNum xs n

parseCommand :: String -> (String, String)
parseCommand str = (fst splitCom, tailSafe (snd splitCom)) where
    splitCom = break (== ' ') str
    tailSafe [] = []
    tailSafe (_:xs) = xs

main :: IO ()
main = withSocketsDo $ do
    g <- getStdGen
    (db, newGen) <- initDB g
    writeDB db
    
    
    hand <- connectTo (serverName db) (Service (serverPort db))
    hSetNewlineMode hand (NewlineMode CRLF CRLF)
    hSetBuffering hand LineBuffering
    
    performClientHandshake db hand
    
    --updateEmail db hand
    
    runRepl db hand newGen

showAllEmails :: ClientDB -> IO ()
showAllEmails db = printMailThreads $ threads [] $ reverse $ mail db where
    threads toBuild [] = toBuild
    threads toBuild (x:xs) = threads (insertMessageThreads x toBuild) xs

importKeyFromUser :: ClientDB -> IO ClientDB
importKeyFromUser db = do
    em <- consoleLine "What is the name of the user: "
    fname <- consoleLine "What is the filename of the user's public key: "
    exist <- doesFileExist fname
    if(exist)
        then do
            let oldMap = known db
            newKey <- readKey fname
            let newMap = insert em newKey oldMap
            let newDB = changeMap newMap db
            return newDB
        else do
            putStrLn "File does not exist!"
            importKeyFromUser db

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
                    newDb <- showEmail db (snd (parseCommand (resStr)))
                    runRepl newDb hand g
        ":re" -> do 
                    (newGen,newDB) <- reply (snd (parseCommand (resStr))) db hand g
                    runRepl newDB hand newGen
        ":disp" -> do
                    showAllEmails db
                    runRepl db hand g
        ":send" -> do
                    (newG,newDB) <- sendEmailMenu db hand g
                    runRepl newDB hand newG
        ":import" -> do
                    newDB <- importKeyFromUser db
                    runRepl newDB hand g
        ":q" -> writeDB db
        _ -> do
            putStrLn "Command not found"
            runRepl db hand g
