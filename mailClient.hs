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
                      , serverName :: String
                      , serverPort :: String
                      , servKey :: Key
                      , pubKey :: Key
                      , privKey :: Key
                      , aesKey :: ByteString
                      , threads :: [MailThread] }
    deriving(Show,Read)

type MailThread = [(Bool, Mail)]

printPerson :: Person -> String
printPerson p = name (p) ++ "at " ++ addr (p)

printMail :: Mail -> IO ()
printMail ma= do
    let m = hdr ma
    putStrLn $ "From: " ++ (printPerson (from m))
    putStrLn $ "To: " ++ (to m)
    putStr $ "CC: "
    mapM_ (\x -> putStr ((printPerson x)++ ", ")) (cc m)
    putStrLn ""
    putStrLn $ "BCC: " ++ (printPerson (bcc m))
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
                putStrLn $ "\t-" ++ map toUpper ((show (timestamp (hdr m))) ++ (show (name (from (hdr m)))) ++ (show (subj (hdr m))))
            else do
                putStrLn $ "\t-" ++ (show (timestamp (hdr m))) ++ (show (name (from (hdr m)))) ++ (show (subj (hdr m)))

initDB :: StdGen -> IO (ClientDB, StdGen)
initDB g = do
    dbStr <- readFile "client.db"
    let db = read dbStr
    let name = username db
    servPub <- readKey "server.pub"
    pri <- readKey (name ++ ".priv")
    pu <-readKey (name ++ ".pub")
    let newDB = ClientDB name (serverName db) (serverPort db) servPub pu pri (fst (genAESKey g)) (threads db)
    return (newDB, snd (genAESKey g))

writeDB :: String -> ClientDB -> IO ()
writeDB path db = writeFile path (show db) 

main :: IO ()
main = do
    g <- getStdGen
    (db, newGen) <- initDB g
    writeDB "client.db" db
    return ()
