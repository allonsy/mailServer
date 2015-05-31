{- Alec Snyder
- mailServer server file
-}
module Main where

import Encrypt
import System.IO
import Data.Map
import Control.Exception
import System.Directory
import Control.Concurrent.STM.TVar
import Control.Concurrent
import Network

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

interMenu :: TVar ServerDB -> IO ()
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
        4 -> quit db
        _ -> putStrLn "Choice not recognized" >> interMenu db

addUser :: TVar ServerDB -> IO ()
addUser var = do
    putStrLn "What is the username of the new User?"
    name <- getLine
    putStrLn $ "What is the filename for the public key of user: " ++ name
    fname <- getLine
    sanity <- doesFileExist fname
    if sanity
        then do
            atomically do
                db <- readTVar var
                pub <- readKey fname
                let newDB = insert name (UserEntry name pub []) (users db)
                writeTVar var $ ServerDB (serverName db) (hname db) (privKey db) (pubKey db) newDB
            putStrLn "User added"
            interMenu var
        else do
            putStrLn "File name doesn't exist"
            addUser var

delUser :: TVar ServerDB -> IO ()
delUser var = do
    putStrLn "What is the username of the User?"
    name <- getLine
    putStrLn "Are you sure? (y/n) "
    sanity <- getLine
    if (sanity == "y")
        then do
            atomically $ do
                db <- readTVar var
                let newDB = delete name (users db)
                writeTVar var $ ServerDB (serverName db) (hname db) (privKey db) (pubKey db) newDB
            putStrLn "User deleted"
            interMenu var
        else interMenu var

modUser :: ServerDB -> IO ()
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
            atomically $ do
                db <- readTVar var
                let newDB = adjust (\_ -> UserEntry name pub []) name (users db)
                writeTVar var $ ServerDB (serverName db) (hname db) (privKey db) (pubKey db) newDB
            putStrLn "user modified"
            interMenu var
        else do
            putStrLn "File name doesn't exist"
            modUser var


writeDB :: TVar ServerDB -> IO ()
writeDB var = do
    db <- atomically $ readTVar var
    writeFile "server.db" (show db)
    return ()

main :: IO ()
main = do
    db <- initServer
    serv <- atomically $ newTVar db 
    interMenu serv
