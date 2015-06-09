{- Alec Snyder
- Test Suite for chatServer
- github link: https://github.com/allonsy/chatServer
-}

module Main (main) where

import Test.QuickCheck
import Test.Hspec
import System.Random
import EncryptMail
import Data.List

decrypt :: Integer -> Key -> Integer
decrypt x k = rsadecrypt k x

encrypt :: Integer -> Key -> Integer
encrypt x k = rsaencrypt k x

--fill in some trivial cases that quickcheck checks
checkString :: String -> Key -> Key -> StdGen -> Bool
checkString x testPub testPriv g
    | x == "" = True
    | head x == '\NUL' = True
    | otherwise = decryptMessage (fst (encryptMessage x testPub g)) testPriv == x

startsWith :: String -> String -> Bool
startsWith [] [] = True
startsWith (x:xs) [] = True
startsWith [] (x:xs) = False
startsWith (x:xs) (c:cs)
    | x == c = startsWith xs cs
    | otherwise = False

isIn :: String -> [String] -> Bool
isIn targ ls = elem targ ls

bccCheck :: [String] -> [String] -> Bool
bccCheck cli2lines cli3lines = shortcircuit1 
                               && shortcircuit2 
                               && (cli3 == "BCC: [\"test3@localhost\"]") 
                               && (cli2 == "BCC: []") where
    cli3 = cli3lines !! (head (findIndices (\x -> x `startsWith` "BCC:") cli3lines))
    cli2 = cli2lines !! ((findIndices (\x -> x `startsWith` "BCC:") cli2lines) !! 1)
    shortcircuit1 = findIndices (\x -> x `startsWith` "BCC:") cli3lines /= []
    shortcircuit2 = length (findIndices (\x -> x `startsWith` "BCC:") cli2lines) > 1

replyCheck :: [String] -> Bool
replyCheck messages = shortCircuit
                      && (messages !! begin) == "BEGIN REPLY:" 
                      && (messages !! mess) == "Thanks for the info!" 
                      && (messages !! end) == "END REPLY"
                      && (messages !! rest) == "This is a test" where
    begin = head $ elemIndices "BEGIN REPLY:" messages
    mess = begin + 1
    end  = mess  + 1
    rest = end  + 1
    shortCircuit = elemIndices "BEGIN REPLY:" messages /= []

displayCheck :: [String] -> Bool
displayCheck messages = "Hey There!" `isIn` messages
                        && "Hey There Again!" `isIn` messages
                        && "Hey there again again!" `isIn` messages

readUnreadCheck :: [String] -> Bool
readUnreadCheck messages = (unread `startsWith` "\t-***[")
                           && (alreadyread `startsWith` "\t-[") where
    unread = messages !! (1 + (head (elemIndices "Hey There Again!" messages)))
    alreadyread = messages !! (1 + (head (elemIndices "Hey There!" messages)))

main :: IO ()
main = do
    testPriv <- readKey "test/Testing.priv"
    testPub <- readKey "test/Testing.pub"
    g <- getStdGen
    
    cli1 <- readFile "test/test1client/trans1.txt"
    let client1FirstTest = lines cli1
    
    cli2 <- readFile "test/test2client/trans2.txt"
    let client2 = lines cli2
    
    cli3 <- readFile "test/test3client/trans3.txt"
    let client3 = lines cli3
    
    cli4 <- readFile "test/test4client/err.txt"
    let client4 = lines cli4
    
    cli1Sec <- readFile "test/test1client/trans2.txt"
    let client1SecondTest = lines cli1Sec
    
    hspec $ describe "Testing Encryption functions" $ do
        describe "encrypts and decrypts correctly" $ do
            it "should correctly encrypt and decrypt Integers correctly" $ property $
                \x -> decrypt (encrypt (abs x) testPub) testPriv == (abs x :: Integer)
            it "Should encrypt and decrypt arbitrary strings" $ property $
                \x -> checkString x testPub testPriv g
        describe "Signs and verifies correctly" $ do
            it "Should sign and verify correctly" $ property $
                \x -> verifySig (x :: String) (signMessage x testPriv) testPub
        describe "Converts integers to keys and back" $ do
            it "should convert integers to keys and back" $ property $
                \x -> keyToInteger (integerToKey (abs x)) == (abs x :: Integer)
    hspec $ describe "Testing Server and Client functionality" $ do
        describe "Authentication" $ do
            it "should authenitcate correct users" $
                "Authentication OK" `isIn` client1FirstTest `shouldBe` True
            it "rejects bad users" $
                "Client: Authentication failure" `isIn` client4 `shouldBe` True
        
        describe "importing users" $ do
            it "should import users from user input" $
                "Key imported for user: test2@localhost" `isIn` client1FirstTest `shouldBe` True
            it "should import user keys from server" $
                "imported key for test3@localhost" `isIn` client1FirstTest `shouldBe` True
        
        describe "sending messages" $ do
            it "Should send messages to users" $
                "Message sent!" `isIn` client1FirstTest `shouldBe` True
            it "should send multiple copies for to, cc, and bcc" $
                length ("Message sent!" `elemIndices` client1FirstTest) `shouldBe` 5
        describe "updating client database" $ do
            it "Should update database with new emails received from server" $
                "importing 3 email(s)" `isIn` client2 `shouldBe` True
        describe "Receiving emails" $ do
            it "Should receive regular emails" $
                "Hey There!" `isIn` client2 `shouldBe` True
            it "Should receive cc emails" $
                "Hey There Again!" `isIn` client3 `shouldBe` True
            it "should receive bcc emails" $
                "Hey there again again!" `isIn` client3 `shouldBe` True
            it "displays the correct bcc headers" $
                bccCheck client2 client3 `shouldBe` True
        describe "Sending Replies" $ do
            it "Should send replies" $
                "Message sent!" `isIn` client2 `shouldBe` True
            it "Should receive replies" $
                replyCheck client1SecondTest `shouldBe` True
        describe "displays and shows email correctly" $ do
            it "should display all received emails" $
                displayCheck client2 `shouldBe` True
            it "should show emails correctly" $
                "This is a test" `isIn` client2 `shouldBe` True
            it "should show read emails and unread emails stylized" $
                readUnreadCheck client2 `shouldBe` True

