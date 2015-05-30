{- Alec Snyder 
- Mail server encryption library
- given a key (can be read in from a file, encrypts the message with rsa and can decrypt it with the opposite key
-}

module Encrypt (fastExponent,Key(Key),Person(Person),rsaencrypt,rsadecrypt,fastMod, readKey) where

import Data.ByteString.Char8
import Crypto.Cipher.AES
import Data.Bits
import Data.List.Split
import System.IO
import Data.Char
import System.Random
import Crypto.Hash.SHA256
import Data.Time.Clock

data Key =  Key { per :: Person
                , nValue :: Integer  --n value
                , expo :: Integer }
    deriving(Show, Read)

type EncryptedPacket = (Integer --RSA encrypted Key for AES
                        ,ByteString) --AES encrypted string

data Mail = Mail {idNum :: Integer
                 ,hdr :: MailHeader
                 ,content :: String
                 ,sig :: Integer}
    deriving(Show, Read)

data MailHeader = MailHeader { to :: String
                             , from :: Person
                             , cc :: [Person]
                             , bcc :: Person
                             , subj :: String
                             , timestamp :: UTCTime }
    deriving(Show, Read)

data Person = Person { name :: String --name
                     , addr :: String } --email address
    deriving(Show, Read)

data EncryptedEmail = EncryptedEmail { idEnc :: Integer
                                     , encHdr :: EncryptedPacket
                                     , encContents :: EncryptedPacket
                                     , encSig :: Integer }
    deriving(Show, Read)
                             

fastExponent :: Integer -> Integer -> Integer
fastExponent base ex
    | ex == 2 = base * base
    | ex == 1 = base
    | ex `mod` 2 == 0 = (fastExponent base (ex `quot` 2)) * (fastExponent base (ex `quot` 2))
    | otherwise = base * (fastExponent base (ex -1))

rsaencrypt :: Key -> Integer -> Integer
rsaencrypt key m = fastMod m (expo key) (nValue key)

rsadecrypt :: Key -> Integer -> Integer
rsadecrypt key c = fastMod c (expo key) (nValue key)

fastMod :: Integer -> Integer -> Integer -> Integer
fastMod base exp modulus = fastModHelper 1 (base `mod` modulus) exp where
    fastModHelper res b e
        | e <= 0 = res
        | otherwise = if ((e `mod` 2) == 1)
                        then fastModHelper ((res*b) `mod` modulus) ((b * b) `mod` modulus) (e `shiftR` 1)
                        else
                            fastModHelper res ((b * b) `mod` modulus) (e `shiftR` 1)

readKey :: String -> IO Key
readKey path = do 
    han <- openFile path ReadMode
    key <- System.IO.hGetLine han
    let ret = read key
    hClose han
    return ret


pad :: String -> ByteString
pad start = process $ pack start where
    process mess = append (genLs 0 empty) mess
    num = 16 - ((Data.ByteString.Char8.length (pack start)) `mod` 16)
    constZero = 0 :: Word
    genLs n ls
        | n >= num = ls
        | otherwise = genLs (n+1) (cons '\NUL' ls)

genByte :: StdGen -> (Int, StdGen)
genByte gen = randomR (0,255) gen
    
genAESKey :: StdGen -> (ByteString, StdGen)
genAESKey gen = genAESHelper empty 0 gen where
    genAESHelper accum count newGen
        | count >=32 = (accum, newGen)
        | otherwise = genAESHelper (cons (chr (fst (genByte newGen))) accum) (count + 1) (snd (genByte newGen))

keyToInteger :: ByteString -> Integer
keyToInteger start = convert 0 0 $ unpack start where
    convert accum _ [] = accum
    convert accum counter (x:xs) = convert (accum + (shiftL (toInteger (ord x)) (counter * 8))) (counter + 1) xs

integerToKey :: Integer -> ByteString
integerToKey start = convert 0 start where
    convert count num
        | count >= 32 = empty
        | otherwise = cons (chr (fromIntegral (num `mod` 256)))
                            (convert 
                                (count + 1)
                                (shiftR num 8))

encryptMessage :: String -> Key -> StdGen -> (EncryptedPacket, StdGen)
encryptMessage mess key gen = (packet, newGen) where
    (k, newGen) = genAESKey gen
    aesInt = keyToInteger k
    packet = (rsaencrypt key aesInt, aesMess)
    aesMess = encryptECB (initAES k) (pad mess)
    
decryptMessage :: EncryptedPacket -> Key -> String
decryptMessage p key = unpad $ unpack dec where
    aesKey = integerToKey $ rsadecrypt key (fst p)
    dec = decryptECB (initAES aesKey) (snd p)

unpad :: String -> String
unpad [] = []
unpad (x:xs)
    | x == '\NUL' = unpad xs
    | otherwise = (x:xs)

signMessage :: String -> Key -> Integer
signMessage mess key = rsaencrypt key $ keyToInteger $
                                        hash $
                                        pack mess

verifySig :: String -> Integer -> Key -> Bool
verifySig new orig key = newHash == oldHash where
    newHash = hash (pack new)
    dec = rsadecrypt key orig
    oldHash = integerToKey dec
