{- Alec Snyder 
- Mail server encryption library
- given a key (can be read in from a file, encrypts the message with rsa and can decrypt it with the opposite key
- also contains various structs to describe mail and encrypted mail
- github: https://github.com/allonsy/mailServer
-}

module EncryptMail (Key(Key)
                   ,MailHeader(MailHeader)
                   ,Person(Person)
                   ,EncryptedEmail(EncryptedEmail)
                   ,Mail(Mail)
                   ,idNum
                   ,to
                   ,from
                   ,cc
                   ,bcc
                   ,content
                   ,name
                   ,hdr
                   ,subj
                   ,addr
                   ,timestamp
                   ,changeBCC
                   ,changeMailBCC
                   ,idEnc
                   ,encHdr
                   ,encContents
                   ,encSig
                   ,fastMod
                   ,rsaencrypt
                   ,rsadecrypt
                   ,genAESKey
                   ,readKey
                   ,integerToKey
                   ,keyToInteger
                   ,encryptMessage
                   ,decryptMessage
                   ,decryptEmail
                   ,encryptEmail
                   ,signMessage
                   ,verifySig
                   ,sendToClient
                   ,recvFromClient) where


import Crypto.Cipher.AES
import Crypto.Hash.SHA256
import Data.ByteString.Char8 (pack,unpack,ByteString,cons,length,empty,append)
import Data.Bits
import Data.Char
import Data.Time.Clock
import System.IO
import System.Random

--Key datatype
--per: Person that this key belongs to
--nValue: n value of the key
--expo: exponent of the key
--same format for both public and private keys

data Key =  Key { per :: Person
                , nValue :: Integer  --n value
                , expo :: Integer }
    deriving(Show, Read)


type EncryptedPacket = (Integer --RSA encrypted Key for AES
                        ,ByteString) --AES encrypted string

data Mail = Mail {idNum :: Integer --unique identifier
                 ,hdr :: MailHeader
                 ,content :: String --message itself
                 ,sig :: Integer} --signature that is encrypted with sender's private key
    deriving(Show, Read, Eq)

data MailHeader = MailHeader { to :: String
                             , from :: Person
                             , cc :: [String] --list of emails
                             , bcc :: [String] --list of emails
                             , subj :: String
                             , timestamp :: UTCTime }
    deriving(Show, Read, Eq)

data Person = Person { name :: String --name
                     , addr :: String } --email address
    deriving(Show, Read, Eq)

data EncryptedEmail = EncryptedEmail { idEnc :: Integer --unique identifier
                                     , encHdr :: EncryptedPacket --encrypted header
                                     , encContents :: EncryptedPacket --encrypted contents
                                     , encSig :: Integer } --signature
    deriving(Show, Read,Eq)

--some homeade lenses!
changeBCC :: MailHeader -> [String] -> MailHeader
changeBCC old targ = MailHeader (to old) (from old) (cc old) targ (subj old) (timestamp old)

changeMailBCC :: Mail -> [String] -> Mail
changeMailBCC m targ = Mail (idNum m) (changeBCC (hdr m) targ) (content m) (sig m) 

                             
--takes in a integer and key and encrypts the integer with the key
rsaencrypt :: Key -> Integer -> Integer
rsaencrypt key m = fastMod m (expo key) (nValue key)

--identical to above, two functions for better readability
rsadecrypt :: Key -> Integer -> Integer
rsadecrypt key c = rsaencrypt key c

--fast modular exponentiation
fastMod :: Integer -> Integer -> Integer -> Integer
fastMod base expon modulus = fastModHelper 1 (base `mod` modulus) expon where
    fastModHelper res b e
        | e <= 0 = res
        | otherwise = if ((e `mod` 2) == 1)
                        then fastModHelper ((res*b) `mod` modulus) 
                                           ((b * b) `mod` modulus) 
                                           (e `shiftR` 1)
                        else
                            fastModHelper res ((b * b) `mod` modulus) 
                                              (e `shiftR` 1)

--given a filepath, reads and returns the key in the file
readKey :: String -> IO Key
readKey path = do 
    han <- openFile path ReadMode
    key <- System.IO.hGetLine han
    let ret = read key
    hClose han
    return ret

--converts a given string to bytestring and appends null chars to the
--beginning until the length of the bytestring is divisible by 16
pad :: String -> ByteString
pad start = process $ pack start where
    process mess = append (genLs 0 empty) mess
    num = 16 - ((Data.ByteString.Char8.length (pack start)) `mod` 16)
    genLs n ls
        | n >= num = ls
        | otherwise = genLs (n+1) (cons '\NUL' ls)

--takes in a string with leading nulls and removes them
unpad :: String -> String
unpad [] = []
unpad (x:xs)
    | x == '\NUL' = unpad xs
    | otherwise = (x:xs)

--generates a random byte
genByte :: StdGen -> (Int, StdGen)
genByte gen = randomR (0,255) gen


--efficiently generates a random AES key by conactenating 32 random bytes
--together
genAESKey :: StdGen -> (ByteString, StdGen)
genAESKey gen = genAESHelper empty 0 gen where
    genAESHelper accum count newGen
        | count >=32 = (accum, newGen)
        | otherwise = genAESHelper (cons (chr (fst (genByte newGen))) accum) (count + 1) (snd (genByte newGen))

--takes in an AES key or hash bytestring and converts it to a large Integer
keyToInteger :: ByteString -> Integer
keyToInteger start = convert 0 0 $ unpack start where
    convert accum _ [] = accum
    convert accum counter (x:xs) = convert (accum + (shiftL (toInteger (ord x)) (counter * 8))) (counter + 1) xs


--inverse of the above
integerToKey :: Integer -> ByteString
integerToKey start = convert 0 start where
    convert count num
        | count >= 32 = empty
        | otherwise = cons (chr (fromIntegral (num `mod` 256)))
                            (convert 
                                (count + 1)
                                (shiftR num 8))

--given a string, key, and stdgen, it encrypts the string and returns the new
--stdgen along with the encrypted string
encryptMessage :: String -> Key -> StdGen -> (EncryptedPacket, StdGen)
encryptMessage mess key gen = (packet, newGen) where
    (k, newGen) = genAESKey gen
    aesInt = keyToInteger k
    packet = (rsaencrypt key aesInt, aesMess)
    aesMess = encryptECB (initAES k) (pad mess)


--inverse of the above, doesn't need a stdgen
decryptMessage :: EncryptedPacket -> Key -> String
decryptMessage p key = unpad $ unpack dec where
    aesKey = integerToKey $ rsadecrypt key (fst p)
    dec = decryptECB (initAES aesKey) (snd p)

--given a string, it computes its hash and then converts the hash
--to an rsa compatible Integer
signMessage :: String -> Key -> Integer
signMessage mess key = rsaencrypt key $ keyToInteger $
                                        hash $
                                        pack mess

--converts the Integer back to a hash, then hashes the string and compares
--the results
verifySig :: String -> Integer -> Key -> Bool
verifySig new orig key = newHash == oldHash where
    newHash = hash (pack new)
    dec = rsadecrypt key orig
    oldHash = integerToKey dec

--given a mail, key, and stdgen, it encrypts the mail part by part
--returns the encrypted email and the new stdgen
encryptEmail :: Mail -> Key -> StdGen -> (EncryptedEmail, StdGen)
encryptEmail m pub gen = (EncryptedEmail 0 header cont (sig m), retGen) where
    (header, newGen) = encryptMessage (show (hdr m)) pub gen
    (cont, retGen) = encryptMessage (show (content m)) pub newGen


--inverse of the above
decryptEmail :: EncryptedEmail -> Key -> Key -> (Mail, Bool)
decryptEmail m pub priv = (retMail, verfy) where
    header = read $ decryptMessage (encHdr m) priv
    cont = read $ decryptMessage (encContents m) priv
    retMail = Mail (idEnc m) header cont (encSig m)
    verfy = verifySig ((show (changeBCC header [])) ++ cont) (encSig m) pub


--given a message to send, AES key, and handle, it encryptsthe message
--then computes the length of the cipher text, sends the length so the
--receiving end knows when the message is done
--and then sends the ciphertext
sendToClient :: String -> ByteString -> Handle -> IO ()
sendToClient mess key hand= do
    let k = initAES key
    let enc = encryptECB k (pad mess)
    let len = Data.ByteString.Char8.length enc
    hPutStrLn hand $ show len
    hPutStrLn hand $ show enc

--given an AES key and handle
--it reads first the length of the cipher text
--then it reads in all the cipher text based on length
--then it decodes the cipher text and returns the plaintext
recvFromClient :: ByteString -> Handle -> IO String
recvFromClient key hand = do
    lenStr <- hGetLine hand
    let len = read lenStr
    mess <- hGetLine hand
    let encMess = read mess :: ByteString
    if (Data.ByteString.Char8.length encMess < len)
        then do
            readAgain len encMess hand
        else do
            let dec = decryptECB (initAES key) encMess
            return $ unpad (unpack dec)
    where
        readAgain l enc han = do
            more <- hGetLine han
            let tot = append enc (pack more)
            if (Data.ByteString.Char8.length tot < l)
                then do
                    readAgain l tot han
                else do
                    let dec = decryptECB (initAES key) tot
                    return $ unpad (unpack dec)
