{- Alec Snyder 
- Mail server encryption library
- given a key (can be read in from a file, encrypts the message with rsa and can decrypt it with the opposite key
-}

module Encrypt (fastExponent,Key,rsaencrypt,rsadecrypt,fastMod) where

import Data.ByteString.Char8
import Crypto.Cipher.AES
import Data.Bits
import Data.List.Split

type Key =  (String   --name of person
            ,String   --email of person
            ,Integer  --n value
            ,Integer) --exponent value
            --both public and private key

fastExponent :: Integer -> Integer -> Integer
fastExponent base ex
    | ex == 2 = base * base
    | ex == 1 = base
    | ex `mod` 2 == 0 = (fastExponent base (ex `quot` 2)) * (fastExponent base (ex `quot` 2))
    | otherwise = base * (fastExponent base (ex -1))

rsaencrypt :: Key -> Integer -> Integer
rsaencrypt (_,_,n,e) m = fastMod m e n

rsadecrypt :: Key -> Integer -> Integer
rsadecrypt (_,_,n,d) c = fastMod c d n

fastMod :: Integer -> Integer -> Integer -> Integer
fastMod base exp modulus = fastModHelper 1 (base `mod` modulus) exp where
    fastModHelper res b e
        | e <= 0 = res
        | otherwise = if ((e `mod` 2) == 1)
                        then fastModHelper ((res*b) `mod` modulus) ((b * b) `mod` modulus) (e `shiftR` 1)
                        else
                            fastModHelper res ((b * b) `mod` modulus) (e `shiftR` 1)

{- readKey String -> Key
readKey str = (head lst, lst !! 1, read (lst !! 2), read (lst !! 3) where
    lst = splitOn "," tail str
-}
