{- Alec Snyder 
- Mail server encryption library
-}

module Encrypt (fastExponent,Key) where

import Data.ByteString.Char8
import Crypto.Cipher.AES

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
rsaencrypt (_,_,n,e) m = (fastExponent m e) `mod` n

rsadecrypt :: Key -> Integer -> Integer
rsadecrypt (_,_,n,d) c = (fastExponent c d) `mod` n
