{- Alec Snyder Mail Server 
- Key generator library
-}

module Main where

import Encrypt
import System.Random
import Data.Bits

genAsymKeys :: IO (Integer, Integer)
genAsymKeys = return (1,2)

genByte :: StdGen -> (Integer, StdGen)
genByte gen = randomR (0,255) gen
    
genLargeNum :: StdGen -> (Integer, StdGen) --generates large 2048 bit Integer
genLargeNum gen = genLargeHelper 0 0 gen where
    genLargeHelper accum count newGen
        | count >=256 = (format accum, newGen)
        | otherwise = genLargeHelper (accum+(shiftL (fst (genByte newGen)) count)) (count + 1) (snd (genByte newGen))
    format n
        | even n = n+1
        | otherwise = n

retPrime :: Integer -> StdGen -> (Integer, StdGen)
retPrime p gen
    | pred = (p,newGen)
    | otherwise = retPrime (p+2) newGen where
    (pred,newGen) = isPrime p gen

factor :: Integer -> (Integer,Integer)
factor num = factorHelper 0 num where
    factorHelper exp mult
        | odd mult = (exp,mult)
        | otherwise = factorHelper (exp+1) (mult `quot` 2)

isPrime :: Integer -> StdGen -> (Bool,StdGen)
isPrime num gen = bigLoop 0 gen where
    (s,d) = factor (num - 1)
    bigLoop count g
        | count >= k = (True,g)
        | otherwise = genRand count g
    smallLoop count x g bigCount
        | count >= (s-1) = (False, g)
        | x == 1 = (False, g)
        | x == (num-1) = bigLoop (bigCount +1) g
        | otherwise = smallLoop (count +1) ((fastExponent x 2) `mod` num) g bigCount
    genRand bigCount g = let (start,newGen) = randomR (2,num-2) g
                            in if ((fastMod start) ==1) || ((fastMod start) == num-1)
                            then bigLoop (bigCount + 1) newGen
                            else smallLoop 0 ((fastExponent (fastMod start) 2) `mod` num) newGen bigCount
    fastMod x = (fastExponent x d) `mod` num
    k= 40


main = do
    g <- getStdGen
    let (b,newG) = genLargeNum g
    let d = retPrime 951221 newG
    putStrLn $ show d
