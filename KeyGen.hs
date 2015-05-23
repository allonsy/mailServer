{- Alec Snyder Mail Server 
- Key generator library and executable generates keys and writes them to a file
- With help from wikipedia for algorithms that run in a reasonable amount of time (aka, my lifetime)
-}

module Main where

import Encrypt
import System.Random
import Data.Bits

main :: IO ()
main = do
    g <- getStdGen
    let (seed1,newGen1) = genLargeNum g
    let (p1,newGen2) = retPrime seed1 newGen1
    let (seed2, newGen3) = genLargeNum newGen2
    let (p2,newGen4) = retPrime seed2 newGen3
    let n = p1 * p2
    let phi = (p1-1) * (p2-1)
    let (e,newGen5) = genCoprime 65537 phi newGen4
    let d = multInverse e phi
    return ((d,n),(e,n))
    putStrLn "Generating keys, please enter your demographic information"
    putStrLn "What is your name? "
    name <- getLine
    putStrLn "What is your email? "
    email <- getLine
    let priv = (name, email, n, d)
    let pub = (name, email, n, e)
    putStrLn $ "Writing public key to " ++ name ++ ".pub"
    writeFile (name ++ ".pub") (show pub)
    putStrLn $ "Writing private key to " ++ name ++ ".priv"
    writeFile (name ++ ".priv") (show priv)
    

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

genCoprime :: Integer -> Integer -> StdGen -> (Integer, StdGen)
genCoprime seed target gen
    | target `mod` candidate /= 0 = (candidate,newGen)
    | otherwise = genCoprime (candidate+2) target newGen where
        (candidate, newGen) = retPrime seed gen

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
        | otherwise = smallLoop (count +1) (fastMod x 2 num) g bigCount
    genRand bigCount g = let (start,newGen) = randomR (2,num-2) g
                            in if ((fastMod start d num) ==1) || ((fastMod start d num) == num-1)
                            then bigLoop (bigCount + 1) newGen
                            else smallLoop 0 (fastMod (fastMod start d num) 2 num) newGen bigCount
    --fastMod x = (fastExponent x d) `mod` num
    k= 40

--a is the e value
-- b in phi value
multInverse :: Integer -> Integer -> Integer
multInverse a b = inverseHelper 0 b 1 a where
    inverseHelper t r newt newr
        | newr == 0 = final t
        | otherwise = inverseHelper newt newr (t - (r `quot` newr) * newt) (r - (r `quot` newr) * newr)
    final t
        | t < 0 = b + t
        | otherwise = t 

showKey :: Key -> String
showKey (a,b,c,d) = "(" ++ a ++ "," ++ b ++ "," ++ (show c) ++ "," ++ (show d) ++ ")"
