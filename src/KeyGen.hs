{- Alec Snyder Mail Server 
- Key generator library and executable generates keys and writes them to a file
- With help from wikipedia for algorithms that run in a reasonable amount of time (aka, my lifetime)
- github: https://github.com/allonsy/mailServer
-}

module Main where

import Data.Bits
import EncryptMail
import System.Random


main :: IO ()
main = do
    g <- getStdGen
    let (seed1,newGen1) = genLargeNum g
    let (p1,newGen2) = retPrime seed1 newGen1
    let (seed2, newGen3) = genLargeNum newGen2
    let (p2,newGen4) = retPrime seed2 newGen3
    let n = p1 * p2
    let phi = (p1-1) * (p2-1)
    let (e,_) = genCoprime 65537 phi newGen4
    let d = multInverse e phi
    putStrLn "Generating keys, please enter your demographic information"
    putStrLn "What is your name? "
    nameUser <- getLine
    putStrLn "What is your email? "
    email <- getLine
    let priv = Key (Person nameUser email) n d
    let pub = Key (Person nameUser email) n e
    putStrLn $ "Writing public key to " ++ nameUser ++ ".pub"
    writeFile (nameUser ++ ".pub") (show pub)
    putStrLn $ "Writing private key to " ++ nameUser ++ ".priv"
    writeFile (nameUser ++ ".priv") (show priv)
    
--generates a single random byte
genByte :: StdGen -> (Integer, StdGen)
genByte gen = randomR (0,255) gen


--generate a large 2048 bit integer efficiently
genLargeNum :: StdGen -> (Integer, StdGen)
genLargeNum gen = genLargeHelper 0 0 gen where
    genLargeHelper accum count newGen
        | count >=256 = (format accum, newGen)
        | otherwise = genLargeHelper 
                        (accum+(shiftL (fst (genByte newGen)) count)) 
                        (count + 1) 
                        (snd (genByte newGen))
    format n
        | even n = n+1
        | otherwise = n

--given a starting value (seed), it finds a random number that is coprime
--to the target number
genCoprime :: Integer -> Integer -> StdGen -> (Integer, StdGen)
genCoprime seed target gen
    | target `mod` candidate /= 0 = (candidate,newGen)
    | otherwise = genCoprime (candidate+2) target newGen where
        (candidate, newGen) = retPrime seed gen

--given a starting value, it returns the first prime that is greater
--than it.
retPrime :: Integer -> StdGen -> (Integer, StdGen)
retPrime p gen
    | predi = (p,newGen)
    | otherwise = retPrime (p+2) newGen where
    (predi,newGen) = isPrime p gen

factor :: Integer -> (Integer,Integer)
factor num = factorHelper 0 num where
    factorHelper expon mult
        | odd mult = (expon,mult)
        | otherwise = factorHelper (expon+1) (mult `quot` 2)

-- miller rabin tests to get efficiently check that a number is prime
-- uses a version of fermat's little theorem
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
        | otherwise = smallLoop (count +1) 
                                (fastMod x 2 num) 
                                g 
                                bigCount
    genRand bigCount g = let (start,newGen) = randomR (2,num-2) g
                            in if ((fastMod start d num) ==1) || ((fastMod start d num) == num-1)
                            then bigLoop (bigCount + 1) newGen
                            else smallLoop 0 (fastMod (fastMod start d num) 2 num) newGen bigCount
    k= 40 --precision constant, the higher the number, the more sure we are of not returning a false positive

-- a is the e value
-- b in phi (totient) value
-- finds the multiplicative inverse using euclid's algorithm
multInverse :: Integer -> Integer -> Integer
multInverse a b = inverseHelper 0 b 1 a where
    inverseHelper t r newt newr
        | newr == 0 = final t
        | otherwise = inverseHelper newt newr (t - (r `quot` newr) * newt) 
                                              (r - (r `quot` newr) * newr)
    final t
        | t < 0 = b + t
        | otherwise = t 

