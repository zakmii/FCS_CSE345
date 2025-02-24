from Crypto.Cipher import Salsa20
from os import urandom
from gmpy2 import invert
from  typing import Optional, Tuple

class Alice:
    def __init__(self):
        self.__symmetric_key: Optional[bytes] = None

    def get_symmetric_key(self) -> bytes:
        return self.__symmetric_key

    def generate_symmetric_key(self) -> None:
        self.__symmetric_key = urandom(16)

class Bob:
    def __init__(self):
        self.__public_key: Optional[Tuple[int, int]] = None
        self.__private_key: Optional[Tuple[int, int]] = None
    
    def get_public_key(self) -> Tuple[int, int]:
        return self.__public_key
    
    def get_private_key(self) -> Tuple[int, int]:
        return self.__private_key

    def generate_key_using_rsa(self,prime_p: int , prime_q: int) -> None:
        n = prime_p * prime_q
        phi = (prime_p - 1) * (prime_q - 1)

        #Taking a prime number e such that 1 < e < phi and gcd(e, phi) = 1
        #Hardcoding to avoid iterating over all numbers between 1 and phi
        e = 65537

        # d is the modular multiplicative inverse of e (modulus phi)
        d = invert(e, phi)

        self.__public_key = (n, e)
        self.__private_key = (n, d)
        


