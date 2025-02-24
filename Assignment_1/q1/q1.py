from Crypto.Cipher import Salsa20
from os import urandom
from gmpy2 import invert, powmod
from  typing import Optional, Tuple

class Alice:
    def __init__(self):
        self.__symmetric_key: Optional[bytes] = None

    def get_symmetric_key(self) -> bytes:
        return self.__symmetric_key

    def generate_symmetric_key(self) -> None:
        self.__symmetric_key = urandom(16)
    
    def encrypt_message(self, message: bytes, bob_public_key: Tuple[int, int]) -> int:
        message_int = int.from_bytes(message, byteorder='big')
        n, e = bob_public_key

        #Encrypting the message using RSA
        cipher_text = powmod(message_int, e, n)
        return cipher_text
    
    def decrypt_salsa20_cipher(self, cipher_text: bytes) -> bytes:
        print("Received Cipher text: ", cipher_text)

        nonce = cipher_text[:8]
        cipher = Salsa20.new(key=self.__symmetric_key, nonce=nonce)
        message = cipher.decrypt(cipher_text[8:])
        return message

class Bob:
    def __init__(self):
        self.__public_key: Optional[Tuple[int, int]] = None
        self.__private_key: Optional[Tuple[int, int]] = None
        self.__alice_symmetric_key: Optional[bytes] = None
    
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
        
    def decrypt_alice_symmetric_key(self, cypher_text: int) -> bytes:
        n , d = self.__private_key
        
        #Decrypting the message using RSA
        message_int = powmod(cypher_text, d, n)

        #convert the integer to bytes as the original symmetric key was in bytes
        byte_length = (message_int.bit_length() + 7) // 8
        message = message_int.to_bytes(byte_length, byteorder='big')

        self.__alice_symmetric_key = message
        return self.__alice_symmetric_key
    
    def encrypt_using_symmetric_key(self, message: Optional[bytes] = None) -> bytes:
        if message is None:
            print("Message is not provided so generating a random message")
            message = urandom(16)
            print("Generated message: ", message)
        
        cipher = Salsa20.new(key=self.__alice_symmetric_key)
        cipher_text = cipher.nonce + cipher.encrypt(message)

        return cipher_text

#Usage
alice = Alice()
bob = Bob()

#Step 1: Alice generates a symmetric key
alice.generate_symmetric_key()
print("Alice's symmetric key: ", alice.get_symmetric_key())

#Step 2: Bob generates a public and private key using RSA
