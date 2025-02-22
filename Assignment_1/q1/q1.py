from Crypto.Cipher import Salsa20
from os import urandom

class Q1Solution:
    def __init__(self):
        self.key = None

    def alice_generate_key(self):
        self.key = urandom(16)
        return self.key

a = Q1Solution()
print(a.alice_generate_key())
