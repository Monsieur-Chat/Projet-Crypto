from abc import ABC, abstractmethod


class interfaceSigniature(ABC):
    @abstractmethod
    def sign(self, vote, privKey):
        pass

    @abstractmethod
    def verify(self, vote, signature, pubKey):
        pass

    @abstractmethod
    def generateKeys(self):
        pass


class interfaceEncryption(ABC):
    @abstractmethod
    def encrypt(self, message, pubKey):
        pass

    @abstractmethod
    def decrypt(self, cipher, privKey):
        pass

    @abstractmethod
    def generateKeys(self) -> tuple:
        pass

    @abstractmethod
    def addCipher(self, c1, c2):
        pass

    @abstractmethod
    def nullCipher(self):
        pass
