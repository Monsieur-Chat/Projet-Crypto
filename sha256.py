from Crypto.Hash import SHA256
from interface import interfaceSigniature


class sha256(interfaceSigniature):
    def __init__(self):
        super().__init__()

    def sign(self, vote, privKey):
        h = SHA256.new(vote.encode())
        return int(h.hexdigest(), 16)

    def verify(self, vote, signature, pubKey):
        h = SHA256.new(vote.encode())
        return signature == int(h.hexdigest(), 16)

    def generateKeys(self):
        return
