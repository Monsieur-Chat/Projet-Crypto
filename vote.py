class vote():
    """docstring for ClassName."""
    def __init__(self, hashF, signF):
        super(ClassName, self).__init__()
        self.hashF = hashF
        self.signF = signF

    def vote(self):
        self.hash = self.hashF.hash(self.message)
        self.sign = self.signF.sign(self.hash)


class dsa():
    def sign(self, message):
        pass
class sha256():
    def hash(self, message):
        pass
class ecdsa():
    def sign(self, message):
        pass


vote = vote(sha256(), dsa())
vote = vote(sha256(), ecdsa())
