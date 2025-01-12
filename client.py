from crypto import interfaceSigniature, interfaceEncryption


class Client:
    def __init__(
        self,
        signature: interfaceSigniature,
        encryption: interfaceEncryption,
        BoxPublicKey,
    ):
        super().__init__()
        self.__signature = signature
        self.__encryption = encryption
        self.__voteCipher: list = []
        self.__voteSignature = None
        self.__boxPubKey = BoxPublicKey

    def setKeys(self, privKey, pubKey):
        self.__privKey = privKey
        self.__pubKey = pubKey

    def __vote(self, vote):
        self.__voteCipher.append(self.__encryption.encrypt(vote, self.__boxPubKey))

    def __sign(self):
        self.__voteSignature = self.__signature.sign(self.__voteCipher, self.__privKey)

    def vote(self, votes):
        assert self.__privKey and self.__pubKey, "please set keys first"
        for voteIndex in range(len(votes)):
            self.__vote(votes[voteIndex])

    def getVote(self):
        assert len(self.__voteCipher) > 0, "please vote first"
        self.__sign()
        return self.__voteCipher, self.__voteSignature
