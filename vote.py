from termcolor import cprint
from crypto import interfaceSigniature, interfaceEncryption
from crypto.encryption import ElGamal
from crypto.signature import Dsa


class Vote:
    def __init__(self, signature: interfaceSigniature, encryption: interfaceEncryption):
        super().__init__()
        self.signature = signature
        self.encryption = encryption
        self.__privateKey, self.__publicKey = self.encryption.generateKeys()
        self.__nbOfCandidates = 5
        self.__listOfValidVote: list = []
        self.__result: list = [self.encryption.nullCipher()] * self.__nbOfCandidates

    def getPublicKey(self):
        return self.__publicKey

    def __validSignature(self, votes, signature, userPubKey):
        return self.signature.verify(votes, signature, userPubKey)

    def __validVote(self, voteList):
        sumVote = self.encryption.nullCipher()
        if not len(voteList) == self.__nbOfCandidates:
            cprint("Invalid number of votes", "red")
            return False
        for i in range(len(voteList)):
            sumVote = self.encryption.addCipher(sumVote, voteList[i])
        sumVote = self.encryption.decrypt(sumVote, self.__privateKey)
        return sumVote == 1

    def voteValidation(self, voteList, signatures, usersPubKey):
        assert len(voteList) == len(signatures) == len(usersPubKey)
        for i in range(len(voteList)):
            if self.__validSignature(
                voteList[i], signatures[i], usersPubKey[i]
            ) and self.__validVote(voteList[i]):
                self.__listOfValidVote.append(voteList[i])
                print("Valid vote")
            else:
                cprint("Invalid vote", "red")

    def counting(self):
        assert self.__listOfValidVote, "please validate vote first"
        cprint(f"Number of valid votes: {len(self.__listOfValidVote)}", "green")
        for candidate in range(self.__nbOfCandidates):
            for vote in self.__listOfValidVote:
                self.__result[candidate] = self.encryption.addCipher(
                    self.__result[candidate], vote[candidate]
                )

    def getResult(self):
        for i in range(len(self.__result)):
            self.__result[i] = self.encryption.decrypt(
                self.__result[i], self.__privateKey
            )
        return self.__result


if __name__ == "__main__":
    v = Vote(Dsa(), ElGamal())
    publicKey = v.getPublicKey()

    ec = ElGamal()
    dsa = Dsa()
    voteCit1 = [1, 0, 0, 0, 0]
    dsaPrivKey1, dsaPubKey1 = dsa.generateKeys()
    cipherCit1 = []
    for voteIndex in range(len(voteCit1)):
        cipherCit1.append(ec.encrypt(voteCit1[voteIndex], publicKey))
    signatureCit1 = dsa.sign(cipherCit1, dsaPrivKey1)

    voteCit2 = [0, 0, 0, 0, 1]
    dsaPrivKey2, dsaPubKey2 = dsa.generateKeys()
    cipherCit2 = []
    for voteIndex in range(len(voteCit2)):
        cipherCit2.append(ec.encrypt(voteCit2[voteIndex], publicKey))
    signatureCit2 = dsa.sign(cipherCit2, dsaPrivKey2)

    allCipher = [cipherCit1, cipherCit2]
    allSignature = [signatureCit1, signatureCit2]
    allPubKey = [dsaPubKey1, dsaPubKey2]

    v.voteValidation(allCipher, allSignature, allPubKey)
    v.counting()

    print(v.getResult())
