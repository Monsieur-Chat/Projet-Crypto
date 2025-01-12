from termcolor import cprint
from crypto import interfaceSigniature, interfaceEncryption
from crypto.encryption import ElGamal
from crypto.signature import Dsa
from client import Client


class Box:
    def __init__(self, signature: interfaceSigniature, encryption: interfaceEncryption):
        super().__init__()
        self.__signature = signature
        self.__encryption = encryption
        self.__privateKey, self.__publicKey = self.__encryption.generateKeys()
        self.__nbOfCandidates = 5
        self.__listOfValidVote: list = []
        self.__voteList: list = []
        self.__voteSignature = []
        self.__result: list = [self.__encryption.nullCipher()] * self.__nbOfCandidates

    def getPublicKey(self):
        return self.__publicKey

    def __validSignature(self, votes, signature, userPubKey):
        return self.__signature.verify(votes, signature, userPubKey)

    def __validVote(self, voteList):
        sumVote = self.__encryption.nullCipher()
        if not len(voteList) == self.__nbOfCandidates:
            cprint("Invalid number of votes", "red")
            return False
        for i in range(len(voteList)):
            sumVote = self.__encryption.addCipher(sumVote, voteList[i])
        sumVote = self.__encryption.decrypt(sumVote, self.__privateKey)
        return sumVote == 1

    def vote(self, vote, signature):
        assert len(self.__voteList) == len(
            self.__voteSignature
        ), "mismatch between votes and signatures"
        self.__voteList.append(vote)
        self.__voteSignature.append(signature)

    def voteValidation(self, usersPubKey):
        assert (
            len(self.__voteList) == len(self.__voteSignature) == len(usersPubKey)
        ), "mismatch between votes and signatures"
        for i in range(len(self.__voteList)):
            if self.__validSignature(
                self.__voteList[i], self.__voteSignature[i], usersPubKey[i]
            ) and self.__validVote(self.__voteList[i]):
                self.__listOfValidVote.append(self.__voteList[i])
                print("Valid vote")
            else:
                cprint("Invalid vote", "red")

    def counting(self):
        assert self.__listOfValidVote, "please validate vote first or not valid vote"
        cprint(f"Number of valid votes: {len(self.__listOfValidVote)}", "green")
        for candidate in range(self.__nbOfCandidates):
            for vote in self.__listOfValidVote:
                self.__result[candidate] = self.__encryption.addCipher(
                    self.__result[candidate], vote[candidate]
                )

    def getResult(self):
        for i in range(len(self.__result)):
            self.__result[i] = self.__encryption.decrypt(
                self.__result[i], self.__privateKey
            )
        return self.__result


if __name__ == "__main__":
    v = Box(Dsa(), ElGamal())
    publicKey = v.getPublicKey()

    dsa = Dsa()
    cit1 = Client(Dsa(), ElGamal(), publicKey)
    cit2 = Client(Dsa(), ElGamal(), publicKey)

    dsaPrivKey1, dsaPubKey1 = dsa.generateKeys()
    dsaPrivKey2, dsaPubKey2 = dsa.generateKeys()

    cit1.setKeys(dsaPrivKey1, dsaPubKey1)
    cit2.setKeys(dsaPrivKey2, dsaPubKey2)

    cit1.vote([1, 0, 0, 0, 0])
    cit2.vote([0, 1, 0, 0, 0])

    cipherCit1, signatureCit1 = cit1.getVote()
    cipherCit2, signatureCit2 = cit2.getVote()

    # print(cipherCit1)
    # print(signatureCit1)

    allCipher = [cipherCit1, cipherCit2]
    allSignature = [signatureCit1, signatureCit2]
    allPubKey = [dsaPubKey1, dsaPubKey2]

    v.vote(cipherCit1, signatureCit1)
    v.vote(cipherCit2, signatureCit2)
    v.voteValidation(allPubKey)
    v.counting()

    print(v.getResult())
