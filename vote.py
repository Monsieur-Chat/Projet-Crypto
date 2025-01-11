from ecelgamal import ECEG_encrypt, ECEG_decrypt, bruteECLog, ECEG_generate_keys, p, ECEG_add
from ecdsa import ECDSA_sign, ECDSA_verify, BaseU, BaseV, mult


# Function to cast a vote
def castVote(voteList, userPrivKey):
    """
    Cast a vote by encrypting, hashing, and signing each message in the vote list.
    Returns the encrypted vote and signature.
    """
    # Encrypt each message in the vote list
    encryptedVotes = [ECEG_encrypt(vote, pubKey) for vote in voteList]

    # Sign each encrypted message, summed each coordinate
    signatures = [ECDSA_sign(userPrivKey, bytes(str(encryptedVote), "utf-8")) for encryptedVote in encryptedVotes]

    return encryptedVotes, signatures


def areVotesValid(voteList, signatures, userPubKey):
    for i in range(len(voteList)):
        return ECDSA_verify(userPubKey, bytes(str(voteList[i]), "utf-8"), signatures[i][0], signatures[i][1])


def openBallotBox(list_r, list_c, privKey):
    out = []
    for i in range(len(list_r)):
        r_sum = list_r[i]
        c_sum = list_c[i]
        decrypted_sum = ECEG_decrypt(r_sum, c_sum, privKey)
        out.append(bruteECLog(decrypted_sum[0], decrypted_sum[1], p))

    return out


def votingProcess():
    # Initiate ballot box : [c1, c2, c3 ...]
    list_r = [(1, 0)] * 5
    list_c = [(1, 0)] * 5

    # ECDSA values initiated in ecdsa.py

    #####################################################
    # Define votes (binary lists for candidates C1 to C5)
    vote1 = [1, 0, 0, 0, 0]  # Vote for candidate C1
    vote2 = [0, 1, 0, 0, 0]  # Vote for candidate C2
    vote3 = [0, 1, 0, 0, 0]  # Vote for candidate C4

    # Get key, all user get the same key for the moment

    userPrivKey = 0xC841F4896FE86C971BEDBCF114A6CFD97E4454C9BE9ABA876D5A195995E2BA8
    userPubKey = mult(userPrivKey, BaseU, BaseV, p)


    # Each voter casts their vote
    encrypted_vote1, signature1 = castVote(vote1, userPrivKey)
    assert areVotesValid(encrypted_vote1, signature1, userPubKey)
    list_r, list_c = ECEG_add(list_r, list_c, encrypted_vote1)

    encrypted_vote2, signature2 = castVote(vote2, userPrivKey)
    assert areVotesValid(encrypted_vote2, signature2, userPubKey)
    list_r, list_c = ECEG_add(list_r, list_c, encrypted_vote2)

    encrypted_vote3, signature3 = castVote(vote3, userPrivKey)
    assert areVotesValid(encrypted_vote3, signature3, userPubKey)
    list_r, list_c = ECEG_add(list_r, list_c, encrypted_vote3)

#########################################################

    # Decrypt Ballot box and show results
    openedBallotBox = openBallotBox(list_r, list_c, privKey)

    # Show results
    winner = 0
    otherWinner = []

    for i, vote in enumerate(openedBallotBox):
        if vote > openedBallotBox[winner]:
            winner = i
            otherWinner = []
        elif vote == openedBallotBox[winner]:
            otherWinner.append(i)

        print(f"Candidate #{i+1} : {vote} votes")
    if not otherWinner:  # Single winner
        print(f"\nThe winner is candidate #{winner+1} with {openedBallotBox[winner]} votes !")
    else:
        print(f"\nThe winner are candidates {"#" + str(winner + 1) + ", #" + ", #".join([str(win + 1) for win in otherWinner[1:]])} with {openedBallotBox[winner]} votes !")


if __name__ == "__main__":
# Generate keys for elgamal as global variable
    privKey, pubKey = ECEG_generate_keys()

# Run the voting process
    votingProcess()
