import socket
import sys
import json

from ecelgamal import p, bruteECLog, ECEG_encrypt
from ecdsa import (
    BaseU, BaseV, ORDER,
    ECDSA_sign, ECDSA_verify, mult
)
import secrets

def generate_secure_private_key():
    return secrets.randbelow(ORDER - 1) + 1

def areVotesValid(voteList, signatures, userPubKey):
    # Just for local debugging if needed
    from ecdsa import ECDSA_verify
    for i in range(len(voteList)):
        if not ECDSA_verify(userPubKey, bytes(str(voteList[i]), "utf-8"),
                            signatures[i][0], signatures[i][1]):
            return False
    return True

def castVote(voteList, userPrivKey, candidatePubKeys):
    encryptedVotes = []
    for i, vote in enumerate(voteList):
        enc = ECEG_encrypt(vote, candidatePubKeys[i])
        encryptedVotes.append(enc)
    # Sign each encrypted message
    signatures = []
    for enc in encryptedVotes:
        s = ECDSA_sign(userPrivKey, bytes(str(enc), "utf-8"))
        signatures.append(s)
    return encryptedVotes, signatures

def main():
    if len(sys.argv) != 3:
        print(f"Usage: python {sys.argv[0]} <HOST> <PORT>")
        sys.exit(1)

    HOST = sys.argv[1]
    PORT = int(sys.argv[2])

    # Connect to server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))

        # 1) Receive the ballot box public key and number of candidates
        data = s.recv(4096)
        msg_in = json.loads(data.decode('utf-8'))

        sharedPubKey = tuple(msg_in["pubKey"])  # (x, y)
        num_candidates = msg_in["num_candidates"]

        print("[Client] Received ballot-box public key:", sharedPubKey)
        print("[Client] Number of candidates:", num_candidates)

        # 2) We assume the server already "knows" our private key, as per your instructions,
        #    but for demonstration we still generate one here.
        #    In a real scenario, you might do something else to match the spec.
        userPrivKey = generate_secure_private_key()
        userPubKey = mult(userPrivKey, BaseU, BaseV, p)
        print("[Client] Generated ephemeral user private key:", hex(userPrivKey))
        print("[Client] userPubKey =", userPubKey)

        # 3) Ask which candidate the user wants to vote for
        chosen = int(input(f"Choose a candidate [1..{num_candidates}]: ")) - 1
        if chosen < 0 or chosen >= num_candidates:
            print("Invalid candidate number!")
            return

        voteList = [0]*num_candidates
        voteList[chosen] = 1

        # 4) Encrypt + Sign
        candidatePubKeys = [sharedPubKey for _ in range(num_candidates)]
        encryptedVotes, signatures = castVote(voteList, userPrivKey, candidatePubKeys)

        # 5) Send to server: (encryptedVotes, signatures, userPubKey)
        # We need to JSON-serialize them
        # convert each ( (r1x,r1y), (c1x,c1y) ) to a list of two lists
        to_send_encrypted = []
        for (r_tuple, c_tuple) in encryptedVotes:
            to_send_encrypted.append([ list(r_tuple), list(c_tuple) ])

        msg_out = {
            "encryptedVotes": to_send_encrypted,  # list of pairs-of-pairs
            "signatures": signatures,             # list of [r, s]
            "userPubKey": list(userPubKey)        # [x, y]
        }
        s.sendall(json.dumps(msg_out).encode('utf-8'))

        print("[Client] Vote sent. Closing.")

if __name__ == "__main__":
    main()
