import socket
import threading
import json
import sys

from ecelgamal import (
    p, ECEG_generate_keys, ECEG_decrypt, ECEG_add, bruteECLog
)
from ecdsa import (
    BaseU, BaseV, ORDER,
    ECDSA_sign, ECDSA_verify, mult
)
import secrets

# ----- BEGIN VOTING LOGIC (extracted from your final code) -----

def generate_secure_private_key():
    # cryptographically secure random integer in [1..ORDER-1]
    return secrets.randbelow(ORDER - 1) + 1

def areVotesValid(voteList, signatures, userPubKey):
    for i in range(len(voteList)):
        if not ECDSA_verify(userPubKey, bytes(str(voteList[i]), "utf-8"),
                            signatures[i][0], signatures[i][1]):
            return False
    return True

# We won't prompt for input in the server anymore.
# The server just holds the "ballot box" and the private/public keys.
# We can store them as global variables in this small example.

# Global “urn” (ballot box) data
ballot_box_r = []
ballot_box_c = []

# Shared key pair for the entire election
sharedPrivKey = None
sharedPubKey = None

# Number of votes to accept before tally
NUM_CANDIDATES = 0
MAX_VOTERS = 0
votes_received = 0

lock = threading.Lock()  # to protect shared data

def tally_and_print():
    """
    After receiving all votes, decrypt each candidate’s sum
    and print the result.
    """
    print("\n=== Final Tally ===")
    print("[Debug] Final aggregated ballot_box_r:", ballot_box_r)
    print("[Debug] Final aggregated ballot_box_c:", ballot_box_c, "\n")

    results = []
    for i in range(NUM_CANDIDATES):
        r_sum = ballot_box_r[i]
        c_sum = ballot_box_c[i]
        decrypted_sum = ECEG_decrypt(r_sum, c_sum, sharedPrivKey)
        vote_count = bruteECLog(decrypted_sum[0], decrypted_sum[1], p)
        print(f"[Debug] Candidate #{i+1} decrypted point: {decrypted_sum} => {vote_count} votes")
        results.append(vote_count)

    # Find winner(s)
    winner = 0
    otherWinners = []
    for i, count in enumerate(results):
        print(f"Candidate #{i + 1}: {count} votes")
        if count > results[winner]:
            winner = i
            otherWinners = []
        elif (i != winner) and (count == results[winner]):
            otherWinners.append(i)

    if not otherWinners:
        print(f"\nWinner: Candidate #{winner+1} with {results[winner]} votes!")
    else:
        tie_candidates = [winner] + otherWinners
        tie_str = ", ".join([f"#{c+1}" for c in tie_candidates])
        print(f"\nTie among candidates {tie_str} with {results[winner]} votes each!")

# ----- END VOTING LOGIC -----

def client_handler(conn, addr):
    global votes_received

    try:
        # 1) Send the public key to the client
        # Convert to a JSON-serializable structure (list of two ints)
        pub_key_to_send = [sharedPubKey[0], sharedPubKey[1]]
        msg_out = {"pubKey": pub_key_to_send,
                   "num_candidates": NUM_CANDIDATES}
        conn.sendall(json.dumps(msg_out).encode('utf-8'))

        # 2) Receive the vote from the client
        data = conn.recv(4096)
        if not data:
            conn.close()
            return

        # Parse the JSON
        msg_in = json.loads(data.decode('utf-8'))
        encryptedVotes = msg_in["encryptedVotes"]  # list of [ (r0,r1), (c0,c1) ] pairs
        signatures = msg_in["signatures"]         # list of [r, s] pairs
        userPubKey_list = msg_in["userPubKey"]    # [x, y]

        # Convert them to the correct tuple/list forms
        # For each candidate's vote, we have: [[r_x, r_y], [c_x, c_y]]
        # So we'll transform each into ((r_x, r_y), (c_x, c_y))
        encryptedVotes_tuples = []
        for enc in encryptedVotes:
            r_tuple = tuple(enc[0])
            c_tuple = tuple(enc[1])
            encryptedVotes_tuples.append((r_tuple, c_tuple))

        userPubKey_tuple = tuple(userPubKey_list)

        # 3) Verify the votes
        if not areVotesValid(encryptedVotes_tuples, signatures, userPubKey_tuple):
            print(f"[Error] Verification failed from client {addr}. Discarding.")
            conn.close()
            return

        # 4) Add them to the ballot box
        with lock:
            ECEG_add(ballot_box_r, ballot_box_c, encryptedVotes_tuples)
            votes_received += 1
            print(f"[Debug] Received vote #{votes_received} from {addr}.")

            # If we've reached MAX_VOTERS, do final tally
            if votes_received >= MAX_VOTERS:
                tally_and_print()
                print("[Server] Reached max voters, closing server.")
                # We’ll shut down the server by closing the main socket
                # (we’ll do it from main thread).
    finally:
        conn.close()


def main():
    global ballot_box_r, ballot_box_c, sharedPrivKey, sharedPubKey
    global NUM_CANDIDATES, MAX_VOTERS

    if len(sys.argv) != 4:
        print(f"Usage: python {sys.argv[0]} <HOST> <PORT> <MAX_VOTERS>")
        print("Then it will ask you for the number of candidates.")
        sys.exit(1)

    HOST = sys.argv[1]
    PORT = int(sys.argv[2])
    MAX_VOTERS = int(sys.argv[3])
    NUM_CANDIDATES = int(input("Enter the number of candidates: "))

    print("[Server] Generating one ElGamal key pair for the entire ballot box...")
    sharedPrivKey, sharedPubKey = ECEG_generate_keys()
    print(f"[Debug] Shared private key = {hex(sharedPrivKey)}")
    print(f"[Debug] Shared public key  = {sharedPubKey}\n")

    # Initialize ballot box
    ballot_box_r = [(1, 0)] * NUM_CANDIDATES
    ballot_box_c = [(1, 0)] * NUM_CANDIDATES

    # Start the TCP server
    print(f"[Server] Starting server on {HOST}:{PORT}, expecting {MAX_VOTERS} votes...")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()

        # We will accept connections until we gather MAX_VOTERS
        while True:
            conn, addr = s.accept()
            print(f"[Server] Connection from {addr}")
            # Handle client in a new thread
            t = threading.Thread(target=client_handler, args=(conn, addr))
            t.start()

            # Check if we have already reached the max voters
            # We use lock to read votes_received safely
            with lock:
                if votes_received >= MAX_VOTERS:
                    # We already tallied. We can break here to stop accepting new connections
                    break

    print("[Server] Done. Exiting.")

if __name__ == "__main__":
    main()
