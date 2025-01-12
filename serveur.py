# serveur.py

import socket
import threading
import json
import sys
import secrets

from ecelgamal import (
    p as ECELG_P, ECEG_generate_keys, ECEG_decrypt, ECEG_add, bruteECLog, ECEG_encrypt
)
from elgamal import (
    PARAM_P as ELG_P, PARAM_Q as ELG_Q, PARAM_G as ELG_G,
    EG_generate_keys, EGA_encrypt, EG_decrypt, bruteLog
)
from dsa import (
    DSA_generate_keys, DSA_sign, DSA_verify
)
from ecdsa import (
    ECDSA_generate_keys, ECDSA_sign, ECDSA_verify
)
import json

votes_received = 0  # Global counter for received votes

def areVotesValid(voteList, signatures, userPubKey, signature_algo, encryption_algo):
    for i in range(len(voteList)):
        if encryption_algo == 'ElGamal':
            message = f"{voteList[i][0]}_{voteList[i][1]}"
        elif encryption_algo == 'ECElGamal':
            message = json.dumps(voteList[i])
        else:
            message = str(voteList[i])
        message_bytes = message.encode('utf-8')
        r, s = signatures[i]
        if signature_algo == 'DSA':
            valid = DSA_verify(message, r, s, userPubKey)
        elif signature_algo == 'ECDSA':
            valid = ECDSA_verify(userPubKey, message_bytes, r, s)
        else:
            print(f"Unsupported signature algorithm: {signature_algo}")
            return False
        if not valid:
            return False
    return True

def castVote(voteList, userPrivKey, candidatePubKeys, encryption_algo, signature_algo):
    encryptedVotes = []
    for i, vote in enumerate(voteList):
        pubKey = candidatePubKeys[i]
        if encryption_algo == 'ElGamal':
            enc = EGA_encrypt(vote, pubKey)  # Use additive encryption for ElGamal
        elif encryption_algo == 'ECElGamal':
            enc = ECEG_encrypt(vote, pubKey)
        else:
            raise ValueError(f"Unsupported encryption algorithm: {encryption_algo}")
        encryptedVotes.append(enc)
    
    signatures = []
    for enc in encryptedVotes:
        if encryption_algo == 'ElGamal':
            message = f"{enc[0]}_{enc[1]}"
            message_bytes = message.encode('utf-8')
        elif encryption_algo == 'ECElGamal':
            message = json.dumps(enc)
            message_bytes = message.encode('utf-8')
        else:
            raise ValueError(f"Unsupported encryption algorithm: {encryption_algo}")
        
        if signature_algo == 'DSA':
            r, s = DSA_sign(message, userPrivKey)
        elif signature_algo == 'ECDSA':
            r, s = ECDSA_sign(userPrivKey, message_bytes)
        else:
            raise ValueError(f"Unsupported signature algorithm: {signature_algo}")
        signatures.append((r, s))
    return encryptedVotes, signatures

def tally_and_print(ballot_box_r, ballot_box_c, sharedPrivKey, encryption_algo, num_candidates):
    print("\n=== Final Tally ===")
    results = []
    for i in range(num_candidates):
        r_sum = ballot_box_r[i]
        c_sum = ballot_box_c[i]
        if encryption_algo == 'ECElGamal':
            decrypted_sum = ECEG_decrypt(r_sum, c_sum, sharedPrivKey)
            vote_count = bruteECLog(decrypted_sum[0], decrypted_sum[1], ECELG_P)
        elif encryption_algo == 'ElGamal':
            decrypted_sum = EG_decrypt(r_sum, c_sum, sharedPrivKey)
            vote_count = bruteLog(decrypted_sum, ELG_G, ELG_P)
        else:
            raise ValueError(f"Unsupported encryption algorithm: {encryption_algo}")
        print(f"Candidate #{i+1}: {vote_count} votes")
        results.append(vote_count)
    
    winner = 0
    otherWinners = []
    for i, count in enumerate(results):
        if count > results[winner]:
            winner = i
            otherWinners = []
        elif i != winner and count == results[winner]:
            otherWinners.append(i)
    if not otherWinners:
        print(f"\nWinner: Candidate #{winner+1} with {results[winner]} votes!")
    else:
        tie_candidates = [winner] + otherWinners
        tie_str = ", ".join([f"#{c+1}" for c in tie_candidates])
        print(f"\nTie among candidates {tie_str} with {results[winner]} votes each!")

def client_handler(conn, addr, config):
    global votes_received

    # Refuse new votes if tallying is done
    if config.get('tallied', False):
        try:
            refusal_msg = json.dumps({"error": "Voting period ended."})
            conn.sendall(refusal_msg.encode('utf-8'))
        except Exception as e:
            print(f"Error sending refusal message: {e}")
        finally:
            conn.close()
        return

    signature_algo = config['signature_algo']
    encryption_algo = config['encryption_algo']
    sharedPubKey = config['sharedPubKey']
    num_candidates = config['num_candidates']
    ballot_box_r = config['ballot_box_r']
    ballot_box_c = config['ballot_box_c']
    sharedPrivKey = config['sharedPrivKey']
    max_voters = config['max_voters']
    lock = config['lock']

    try:
        msg_out = {
            "pubKey": sharedPubKey,
            "num_candidates": num_candidates,
            "signature_algo": signature_algo,
            "encryption_algo": encryption_algo
        }
        conn.sendall(json.dumps(msg_out).encode('utf-8'))

        data = conn.recv(4096)
        if not data:
            conn.close()
            return

        msg_in = json.loads(data.decode('utf-8'))
        encryptedVotes = msg_in["encryptedVotes"]
        signatures = msg_in["signatures"]
        userPubKey_list = msg_in["userPubKey"]

        if signature_algo == 'DSA':
            if isinstance(userPubKey_list, list):
                userPubKey_value = int(userPubKey_list[0])
            else:
                userPubKey_value = int(userPubKey_list)
        elif signature_algo == 'ECDSA':
            userPubKey_value = tuple(userPubKey_list)
        else:
            print(f"Unsupported signature algorithm: {signature_algo}")
            conn.close()
            return

        if encryption_algo == 'ECElGamal':
            encryptedVotes_tuples = [tuple(vote) for vote in encryptedVotes]
        elif encryption_algo == 'ElGamal':
            encryptedVotes_tuples = [tuple(vote) for vote in encryptedVotes]
        else:
            print(f"Unsupported encryption algorithm: {encryption_algo}")
            conn.close()
            return

        if not areVotesValid(encryptedVotes_tuples, signatures, userPubKey_value, signature_algo, encryption_algo):
            print(f"[Error] Verification failed from client {addr}. Discarding.")
            conn.close()
            return

        with lock:
            if encryption_algo == 'ECElGamal':
                ECEG_add(ballot_box_r, ballot_box_c, encryptedVotes_tuples)
            elif encryption_algo == 'ElGamal':
                for i in range(len(encryptedVotes_tuples)):
                    r, c = encryptedVotes_tuples[i]
                    ballot_box_r[i] = (ballot_box_r[i] * r) % ELG_P
                    ballot_box_c[i] = (ballot_box_c[i] * c) % ELG_P
            else:
                raise ValueError(f"Unsupported encryption algorithm: {encryption_algo}")

            votes_received += 1
            print(f"[Debug] Received vote #{votes_received} from {addr}.")

            if votes_received >= max_voters and not config.get('tallied', False):
                config['tallied'] = True
                tally_and_print(ballot_box_r, ballot_box_c, sharedPrivKey, encryption_algo, num_candidates)
                print("[Server] Reached max voters, closing server.")
    finally:
        conn.close()

def main():
    global votes_received
    votes_received = 0

    if len(sys.argv) != 5:
        print(f"Usage: python {sys.argv[0]} <HOST> <PORT> <MAX_VOTERS> <NUM_CANDIDATES>")
        sys.exit(1)

    HOST = sys.argv[1]
    PORT = int(sys.argv[2])
    MAX_VOTERS = int(sys.argv[3])
    NUM_CANDIDATES = int(sys.argv[4])

    print("Select Signature Algorithm:")
    print("1. DSA")
    print("2. ECDSA")
    sig_choice = input("Enter choice number (1 or 2): ").strip()
    if sig_choice == '1':
        signature_algo = 'DSA'
    elif sig_choice == '2':
        signature_algo = 'ECDSA'
    else:
        print("Invalid choice for Signature Algorithm.")
        sys.exit(1)

    print("\nSelect Encryption Algorithm:")
    print("1. ElGamal")
    print("2. EC-ElGamal")
    enc_choice = input("Enter choice number (1 or 2): ").strip()
    if enc_choice == '1':
        encryption_algo = 'ElGamal'
    elif enc_choice == '2':
        encryption_algo = 'ECElGamal'
    else:
        print("Invalid choice for Encryption Algorithm.")
        sys.exit(1)

    print(f"\nSelected Signature Algorithm: {signature_algo}")
    print(f"Selected Encryption Algorithm: {encryption_algo}\n")

    if encryption_algo == 'ElGamal':
        sharedPrivKey, sharedPubKey = EG_generate_keys()
    elif encryption_algo == 'ECElGamal':
        sharedPrivKey, sharedPubKey = ECEG_generate_keys()
    else:
        print(f"Unsupported encryption algorithm: {encryption_algo}")
        sys.exit(1)

    print(f"[Debug] Shared private key = {sharedPrivKey}")
    print(f"[Debug] Shared public key  = {sharedPubKey}\n")

    if encryption_algo == 'ElGamal':
        ballot_box_r = [1] * NUM_CANDIDATES
        ballot_box_c = [1] * NUM_CANDIDATES
    elif encryption_algo == 'ECElGamal':
        ballot_box_r = [(1, 0)] * NUM_CANDIDATES
        ballot_box_c = [(1, 0)] * NUM_CANDIDATES
    else:
        raise ValueError(f"Unsupported encryption algorithm: {encryption_algo}")

    lock = threading.Lock()

    config = {
        'signature_algo': signature_algo,
        'encryption_algo': encryption_algo,
        'sharedPrivKey': sharedPrivKey,
        'sharedPubKey': sharedPubKey,
        'num_candidates': NUM_CANDIDATES,
        'max_voters': MAX_VOTERS,
        'ballot_box_r': ballot_box_r,
        'ballot_box_c': ballot_box_c,
        'lock': lock,
        'tallied': False
    }

    print(f"[Server] Starting server on {HOST}:{PORT}, expecting {MAX_VOTERS} votes for {NUM_CANDIDATES} candidates...")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()

        while True:
            conn, addr = s.accept()
            print(f"[Server] Connection from {addr}")
            threading.Thread(target=client_handler, args=(conn, addr, config)).start()

            with lock:
                if votes_received >= MAX_VOTERS:
                    break

    print("[Server] Done. Exiting.")

if __name__ == "__main__":
    main()
