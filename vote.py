from ecelgamal import *
from ecdsa import *
import secrets

def generate_secure_private_key():
    # cryptographically secure random integer in [1..ORDER-1]
    return secrets.randbelow(ORDER - 1) + 1

def areVotesValid(voteList, signatures, userPubKey):
    """
    Verify that *all* votes in voteList match their signatures.
    Returns True if all are valid; False otherwise.
    """
    for i in range(len(voteList)):
        if not ECDSA_verify(userPubKey, bytes(str(voteList[i]), "utf-8"), 
                            signatures[i][0], signatures[i][1]):
            return False
    return True

def castVote(voteList, userPrivKey, candidatePubKeys):
    """
    Encrypt each candidate's vote (0 or 1) with that candidate's (identical) public key.
    Then sign each encrypted vote using the voter's private key.
    
    voteList: [0,1,0,...] indicating for which candidate the user voted
    userPrivKey: the voter's ECDSA private key for signing
    candidatePubKeys: list of identical public keys, one for each candidate
    """
    encryptedVotes = []
    for i, vote in enumerate(voteList):
        # Encrypt the vote under the (identical) public key for candidate i
        encrypted_vote = ECEG_encrypt(vote, candidatePubKeys[i])
        encryptedVotes.append(encrypted_vote)

    # Sign each encrypted message
    signatures = [
        ECDSA_sign(userPrivKey, bytes(str(enc), "utf-8")) 
        for enc in encryptedVotes
    ]

    return encryptedVotes, signatures

def votingProcess():
    ####################################################################
    # 1. Ask how many candidates, how many voters
    ####################################################################
    num_candidates = int(input("Enter the number of candidates: "))
    num_voters = int(input("Enter the number of voters: "))

    ####################################################################
    # 2. Generate ONE ElGamal key pair for ALL candidates
    #    Everyone shares the same private/public key.
    ####################################################################
    print("\n[Debug] Generating ONE key pair for all candidates...\n")
    sharedPrivKey, sharedPubKey = ECEG_generate_keys()
    print(f"[Debug] Shared private key = {hex(sharedPrivKey)}")
    print(f"[Debug] Shared public key  = {sharedPubKey}\n")

    # Build a list of identical public keys—one for each candidate
    candidatePubKeys = [sharedPubKey for _ in range(num_candidates)]

    ####################################################################
    # 3. Initialize the SINGLE “urn” (ballot box):
    #    a list of (r, c) pairs, one entry per candidate.
    #
    #    Even though we have multiple entries, conceptually it's one
    #    overall “urn” with separate slots for each candidate.
    ####################################################################
    ballot_box_r = [(1, 0)] * num_candidates
    ballot_box_c = [(1, 0)] * num_candidates

    ####################################################################
    # 4. For each voter, generate an ECDSA key for signing,
    #    let them choose a candidate, and add that encrypted vote
    #    into the single ballot box.
    ####################################################################
    for voter_id in range(num_voters):
        print(f"\n=== Voter #{voter_id + 1} ===")

        # Generate an ECDSA key pair for the voter
        userPrivKey = generate_secure_private_key()
        userPubKey = mult(userPrivKey, BaseU, BaseV, p)

        print(f"[Debug] Voter #{voter_id+1} private key = {hex(userPrivKey)}")
        print(f"[Debug] Voter #{voter_id+1} public key  = {userPubKey}\n")

        # The voter chooses exactly one candidate (for simplicity)
        chosen_candidate = int(input(f"Choose a candidate [1..{num_candidates}]: ")) - 1
        if chosen_candidate < 0 or chosen_candidate >= num_candidates:
            raise ValueError("Invalid candidate number!")
        print(f"[Debug] Voter #{voter_id+1} chose candidate #{chosen_candidate+1}\n")

        # Build the vote list: 1 for chosen candidate, 0 for others
        voteList = [0] * num_candidates
        voteList[chosen_candidate] = 1

        # Encrypt + Sign the votes for each candidate (same public key)
        encryptedVotes, signatures = castVote(voteList, userPrivKey, candidatePubKeys)

        # Debug: show each encrypted vote
        for i, enc in enumerate(encryptedVotes):
            print(f"[Debug] Encrypted vote for candidate #{i+1}: {enc}")

        # Verify
        if not areVotesValid(encryptedVotes, signatures, userPubKey):
            print("Error: Verification failed for this voter's ballot. Aborting...")
            return

        # Add to the single ballot box (which has multiple slots)
        # This is effectively "one urn" but with separate compartments
        ballot_box_r, ballot_box_c = ECEG_add(ballot_box_r, ballot_box_c, encryptedVotes)

        print(f"\n[Debug] Updated ballot_box_r: {ballot_box_r}")
        print(f"[Debug] Updated ballot_box_c: {ballot_box_c}\n")

    ####################################################################
    # 5. Final Tally: Using the SAME private key to decrypt each slot
    #    in the single urn. Then compute discrete log to get counts.
    ####################################################################
    print("\n=== Final Tally ===")
    print(f"[Debug] Final aggregated ballot_box_r: {ballot_box_r}")
    print(f"[Debug] Final aggregated ballot_box_c: {ballot_box_c}\n")

    results = []
    for i in range(num_candidates):
        # Everyone uses the same private key
        r_sum = ballot_box_r[i]
        c_sum = ballot_box_c[i]

        decrypted_sum = ECEG_decrypt(r_sum, c_sum, sharedPrivKey)
        vote_count = bruteECLog(decrypted_sum[0], decrypted_sum[1], p)

        print(f"[Debug] Candidate #{i+1} decrypted point: {decrypted_sum}, => {vote_count} votes")
        results.append(vote_count)

    ####################################################################
    # 6. Display the results and find the winner
    ####################################################################
    winner = 0
    otherWinners = []  # For ties

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


if __name__ == "__main__":
    votingProcess()
