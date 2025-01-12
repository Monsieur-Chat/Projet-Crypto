from rfc7748 import x25519, add, sub, computeVcoordinate, mult
from algebra import mod_inv, int_to_bytes
import secrets  # Use cryptographically secure randomness instead of random.randint

p = 2**255 - 19
ORDER = 2**252 + 27742317777372353535851937790883648493

BaseU = 9
BaseV = computeVcoordinate(BaseU)


def bruteECLog(C1, C2, p):
    s1, s2 = 1, 0
    for i in range(p):
        if s1 == C1 and s2 == C2:
            return i
        s1, s2 = add(s1, s2, BaseU, BaseV, p)
    return -1


def EGencode(message):
    """
    Encodes message 0 -> (1, 0) 
                   1 -> (BaseU, BaseV).
    You can adapt this if you have different or larger message sets.
    """
    if message == 0:
        return (1, 0)
    if message == 1:
        return (BaseU, BaseV)


def ECEG_generate_keys():
    """
    Generate an EC-ElGamal keypair:
      private_key = random integer in [1..(ORDER-1)]
      public_key  = private_key * G
    """
    # Use cryptographically secure random in [1..ORDER-1]
    privKey = secrets.randbelow(ORDER - 1) + 1
    # Compute the corresponding public key
    pubKey = mult(privKey, BaseU, BaseV, p)
    return privKey, pubKey


def ECEG_encrypt(message, pubKey):
    """
    EC-ElGamal encryption of 'message' using 'pubKey'.
    message is assumed to be in {0,1}, for which we use EGencode().
    """
    # Generate a random ephemeral key r in [1..ORDER-1]
    r = secrets.randbelow(ORDER - 1) + 1
    # C1 = r*G
    C1 = mult(r, BaseU, BaseV, p)
    # x = r * pubKey = r * Q
    x = mult(r, pubKey[0], pubKey[1], p)
    # C2 = M + x
    # but M is encoded as EGencode(message)
    encoded = EGencode(message)
    C2 = add(x[0], x[1], encoded[0], encoded[1], p)
    return (C1, C2)


def ECEG_decrypt(C1, C2, privKey):
    """
    Decrypt using the private key:
      shared_secret = privKey * C1
      decrypted_message = C2 - shared_secret
    """
    # Compute the shared secret
    shared_secret = mult(privKey, C1[0], C1[1], p)
    # Subtract it from C2
    decrypted_message = sub(C2[0], C2[1], shared_secret[0], shared_secret[1], p)
    return decrypted_message


def ECEG_add(list_r, list_c, vote):
    """
    Adds an encrypted vote to the running tallies (list_r, list_c).
    Each candidate has a slot in list_r/list_c.
    vote is a list of (C1,C2) pairs for each candidate.
    """
    assert len(list_r) == len(list_c)
    assert len(list_r) == len(vote)

    for i in range(len(vote)):
        r1, c1 = vote[i]
        # Accumulate r
        list_r[i] = add(list_r[i][0], list_r[i][1], r1[0], r1[1], p)
        # Accumulate c
        list_c[i] = add(list_c[i][0], list_c[i][1], c1[0], c1[1], p)

    return list_r, list_c


if __name__ == "__main__":
    privKey, pubKey = ECEG_generate_keys()

    # client 1
    messages = [0, 0, 0, 1, 0]
    encrypted_messages = [ECEG_encrypt(msg, pubKey) for msg in messages]
    print("Encrypted messages (client 1):")
    for em in encrypted_messages:
        print(em)

    # client 2
    messages = [0, 1, 0, 0, 0]
    encrypted_messages2 = [ECEG_encrypt(msg, pubKey) for msg in messages]
    print("\nEncrypted messages (client 2):")
    for em in encrypted_messages2:
        print(em)

    # Initialize tally (one slot per candidate)
    list_r = [(1, 0)] * 5
    list_c = [(1, 0)] * 5

    # Add both sets of encrypted messages
    list_r, list_c = ECEG_add(list_r, list_c, encrypted_messages)
    list_r, list_c = ECEG_add(list_r, list_c, encrypted_messages2)

    print("\nFinal Tally (Encrypted):")
    for i in range(len(list_r)):
        print(f"Candidate {i}: R={list_r[i]}, C={list_c[i]}")

    # Decrypt sum and decode via bruteECLog
    print("\nDecrypted sums for each candidate:")
    for i in range(len(list_r)):
        r_sum = list_r[i]
        c_sum = list_c[i]
        decrypted_sum = ECEG_decrypt(r_sum, c_sum, privKey)
        m = bruteECLog(decrypted_sum[0], decrypted_sum[1], p)
        print(f"Candidate {i} sum of messages: {m}")
