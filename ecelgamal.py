from rfc7748 import x25519, add, sub, computeVcoordinate, mult
from algebra import mod_inv, int_to_bytes
from random import randint

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
    if message == 0:
        return (1, 0)
    if message == 1:
        return (BaseU, BaseV)


def ECEG_generate_keys():
    # Generate a random private key
    privKey = randint(1, ORDER - 1)
    # Compute the corresponding public key
    pubKey = mult(privKey, BaseU, BaseV, p)
    return privKey, pubKey


def ECEG_encrypt(message, pubKey):
    # Generate a random ephemeral key
    r = randint(1, ORDER - 1)
    # Compute the shared secret
    C1 = mult(r, BaseU, BaseV, p)
    # Compute the encrypted message
    x = mult(r, pubKey[0], pubKey[1], p)
    C2 = add(x[0], x[1], EGencode(message)[0], EGencode(message)[1], p)
    return (C1, C2)


def ECEG_decrypt(C1, C2, privKey):
    # Compute the shared secret using the private key
    shared_secret = mult(privKey, C1[0], C1[1], p)
    # Decrypt the message
    decrypted_message = sub(C2[0], C2[1], shared_secret[0], shared_secret[1], p)
    return decrypted_message


if __name__ == "__main__":
    privKey, pubKey = ECEG_generate_keys()
    messages = [1, 0, 1, 1, 0, 1]
    encrypted_messages = [ECEG_encrypt(message, pubKey) for message in messages]
    r_sum = (1, 0)
    c_sum = (1, 0)
    for r, c in encrypted_messages:
        r_sum = add(r_sum[0], r_sum[1], r[0], r[1], p)
        c_sum = add(c_sum[0], c_sum[1], c[0], c[1], p)
    print(f"Sum of encrypted messages: {r_sum}, {c_sum}")
    decrypted_sum = ECEG_decrypt(r_sum, c_sum, privKey)
    m = bruteECLog(decrypted_sum[0], decrypted_sum[1], p)
    print(f"Sum of messages: {m}")
