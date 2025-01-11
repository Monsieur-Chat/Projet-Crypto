from ..internal.interface import interfaceEncryption
from ..internal.rfc7748 import add, sub, computeVcoordinate, mult
from random import randint

p = 2**255 - 19
ORDER = 2**252 + 27742317777372353535851937790883648493

BaseU = 9
BaseV = computeVcoordinate(BaseU)


class EcElGamal(interfaceEncryption):
    def __init__(self):
        super().__init__()

    def encrypt(self, message, pubKey):
        return ECEG_encrypt(message, pubKey)

    def decrypt(self, cipher, privKey):
        x, y = ECEG_decrypt(cipher[0], cipher[1], privKey)
        return bruteECLog(x, y, p)

    def generateKeys(self):
        return ECEG_generate_keys()

    def addCipher(self, C1, C2):
        r1, c1 = C1
        r2, c2 = C2
        rSum = add(r1[0], r1[1], r2[0], r2[1], p)
        cSum = add(c1[0], c1[1], c2[0], c2[1], p)
        return (rSum, cSum)

    def nullCipher(self):
        return ((1, 0), (1, 0))


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


def ECEG_add(list_r, list_c, vote):
    assert len(list_r) == len(list_c)
    assert len(list_r) == len(vote)

    for i in range(len(vote)):
        r1, c1 = vote[i]
        list_r[i] = add(list_r[i][0], list_r[i][1], r1[0], r1[1], p)
        list_c[i] = add(list_c[i][0], list_c[i][1], c1[0], c1[1], p)

    return list_r, list_c


if __name__ == "__main__":
    privKey, pubKey = ECEG_generate_keys()

    # client 1
    messages = [0, 0, 0, 1, 0]
    encrypted_messages = [ECEG_encrypt(message, pubKey) for message in messages]
    print(encrypted_messages)

    # client 2
    messages = [0, 1, 0, 0, 0]
    encrypted_messages2 = [ECEG_encrypt(message, pubKey) for message in messages]

    list_r = [(1, 0)] * 5
    list_c = [(1, 0)] * 5

    list_r, list_c = ECEG_add(list_r, list_c, encrypted_messages)
    list_r, list_c = ECEG_add(list_r, list_c, encrypted_messages2)
    """
    for i in range(len(encrypted_messages)):
        r1, c1 = encrypted_messages[i]
        r2, c2 = encrypted_messages2[i]
        list_r[i] = add(list_r[i][0], list_r[i][1], r1[0], r1[1], p)
        list_c[i] = add(list_c[i][0], list_c[i][1], c1[0], c1[1], p)

        list_r[i] = add(list_r[i][0], list_r[i][1], r2[0], r2[1], p)
        list_c[i] = add(list_c[i][0], list_c[i][1], c2[0], c2[1], p)
    """

    # print(f"Sum of encrypted messages: {r_sum}, {c_sum}")
    for i in range(len(list_r)):
        r_sum = list_r[i]
        c_sum = list_c[i]
        decrypted_sum = ECEG_decrypt(r_sum, c_sum, privKey)
        m = bruteECLog(decrypted_sum[0], decrypted_sum[1], p)
        print(f"{i} Sum of messages: {m}")
