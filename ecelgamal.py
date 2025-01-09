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
    

    # client 1
    messages = [0, 0, 0, 1, 0]
    encrypted_messages = [ECEG_encrypt(message, pubKey) for message in messages]

    # client 2 
    messages = [0, 1, 0, 0, 0]
    encrypted_messages2 = [ECEG_encrypt(message, pubKey) for message in messages]


    # server
    r1_sum = (1, 0)
    c1_sum = (1, 0)

    r2_sum = (1, 0)
    c2_sum = (1, 0)

    r3_sum = (1, 0)
    c3_sum = (1, 0)

    c4_sum = (1, 0)
    r4_sum = (1, 0)

    r5_sum = (1, 0)
    c5_sum = (1, 0)

    list_r = [r1_sum, r2_sum, r3_sum, r4_sum, r5_sum]
    list_c = [c1_sum, c2_sum, c3_sum, c4_sum, c5_sum]

    for i in range(len(encrypted_messages)):
        r1, c1 = encrypted_messages[i]
        r2, c2 = encrypted_messages2[i]
        list_r[i] = add(list_r[i][0], list_r[i][1], r1[0], r1[1], p)
        list_c[i] = add(list_c[i][0], list_c[i][1], c1[0], c1[1], p)

        list_r[i] = add(list_r[i][0], list_r[i][1], r2[0], r2[1], p)
        list_c[i] = add(list_c[i][0], list_c[i][1], c2[0], c2[1], p)



    # print(f"Sum of encrypted messages: {r_sum}, {c_sum}")
    for i in range(len(list_r)):
        r_sum = list_r[i]
        c_sum = list_c[i]
        decrypted_sum = ECEG_decrypt(r_sum, c_sum, privKey)
        m = bruteECLog(decrypted_sum[0], decrypted_sum[1], p)
        print(f"{i} Sum of messages: {m}")
