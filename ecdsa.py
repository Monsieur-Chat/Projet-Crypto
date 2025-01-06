from rfc7748 import x25519, add, computeVcoordinate, mult
from Crypto.Hash import SHA256
from random import randint
from algebra import mod_inv

p = 2**255 - 19
ORDER = (2**252 + 27742317777372353535851937790883648493)

BaseU = 9
BaseV = computeVcoordinate(BaseU)


def Hash(message):
    h = SHA256.new(message)
    return (int(h.hexdigest(), 16))

def ECDSA_generate_nonce():
    return randint(1, ORDER - 1)

def ECDSA_generate_keys():
    d = randint(1, ORDER - 1)
    Q = mult(d, BaseU, BaseV, p)
    return d, Q

def ECDSA_sign(d, message):
    k = ECDSA_generate_nonce()
    k = 0x2c92639dcf417afeae31e0f8fddc8e48b3e11d840523f54aaa97174221faee6
    R = mult(k, BaseU, BaseV, p)[0]
    r = R % ORDER
    h = Hash(message)
    s = (mod_inv(k, ORDER) * (h + d * r)) % ORDER
    return r, s
        #  x, y

def ECDSA_verify(Q, message, r, s):
    h = Hash(message)
    w = mod_inv(s, ORDER)
    u1 = (h * w) % ORDER
    u2 = (r * w) % ORDER
    u1g = mult(u1, BaseU, BaseV, p)
    u2Q = mult(u2, Q[0], Q[1], p)
    v = add(u1g[0], u1g[1], u2Q[0], u2Q[1], p)
    return v == r


if __name__ == "__main__":
    message = b"A very very important message !"
    x = 0xc841f4896fe86c971bedbcf114a6cfd97e4454c9be9aba876d5a195995e2ba8

    Q = mult(x, BaseU, BaseV, p)

    r, s = ECDSA_sign(x, message)

    expected_r = 0x429146a1375614034c65c2b6a86b2fc4aec00147f223cb2a7a22272d4a3fdd2
    expected_s = 0xf23bcdebe2e0d8571d195a9b8a05364b14944032032eeeecd22a0f6e94f8f33

    is_valid = ECDSA_verify(Q, message, r, s)

    print(f"Generated r: {hex(r)}")
    print(f"Generated s: {hex(s)}")
    print(f"Expected r: {hex(expected_r)}")
    print(f"Expected s: {hex(expected_s)}")
    print(f"Signature valid: {is_valid}")
    print(r == expected_r, s == expected_s)
