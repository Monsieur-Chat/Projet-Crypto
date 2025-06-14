from rfc7748 import x25519, add, computeVcoordinate, mult
from Crypto.Hash import SHA256
import secrets  # Use this instead of random for cryptographically secure RNG
from algebra import mod_inv

p = 2**255 - 19
ORDER = 2**252 + 27742317777372353535851937790883648493

BaseU = 9
BaseV = computeVcoordinate(BaseU)

def Hash(message):
    h = SHA256.new(message)
    return int(h.hexdigest(), 16)

def ECDSA_generate_nonce():
    # Cryptographically secure random integer in [1..ORDER-1]
    return secrets.randbelow(ORDER - 1) + 1

def ECDSA_generate_keys():
    # Private key d in [1..ORDER-1]
    d = secrets.randbelow(ORDER - 1) + 1
    # Public key Q = d * G
    Q = mult(d, BaseU, BaseV, p)
    return d, Q

def ECDSA_sign(d, message):
    k = ECDSA_generate_nonce()
    h = Hash(message)
    # R = k * G, we take R.x-coordinate mod ORDER as r
    R = mult(k, BaseU, BaseV, p)[0]
    r = R % ORDER
    s = (mod_inv(k, ORDER) * (h + d * r)) % ORDER
    return r, s

def ECDSA_verify(Q, message, r, s):
    h = Hash(message)
    w = mod_inv(s, ORDER)
    u1 = (h * w) % ORDER
    u2 = (r * w) % ORDER
    u1g = mult(u1, BaseU, BaseV, p)
    u2Q = mult(u2, Q[0], Q[1], p)
    v = add(u1g[0], u1g[1], u2Q[0], u2Q[1], p)[0] % ORDER
    print(v)
    print(r)
    return v == r

if __name__ == "__main__":
    message = b"A very very important message !"
    x = 0xC841F4896FE86C971BEDBCF114A6CFD97E4454C9BE9ABA876D5A195995E2BA8
    Q = mult(x, BaseU, BaseV, p)
    r, s = ECDSA_sign(x, message)
    expected_r = 0x429146A1375614034C65C2B6A86B2FC4AEC00147F223CB2A7A22272D4A3FDD2
    expected_s = 0xF23BCDEBE2E0D8571D195A9B8A05364B14944032032EEEECD22A0F6E94F8F33

    is_valid = ECDSA_verify(Q, message, r, s)
    print(f"Generated r: {hex(r)}")
    print(f"Generated s: {hex(s)}")
    print(f"Expected r: {hex(expected_r)}")
    print(f"Expected s: {hex(expected_s)}")
    print(f"Signature valid: {is_valid}")
    print(r == expected_r, s == expected_s)
