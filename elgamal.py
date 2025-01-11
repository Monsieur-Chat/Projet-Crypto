from algebra import mod_inv, int_to_bytes
from random import randint

PARAM_P = 0x87A8E61DB4B6663CFFBBD19C651959998CEEF608660DD0F25D2CEED4435E3B00E00DF8F1D61957D4FAF7DF4561B2AA3016C3D91134096FAA3BF4296D830E9A7C209E0C6497517ABD5A8A9D306BCF67ED91F9E6725B4758C022E0B1EF4275BF7B6C5BFC11D45F9088B941F54EB1E59BB8BC39A0BF12307F5C4FDB70C581B23F76B63ACAE1CAA6B7902D52526735488A0EF13C6D9A51BFA4AB3AD8347796524D8EF6A167B5A41825D967E144E5140564251CCACB83E6B486F6B3CA3F7971506026C0B857F689962856DED4010ABD0BE621C3A3960A54E710C375F26375D7014103A4B54330C198AF126116D2276E11715F693877FAD7EF09CADB094AE91E1A1597

PARAM_Q = 0x8CF83642A709A097B447997640129DA299B1A47D1EB3750BA308B0FE64F5FBD3

PARAM_G = 0x3FB32C9B73134D0B2E77506660EDBD484CA7B18F21EF205407F4793A1A0BA12510DBC15077BE463FFF4FED4AAC0BB555BE3A6C1B0C6B47B1BC3773BF7E8C6F62901228F8C28CBB18A55AE31341000A650196F931C77A57F2DDF463E5E9EC144B777DE62AAAB8A8628AC376D282D6ED3864E67982428EBC831D14348F6F2F9193B5045AF2767164E1DFC967C1FB3F2E55A4BD1BFFE83B9C80D052B985D182EA0ADB2A3B7313D3FE14C8484B1E052588B9B7D2BBD2DF016199ECD06E1557CD0915B3353BBB64E0EC377FD028370DF92B52C7891428CDC67EB6184B523D1DB246C32F63078490F00EF8D647D148D47954515E2327CFEF98C582664B4C0F6CC41659


class ElGamal:
    def __init__(self):
        super().__init__()

    def encrypt(self, message, pubKey):
        return EGM_encrypt(message, pubKey)

    def decrypt(self, cipher, privKey):
        return EG_decrypt(cipher[0], cipher[1], privKey)


def bruteLog(c, g, p):
    s = 1
    for i in range(p):
        if s == c:
            return i
        s = (s * g) % p
        if s == c:
            return i + 1
    return -1


def EG_generate_keys():
    private_key = randint(1, PARAM_Q - 1)
    public_key = pow(PARAM_G, private_key, PARAM_P)
    return private_key, public_key


def EGM_encrypt(message, public_key):
    # message_int = int.from_bytes(message.encode(), 'big')
    k = randint(1, PARAM_Q - 1)
    r = pow(PARAM_G, k, PARAM_P)
    c = (message * pow(public_key, k, PARAM_P)) % PARAM_P
    return r, c


def EGA_encrypt(message, public_key):
    # message_int = int.from_bytes(message.encode(), 'big')
    k = randint(1, PARAM_Q - 1)
    r = pow(PARAM_G, k, PARAM_P)
    c = (pow(PARAM_G, message, PARAM_P) * pow(public_key, k, PARAM_P)) % PARAM_P
    return r, c


def EG_decrypt(r, c, private_key):
    s = pow(r, private_key, PARAM_P)
    s_inv = mod_inv(s, PARAM_P)
    decrypted_message_int = (c * s_inv) % PARAM_P
    return decrypted_message_int


if __name__ == "__main__":
    private_key, public_key = EG_generate_keys()
    m1 = 0x2661B673F687C5C3142F806D500D2CE57B1182C9B25BFE4FA09529424B
    m2 = 0x1C1C871CAABCA15828CF08EE3AA3199000B94ED15E743C3
    r1, c1 = EGM_encrypt(m1, public_key)
    r2, c2 = EGM_encrypt(m2, public_key)

    m3 = int_to_bytes(EG_decrypt(r1 * r2, c1 * c2, private_key))
    print(m3)

    m1 = 1
    m2 = 0
    m3 = 1
    m4 = 1
    m5 = 0
    r1, c1 = EGA_encrypt(m1, public_key)
    r2, c2 = EGA_encrypt(m2, public_key)
    r3, c3 = EGA_encrypt(m3, public_key)
    r4, c4 = EGA_encrypt(m4, public_key)
    r5, c5 = EGA_encrypt(m5, public_key)

    m6 = EG_decrypt(r1 * r2 * r3 * r4 * r5, c1 * c2 * c3 * c4 * c5, private_key)
    print(bruteLog(m6, PARAM_G, PARAM_P))
