#! /usr/bin/python3.7
# -*- coding: utf-8 -*-
# Module request: Util(self)
# Author: w366er

from w366er_tool import Util

"""
Description:
1. Implement of Elgamal crypto system
2. Elgamal crypto system is based on Diffie Hellman Key Exchange
3. References: 
    - https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange
    - https://en.wikipedia.org/wiki/ElGamal_encryption
"""


def encrypt(plaintext, a, p, pub_key, i):
    """
    Elgamal Encryption

    * Attention:
        - i can not be re-used due to some security reasons

    :param plaintext: plaintext that needed to be encrypted --> bytes
    :param a: primitive element --> int
    :param p: large prime --> int
    :param pub_key: shared public key  --> int
    :param i:  i, which is used to compute ephemeral key  --> int
    :return:  cipher --> bytes
    """

    plaintext = Util.bytes_to_long(plaintext)
    ephem_key = pow(a, i, p)
    mask_key = pow(pub_key, i, p)
    return ephem_key, Util.long_to_bytes((mask_key * plaintext) % p)


def decrypt(cipher, ephem_key, d, p):
    """
    Elgamal Encryption

    :param cipher:  cipher that needed to be decrypted  --> bytes
    :param ephem_key:  ephemeral key  --> int
    :param d:  private key --> int
    :param p:  large prime  --> int
    :return:  plaintext --> int
    """

    cipher = Util.bytes_to_long(cipher)
    mask_key = pow(ephem_key, d, p)
    inv_mask_key = Util.extend_euclidean_algorithm(mask_key, p)[0] % p
    return Util.long_to_bytes((cipher * inv_mask_key) % p)


"""
# test
if __name__=="__main__":
    from w366er_tool import Util
    import random

    p = Util.get_prime(1024)
    print("p:", p)  # check
    a = random.randint(2, p - 2)
    print("a:", a)  # check
    d = random.randint(2, p - 2)
    print("d:", d)  # check
    pub = pow(a, d, p)
    i = random.randint(2, p - 2)
    print("i:", i)
    plaintext = b'flag{0bek-dfsd-23kf-xivh}'
    cipher = encrypt(plaintext, a, p, pub, i)
    print("cipher:", cipher)  # check
    print(decrypt(cipher[1], cipher[0], d, p))
"""

