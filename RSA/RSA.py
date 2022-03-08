#! /usr/bin/python3.7
# -*- coding: utf-8 -*-
# Module request: Util(self)
# Author: w366er

from w366er_tool import Util
import random
import math

"""
Description:
1. Implement of RSA Algorithm
2. Encryption and Decryption:
    - Encryption: c = m ^ e mod n
    - Decryption: m = c ^ d mod n
"""


class new:
    q = 0
    p = 0
    e = 0
    n = 0
    d = 0

    def __init__(self, n=0, e=0, d=0, p=0, q=0, show=False):
        """
        Initialisation, with two modes: given(e=e') or given(n=n', e=e', d=d'), p and q is not really require

        * Attention:
            - If parameters(n or e) are not given, it will be randomly generated.
        :param n: Modulus n --> int
        :param e: public key e  --> int
        :param d: private key d --> int
        :param p: prime number p  --> int
        :param q: prime number q --> int
        :param show: print the generated numbers --> boolean
        """
        if not(n and e and d):
            self.p = Util.get_prime(512)
            self.q = Util.get_prime(512)
            self.n = self.p * self.q
            phi = (self.p - 1) * (self.q - 1)
            self.e = 65537
            self.d = Util.extend_euclidean_algorithm(self.e, phi)[0] % phi
            if show:
                print("RSAkey: ")
                print("n: ", self.n)
                print("e: ", self.e)
                print("d: ", self.d) # fix here
                print("p: ", self.p)
                print("q: ", self.q)
        else:
            self.n = n
            self.e = e
            self.d = d
            self.p = p
            self.q = q

    def encrypt(self, plaintext, e=0, n=0):
        """
        RSA encryption

        :param plaintext:  plaintext that need to be encrypted  --> bytes
        :param e: public key --> int
        :param n: modulus  --> int
        :return:  cipher --> bytes
        """
        try:
            if e == 0 or n == 0:
                e = self.e
                n = self.n
        except:
            pass
        plaintext = int.from_bytes(plaintext, byteorder="big", signed=False)
        return Util.long_to_bytes(pow(plaintext, e, n))

    def decrypt(self, cipher, d=0, n=0):
        """
        RSA decryption

        :param cipher:  cipher that need to be decrypted  --> bytes
        :param d: private key  --> int
        :param n: modulus  --> int
        :return:  plaintext --> bytes
        """
        try:
            if d == 0 or n == 0:
                d = self.d
                n = self.n
        except:
            pass
        cipher = int.from_bytes(cipher, byteorder="big", signed=False)
        return Util.long_to_bytes(pow(cipher, d, n))

# Stop here rsa padding

