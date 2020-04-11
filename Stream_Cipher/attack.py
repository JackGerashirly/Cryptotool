#! /usr/bin/python3.7
# -*- coding: utf-8 -*-
# Module request: Util(self)
# Author: w366er
from w366er_tool import Util
from w366er_tool.Stream_Cipher import Stream_Cipher

# Contents
#
# Attack methods of Stream Cipher
"""
1. leak partial plaintext attack(LFSR)
"""


# 1st method
#
# leak partial plaintext attack(LFSR)
"""
Description:
1. cipher is known.
2. degree m(the numbers of flip-flops in LFSR) is known.
3. partial x_i has been leaked, i = 0, 1, 2, ..., (2m - 1).
"""


def leak_partial_plaintext_attack_lfsr(cipher, m, partial_x):
    """
    leak partial plaintext attack in LFSR

    :param cipher: -> cipher that needed to be broken -> string
    :param m: -> the number of flip-flops in LFSR -> int
    :param partial_x: -> high position bits of x -> bits string
    :return: -> attack result, plaintext -> string
    """
    temp_cipher = Util.str2bin(cipher)

    # recover key stream S
    S = [int(temp_cipher[i]) ^ int(partial_x[i]) for i in range(2 * m)]
    # construct equations(in a matrix form, directs like [S_m, S_{m-1}, ..., S_0] in a row)
    A = [[0 for j in range(m + 1)] for i in range(m)]
    A = [S[i:i+m+1] for i in range(m)]
    # solve the equations with gaussian elimination, recovering the taps
    taps = Util.gaussian_elimination(A)[::-1]
    taps = [int(i) % 2 for i in taps]
    # decrypt
    iv = S[:m][::-1]
    # test
    # print("iv:", iv)
    # print("taps:", taps)
    plain = Stream_Cipher.decrypt(cipher, iv, taps)
    return plain


if __name__ == '__main__':  # test sample
    m = 5
    taps = [1, 0, 1, 1, 1]
    iv = [1, 1, 0, 1, 0]
    plaintext = "flag{ilovegermany}"
    cipher = Stream_Cipher.encrypt(plaintext, iv, taps)
    partial_x = Util.str2bin(plaintext)[:2*m]
    recover_plain = leak_partial_plaintext_attack_lfsr(cipher, m, partial_x)
    print(recover_plain)
