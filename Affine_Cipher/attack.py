#! /usr/bin/python3.7
# -*- coding: utf-8 -*-
# Module request: gmpy2, Affine_Cipher(self)
# Author: w366er
from w366er_tool.Affine_Cipher import Affine_Cipher
import gmpy2

# Contents
#
# Attack methods of Affine Cipher
"""
1. Brute-force attack
2. Leak two groups of plaintext and cipher(alphabets)
"""


# GCD Function
def gcd(x, y):
    while y != 0:
        x, y = y, x % y
    return x


# 1st Method
#
# Brute-force attack for Affine Cipher
"""
Descriptions:
1. Key space:
#a = {1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25} ==> size = 12, because gcd(a, 26) == 1 and in modulo 26
#b = {0, 1, ..., 24, 25} ==> size = 26
#k = #a * #b = 312, which is really small
"""
# a space: size = 12
a_space = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]


def brute_force_attack(cipher):
    """
    brute force attack

    :param cipher: cipher that needed to be broken
    """
    for a in a_space:
        for b in range(26):
            key = [a, b]
            print("Key(a, b) = ", key)
            print(Affine_Cipher.decrypt(cipher, key))


# 2nd Method
#
# Leak two groups of plaintext and cipher
"""
Description:
1. If two groups of plaintext and cipher(both are alphabets) are leaked, we can solve the linear equations to get a and b.
2. Only works when gcd(x1 - x2, 26) = 1
"""


def leak_two_groups(x1, x2, y1, y2, cipher):
    """
    Leak two groups attack

    :param x1: plaintext of The 1st group, represents its position in alphabets(both lowercase and uppercase) -> int
    :param x2: plaintext of The 2nd group, represents its position in alphabets -> int
    :param y1: cipher of The 1st group, represents its position in alphabets -> int
    :param y2: cipher of The 2nd group, represents its position in alphabets -> int
    :param cipher: cipher that needed to be broken -> str
    :return: attack result -> str
    """
    dx = (x1 - x2) % 26
    # Judge dx
    if gcd(dx, 26) != 1:
        exit("dx is not prime with 26!")

    inv_dx = gmpy2.invert(dx, 26)
    a = inv_dx * (y1 - y2) % 26
    b = (y1 - x1 * a) % 26
    print(Affine_Cipher.decrypt(cipher, [a, b]))


if __name__ == '__main__': # test sample
    cipher = input("Please input your cipher: \n")
    brute_force_attack(cipher)
