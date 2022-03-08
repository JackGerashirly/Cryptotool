#! /usr/bin/python3.7
# -*- coding:utf-8 -*-
# Author: w366er

"""
All attack methods of Caeser Cipher
1. Brute-force attack
"""

#
#
# Brute-force attack for shift cipher(Caeser cipher)
"""
Descriptions:
1. Key space: #K = 26(from 0 to 25), which is really small
"""


def brute_force_attack(cipher):
    for i in range(0, 26):
        print("shift = ", 26 - i)
        for p in cipher:
            if ord("a") <= ord(p) <= ord("z"):
                print(chr(ord("a") + (ord(p) - ord("a") + i) % 26), end="")
            elif ord("A") <= ord(p) <= ord("Z"):
                print(chr(ord("A") + (ord(p) - ord("A") + i) % 26), end="")
            else:
                print(p, end="")
        print("")


if __name__ == '__main__':
    cipher = input("Please input your cipher: \n")
    brute_force_attack(cipher)
