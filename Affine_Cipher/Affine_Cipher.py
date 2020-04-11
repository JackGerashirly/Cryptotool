#! /usr/bin/python 3.7
# -*- coding: utf-8 -*-
# Module request: gmpy2
# Author: w366er
import gmpy2

"""
Descriptions:
1. Implements of Affine Cipher
2. Encryption and Decryption:
    Let a, b belongs to Z(26),
    Encryption: e(x) = (a * x + b) mod 26
    Decryption: d(y) = a^(-1) * (y - b) mod 26
    We need remind that gcd(a, 26) == 1
3. Affine Cipher only works in alphabets.
"""


# GCD Function
def gcd(x, y):
    while y != 0:
        x, y = y, x % y
    return x


# Encryption
def encrypt(plain, key):
    """
    Affine Cipher Encryption

    :param plain: plaintext needed to be encrypted -> str
    :param key: key in the encryption, consist of a and b -> tuple[a, b]
    :return: encryption result -> str
    """

    # Judge key(a)
    if gcd(key[0], 26) != 1:
        exit("a is not prime with 26 in your affine cipher!")

    a, b = key[0], key[1]
    res = ""
    for p in plain:
        if ord('a') <= ord(p) <= ord('z'):
            res += chr(((ord(p) - ord('a')) * a + b) % 26 + ord('a'))
        elif ord('A') <= ord(p) <= ord('Z'):
            res += chr(((ord(p) - ord('A')) * a + b) % 26 + ord('A'))
        else:
            res += p
    return res


# Decryption
def decrypt(cipher, key):
    """
    Affine Cipher Decryption

    :param cipher: cipher needed to be decrypted -> str
    :param key: key in the decryption, consist of a and b -> tuple[a, b]
    :return: decryption result -> str
    """

    # Judge key(a)
    if gcd(key[0], 26) != 1:
        exit("a is not prime with 26 in your affine cipher!")

    a, b = key[0], key[1]
    inv_a = gmpy2.invert(a, 26)
    res = ""
    for p in cipher:
        if ord('a') <= ord(p) <= ord('z'):
            res += chr((ord(p) - ord('a') - b) * inv_a % 26 + ord('a'))
        elif ord('A') <= ord(p) <= ord('Z'):
            res += chr((ord(p) - ord('A') - b) * inv_a % 26 + ord('A'))
        else:
            res += p
    return res


if __name__ == '__main__':
    gui = """
        ------------------------------------
        |   # Affine Cipher GUI(2020)      |
        |   Options:                       |
        |   1. Encrypt                     |
        |   2. Decrypt                     |
        |   3. Exit                        |
        ------------------------------------
Input your selection: """

    while True:
        print(gui)
        selection = input()

        if selection == '1':
            plaintext = input("Input your plaintext: \n").strip()
            a = int(input("Input your key(a): \n").strip())
            b = int(input("Input your key(b): \n").strip())
            key = [a, b]
            print("Your Result:", encrypt(plaintext, key))
            print("____________________________________________")
        elif selection == '2':
            cipher = input("Input your cipher: \n").strip()
            a = int(input("Input your key(a): \n").strip())
            b = int(input("Input your key(b): \n").strip())
            key = [a, b]
            print("Your Result:", decrypt(cipher, key))
            print("____________________________________________")
        elif selection == '3':
            print("Exit!")
            exit(0)
        else:
            exit("Invalid string!")
