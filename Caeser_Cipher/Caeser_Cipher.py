#! /usr/bin/python3.7
# -*- coding: utf-8 -*-
# Author: w366er
"""
Descriptions:
1. Implements of Caeser Cipher
2. Encryption and Decryption:
Let key in Z(26),
Encryption: e(x) = (x + key) mod 26
Decryption: d(y) = (x - key) mod 26
3. Caeser Cipher only works in alphabets.
"""


# Encryption
def encrypt(plain, key):
    """
    Caeser Cipher Encryption

    :param plain: plaintext needed to be encrypted -> str
    :param key: key in the encryption -> int
    :return: encryption result -> str
    """
    res = ""
    for p in plain:
        if ord('a') <= ord(p) <= ord('z'):
            res += chr((ord(p) - ord('a') + key) % 26 + ord('a'))
        elif ord('A') <= ord(p) <= ord('Z'):
            res += chr((ord(p) - ord('A') + key) % 26 + ord('A'))
        else:
            res += p
    return res


# Decryption
def decrypt(cipher, key):
    """
    Caeser Cipher Decryption

    :param cipher: cipher needed to be decrypted -> str
    :param key: key in the decryption -> int
    :return: decryption result -> str
    """
    res = ""
    for p in cipher:
        if ord('a') <= ord(p) <= ord('z'):
            res += chr((ord(p) - ord('a') - key) % 26 + ord('a'))
        elif ord('A') <= ord(p) <= ord('Z'):
            res += chr((ord(p) - ord('A') - key) % 26 + ord('A'))
        else:
            res += p
    return res


if __name__ == '__main__':
    gui = """
    ------------------------------------
    |   # Caeser Cipher GUI(2020)      |
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
            key = int(input("Input your key: \n").strip())
            print("Your Result: ", encrypt(plaintext, key))
            print("____________________________________________")
        elif selection == '2':
            cipher = input("Input your cipher: \n").strip()
            key = int(input("Input your key: \n").strip())
            print("Your Result: ", decrypt(cipher, key))
            print("____________________________________________")
        elif selection == '3':
            print("Exit!")
            exit(0)
        else:
            exit("Invalid string!")
