#! /usr/bin/python3
# -*- coding: utf-8 -*-
# Module request: 
# Author: w366er
import itertools

"""
Descritpions:
1. Implements of Vigenere Cipher

"""

def encrypt(plaintext,key):  # check pass
    cipher = ''
    key = key.lower()
    iterkey = itertools.cycle(key)
    for i,j in zip(plaintext,iterkey):
    # uppercase 65 - 90; lowercase 97 - 122
        a = ord(i)
        sign = ord(j) - 97
        if 65 <= a <= 90:
            a -= 65
            cipher += chr(((a + sign) % 26) + 65)
        elif 97 <= a <= 122:
            a -= 97
            cipher += chr(((a + sign) % 26) + 97)
        else:
            cipher += chr(a)
    return cipher


def decrypt(cipher,key):  # check pass
    plaintext = ''
    key = key.lower()
    iterkey = itertools.cycle(key)
    for i,j in zip(cipher,iterkey):
        a = ord(i)
        sign = ord(j) - 97
        if 65 <= a <= 90:
            a -= 65
            plaintext += chr(((a - sign) % 26) + 65)
        elif 97 <= a <= 122:
            a -= 97
            plaintext += chr(((a - sign) % 26) + 97)
        else:
            plaintext += chr(a)
    return plaintext



if __name__ == "__main__":
    gui = """
        ------------------------------------
        |   # Vigenere Cipher GUI(2020)      |
        |   Options:                       |
        |   1. Encrypt                     |
        |   2. Decrypt                     |
        |   3. Exit                        |
        ------------------------------------
Input your selection: """

    while True:
        print(gui)
        selection = str(input())

        if selection == '1':
            plaintext = raw_input("Input your plaintext: \n").strip()
            key = raw_input("Input your key: \n").strip()
            print("Your Result:", encrypt(plaintext, key))
            print("____________________________________________")
        elif selection == '2':
            cipher = raw_input("Input your cipher: \n").strip()
            key = raw_input("Input your key: \n").strip()
            print("Your Result:", decrypt(cipher, key))
            print("____________________________________________")
        elif selection == '3':
            print("Exit!")
            exit(0)
        else:
            exit("Invalid string!")

 