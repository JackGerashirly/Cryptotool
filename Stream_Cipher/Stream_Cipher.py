#! /usr/bin/python3.7
# -*- coding: utf-8 -*-
# Module request: Util(self)
# Author: w366er

from w366er_tool import Util

"""
Description:
1. Implement of Stream Cipher(with normal LFSRs)
2. Encryption and Decryption:
    Encryption: y_i = x_i + S_i mod 2
    Decryption: x_i = y_i + S_i mod 2
3. Key stream S is generated from LFSRs.
4. Stream Cipher encrypts bits by bits.
5. The key is at least as long as the plaintext.
6. p sequence is often decided by a primitive polynomial, p(x) = x^m + p_{m-1}*x^{m-1} + ... + p_0*x^{0}.
"""


# Linear Feedback Shift Register(LFSR)
def lfsr(iv, taps, length):
    """
    Implement of a simple LFSR

    :param iv: initial Value, put in a direction: [v_{m-1}, v_{m-2}, ..., v_{0}] (in reverse order to the pic) -> list
    :param taps: LFSR configuration(p sequence), also put in a direction: [p_{m-1}, p_{m-1}, ..., p_{0}] -> list
    :param length: the length of the plaintext , cipher or the length you actually want -> int
    :return: the key in stream cipher -> bits list
    """
    # Get the index of taps
    index = []
    for i in range(len(taps)):
        if taps[i]:
            index.append(i)

    state = iv.copy()
    key = []
    left_length = length
    while left_length > 0:
        feedback = 0
        # store the last one
        key.append(state[-1])
        # feedback
        for i in index:
            feedback ^= state[i]
        # shift
        state = [feedback] + state[:-1]
        # count length
        left_length -= 1
    return key


# Encryption
def encrypt(plain, iv, taps):
    """
    Stream Cipher Encryption

    :param plain: plaintext that needed to be encrypted -> string
    :param iv: initial value in LFSR, see more details with lfsr -> list
    :param taps: LFSR configuration(p sequence), see more details with lfsr -> list
    :return: encryption result
    """
    plain = Util.str2bin(plain)
    length = len(plain)
    key = lfsr(iv, taps, length)
    # print("Your key:", key)
    res = ''.join(str(int(p) ^ int(key[i])) for i, p in enumerate(plain))
    return Util.bin2str(res)


# Decryption
def decrypt(cipher, iv, taps):
    """
    Stream Cipher Decryption

    :param cipher: cipher that needed to be decrypted -> string
    :param iv: initial value in LFSR, see more details with lfsr -> list
    :param taps: LFSR configuration(p sequence), see more details with lfsr -> list
    :return:  decryption result
    """
    cipher = Util.str2bin(cipher)
    length = len(cipher)
    key = lfsr(iv, taps, length)
    # print("Your key:", key)
    res = ''.join(str(int(p) ^ int(key[i])) for i, p in enumerate(cipher))
    return Util.bin2str(res)


if __name__ == '__main__':
    gui = """
            ------------------------------------
            |   # Stream Cipher GUI(2020)      |
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
            # Input sample: 0, 0, 1
            iv = list(int(x.strip()) for x in input("Input the initial value of LFSR: \n").split(','))
            # Input sample: 0, 1, 1
            taps = list(int(x.strip()) for x in input("Input the LFSR configuration(p sequences): \n").split(','))
            print("Your Result:", encrypt(plaintext, iv, taps))
            print("____________________________________________")
        elif selection == '2':
            cipher = input("Input your cipher: \n").strip()
            # Input sample: 0, 0, 1
            iv = list(int(x.strip()) for x in input("Input the initial value of LFSR: \n").split(','))
            # Input sample: 0, 1, 1
            taps = list(int(x.strip()) for x in input("Input the LFSR configuration(p sequences): \n").split(','))
            print("Your Result:", decrypt(cipher, iv, taps))
            print("____________________________________________")
        elif selection == '3':
            print("Exit!")
            exit(0)
        else:
            exit("Invalid string!")
