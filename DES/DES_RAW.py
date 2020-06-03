#! /usr/bin/python3.7
# -*- coding: utf-8 -*-
# Module request: Util(self)
# Author: w366er

"""
Description:
1. Implement of normal DES
2. About the f function
    1. Input: R_i, subkey_i
    2. Steps:
        1. Expansion Box
        2. XOR with the subkey
        3. S-box substitution
        4. Straight Permutation
"""


class new:
    def __init__(self, key):
        self.key_box = []
        self.shift_box = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
        self.drop_box = [57, 49, 41, 33, 25, 17, 9, 1,
                         58, 50, 42, 34, 26, 18, 10, 2,
                         59, 51, 43, 35, 27, 19, 11, 3,
                         60, 52, 44, 36, 63, 55, 47, 39,
                         31, 23, 15, 7, 62, 54, 46, 38,
                         30, 22, 14, 6, 61, 53, 45, 37,
                         29, 21, 13, 5, 28, 20, 12, 4
                         ]
        self.compression_box = [14, 17, 11, 24, 1, 5, 3, 28,
                                15, 6, 21, 10, 23, 19, 12, 4,
                                26, 8, 16, 7, 27, 20, 13, 2,
                                41, 52, 31, 37, 47, 55, 30, 40,
                                51, 45, 33, 48, 44, 49, 39, 56,
                                34, 53, 46, 42, 50, 36, 29, 32
                                ]
        self.initial_permutation_box = [58, 50, 42, 34, 26, 18, 10, 2,
                                        60, 52, 44, 36, 28, 20, 12, 4,
                                        62, 54, 46, 38, 30, 22, 14, 6,
                                        64, 56, 48, 40, 32, 24, 16, 8,
                                        57, 49, 41, 33, 25, 17, 9, 1,
                                        59, 51, 43, 35, 27, 19, 11, 3,
                                        61, 53, 45, 37, 29, 21, 13, 5,
                                        63, 55, 47, 39, 31, 23, 15, 7
                                        ]
        self.final_permutation_box = [40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
                                      38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
                                      36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
                                      34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25
                                      ]
        self.expansion_permutation_box = [32, 1, 2, 3, 4, 5,
                                          4, 5, 6, 7, 8, 9,
                                          8, 9, 10, 11, 12, 13,
                                          12, 13, 14, 15, 16, 17,
                                          16, 17, 18, 19, 20, 21,
                                          20, 21, 22, 23, 24, 25,
                                          24, 25, 26, 27, 28, 29,
                                          28, 29, 30, 31, 32, 1
                                          ]
        self.straight_permutation_box = [16, 7, 20, 21, 29, 12, 28, 17,
                                         1, 15, 23, 26, 5, 18, 31, 10,
                                         2, 8, 24, 14, 32, 27, 3, 9,
                                         19, 13, 30, 6, 22, 11, 4, 25
                                         ]
        self.s_box = [[[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
                       [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
                       [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
                       [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 00, 6, 13]
                       ],
                      [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
                       [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
                       [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
                       [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
                       ],
                      [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
                       [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
                       [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
                       [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
                       ],
                      [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
                       [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
                       [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
                       [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
                       ],
                      [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
                       [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
                       [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
                       [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
                       ],
                      [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
                       [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
                       [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
                       [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
                       ],
                      [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
                       [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
                       [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
                       [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
                       ],
                      [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
                       [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
                       [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
                       [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
                       ]
                      ]

        # Generate Round Keys
        self.generate_key(key)

    # Generate Key Function
    def generate_key(self, g_key):
        """
        generate 16 subkeys

        :param g_key: key, a 64 bits long hex string -> hex string
        :return: none
        """

        if len(g_key) != 16:
            exit("The key must be 64 bits long in hex.")

        # Change to 64-bit binary
        bin_key = bin(int(g_key, 16))[2:]
        for i in range(0, (64 - len(bin_key))):
            bin_key = "0" + bin_key

        # Drop the Parity Bits
        temp = ""
        for i in self.drop_box:
            temp += bin_key[i - 1]
        bin_key = temp

        # Get the Left and Right Key
        left_key = bin_key[0:28]
        right_key = bin_key[28:56]

        # Get 16 Rounds Keys
        for i in self.shift_box:

            # Circulation Shifting
            for j in range(i):
                temp = left_key[0]
                left_key = left_key[1:]
                left_key += temp
            for j in range(i):
                temp = right_key[0]
                right_key = right_key[1:]
                right_key += temp

            temp = left_key + right_key
            round_key = ""

            # Compression Box
            for j in self.compression_box:
                round_key += temp[j - 1]

            # Store the round key
            self.key_box.append(round_key)

    # Encryption
    def encrypt(self, plain):
        """
        DES encryption

        :param plain: plaintext that needed to be encrypted -> hex string
        :return: encryption result -> hex string
        """

        if len(plain) != 16:
            exit("The plaintext must be 64 bits long in hex.")

        cipher = ""

        # Change to 64-bit Binary
        bin_plaintext = bin(int(plain, 16))[2:]
        for i in range(0, (64 - len(bin_plaintext))):
            bin_plaintext = "0" + bin_plaintext

        # Initial Permutation
        temp = ""
        for i in self.initial_permutation_box:
            temp += bin_plaintext[i - 1]
        bin_plaintext = temp

        # Get the Left and Right Plaintext
        left_plaintext = bin_plaintext[0:32]
        right_plaintext = bin_plaintext[32:64]

        # Generate Cipher
        for i in range(16):
            # Store the Real Right_plaintext
            right_plaintext_r = right_plaintext

            # Expansion Permutation
            temp = ""
            for j in self.expansion_permutation_box:
                temp += right_plaintext[j - 1]
            right_plaintext = temp

            # ExclusiveOr With the Round Key
            round_key = self.key_box[i]
            temp = ""
            for j in range(len(right_plaintext)):
                temp += str(int(right_plaintext[j]) ^ int(round_key[j]))
            right_plaintext = temp

            # S-Box Function
            temp = ""
            for j in range(8):
                s_box = self.s_box[j]
                block = right_plaintext[j * 6:j * 6 + 6]
                row = int((block[0] + block[5]), 2)
                line = int((block[1] + block[2] + block[3] + block[4]), 2)
                temp1 = bin(s_box[row][line])[2:]
                for k in range(4 - len(temp1)):
                    temp1 = "0" + temp1
                temp += temp1
            right_plaintext = temp

            # Straight Permutation
            temp = ""
            for j in self.straight_permutation_box:
                temp += right_plaintext[j - 1]
            right_plaintext = temp

            # ExclusiveOr With the Left Plaintext
            temp = ""
            for j in range(len(right_plaintext)):
                temp += str(int(right_plaintext[j]) ^ int(left_plaintext[j]))

            # Swap the Right Plaintext and the Left Plaintext
            if i == 15:
                left_plaintext = temp
                right_plaintext = right_plaintext_r
                cipher = left_plaintext + right_plaintext
            else:
                left_plaintext = right_plaintext_r
                right_plaintext = temp

        # Final Permutation
        temp = ""
        for i in self.final_permutation_box:
            temp += cipher[i - 1]
        cipher = temp

        # padding into 64 bits
        cipher = hex(int(cipher, 2))[2:]
        for i in range(16 - len(cipher)):
            cipher = '0' + cipher

        return cipher

    # Decryption
    def decrypt(self, cipher):
        """
        DES decryption

        :param cipher: cipher that needed to be decrypted -> hex string
        :return: decryption result -> hex string
        """

        if len(cipher) != 16:
            exit("The cipher must be 64 bits long in hex.")

        plaintext = ""

        # Change to 64-bit Binary
        bin_cipher = bin(int(cipher, 16))[2:]
        for i in range(0, (64 - len(bin_cipher))):
            bin_cipher = "0" + bin_cipher

        # Initial Permutation
        temp = ""
        for i in self.initial_permutation_box:
            temp += bin_cipher[i - 1]
        bin_cipher = temp

        # Get the Left and Right Key
        left_cipher = bin_cipher[0:32]
        right_cipher = bin_cipher[32:64]

        # Decrypt the Cipher
        for i in range(16):
            # Store the Initial Right Cipher
            right_cipher_r = right_cipher

            # Expansion Permutation
            temp = ""
            for j in self.expansion_permutation_box:
                temp += right_cipher[j - 1]
            right_cipher = temp

            # ExclusiveOr With the Round Key
            round_key = self.key_box[16 - 1 - i]
            temp = ""
            for j in range(len(right_cipher)):
                temp += str(int(right_cipher[j]) ^ int(round_key[j]))
            right_cipher = temp

            # S-Box Function
            temp = ""
            for j in range(8):
                s_box = self.s_box[j]
                block = right_cipher[j * 6:j * 6 + 6]
                row = int((block[0] + block[5]), 2)
                line = int((block[1] + block[2] + block[3] + block[4]), 2)
                temp1 = bin(s_box[row][line])[2:]
                for k in range(4 - len(temp1)):
                    temp1 = "0" + temp1
                temp += temp1
            right_cipher = temp

            # Straight Permutation
            temp = ""
            for j in self.straight_permutation_box:
                temp += right_cipher[j - 1]
            right_cipher = temp

            # ExclusiveOr With the Left Plaintext
            temp = ""
            for j in range(len(right_cipher)):
                temp += str(int(right_cipher[j]) ^ int(left_cipher[j]))

            # Swap the Right Cipher and the Left Cipher
            if i == 15:
                left_cipher = temp
                right_cipher = right_cipher_r
                plaintext = left_cipher + right_cipher
            else:
                left_cipher = right_cipher_r
                right_cipher = temp

        # Final Permutation
        temp = ""
        for i in self.final_permutation_box:
            temp += plaintext[i - 1]
        plaintext = temp

        # padding into 64 bits
        plaintext = hex(int(plaintext, 2))[2:]
        for i in range(16 - len(plaintext)):
            plaintext = '0' + plaintext

        return plaintext


if __name__ == '__main__':
    gui = """
    ------------------------------------
    |   # DES Cipher GUI(2020)                |
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
            plaintext = input("Input your plaintext in hex: \n").strip()
            key = input("Input your key in hex: \n").strip()
            print("Your Result: ", new(key).encrypt(plaintext))
            print("____________________________________________")
        elif selection == '2':
            cipher = input("Input your cipher in hex: \n").strip()
            key = input("Input your key in hex: \n").strip()
            print("Your Result: ", new(key).decrypt(cipher))
            print("____________________________________________")
        elif selection == '3':
            print("Exit!")
            exit(0)
        else:
            exit("Invalid string!")


# Test:
# Key: AABB09182736CCDD
# Plaintext: 123456ABCD132536
# Cipher: c0b7a8d05f3a829c

