#! /usr/bin/python3.7
# -*- coding: utf-8 -*-
# Module request: Util(self)
# Author: w366er
from w366er_tool.Util import gmult
"""
Description:
1. Implement of normal AES-128, AES-192, AES-256
2. Including:
    1. Key Addition
    2. Bytes Substitution(S-box)
    3. Shift Rows
    4. Mix Columns
"""


class AES:
    def __init__(self):
        self.round_key_box = []
        self.s_box = [[0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76],
                      [0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0],
                      [0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15],
                      [0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75],
                      [0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84],
                      [0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf],
                      [0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8],
                      [0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2],
                      [0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73],
                      [0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb],
                      [0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79],
                      [0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08],
                      [0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a],
                      [0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e],
                      [0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf],
                      [0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]
                      ]
        self.inv_s_box = [[0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb],
                          [0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb],
                          [0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e],
                          [0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25],
                          [0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92],
                          [0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84],
                          [0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06],
                          [0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b],
                          [0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73],
                          [0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e],
                          [0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b],
                          [0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4],
                          [0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f],
                          [0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef],
                          [0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61],
                          [0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d]
                          ]
        self.rcon_box = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A, 0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A, 0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39]

    def generate_key(self, g_key, g_rounds):  # check pass
        """
        Generate subkeys for encryption and decryption, words by words.

        :param g_key: the initial given key
        :param g_rounds: rounds in the key schedule
        :return: no return
        """

        g_key = list(g_key)
        Ng_key = len(g_key) // 4
        self.round_key_box = [g_key[i:i+4] for i in range(0, 4*Ng_key, 4)]
        # check pass

        i = Ng_key
        while i < 4 * (g_rounds + 1):
            t = self.round_key_box[i - 1]
            if i % Ng_key == 0:  # g-function
                tt = self.Wsub(self.Wrot(t))
                t = [tt[0] ^ self.rcon_box[i // Ng_key]] + tt[1:]
            elif Ng_key > 6 and i % Ng_key == 4:  # 256-length key also have a h-function
                t = self.Wsub(t)
            self.round_key_box.append(self.Wxor(self.round_key_box[i - Ng_key], t))
            i += 1

    def Wsub(self, w):  # check pass
        """
        S-box substitution operation for words

        :param w: a 4-byte list --> list
        :return: S-box permutation result --> list
        """
        return [self.s_box[w[i] >> 4][w[i] & 0xf] for i in range(4)]

    def Wrot(self, w):  # check pass
        """
        Rotation in the key schedule, shift left by bytes.

        :param w: a 4-byte list --> list
        :return: rotation result --> list
        """
        return w[1:] + [w[0]]

    def Wxor(self, w1, w2):  # check pass
        """
        Xor two words in key schedule, bytes by bytes.

        :param w1: a 4-byte list --> list
        :param w2: a 4-byte list --> list
        :return: a 4-byte list --> list
        """
        return [w1[i] ^ w2[i] for i in range(4)]

    def AddRoundkey(self, s, k):  # check pass
        """
        Key addition layer

        :param s: a 16-byte list --> list
        :param k: the first sub key
        :return: no return
        """
        for i in range(16):
            s[i] ^= k[i]

    def BySub(self, s):  # check pass
        """
        S-box substitution layer

        :param s: a 16-byte list --> list
        :return: no return
        """
        for i in range(16):
            s[i] = self.s_box[s[i] >> 4][s[i] & 0xf]

    def InvBySub(self, s):  # check pass
        """
        Inverse of S-box substitution layer
        :param s: a 16-byte list --> list
        :return: no return
        """
        for i in range(16):
            s[i] = self.inv_s_box[s[i] >> 4][s[i] & 0xf]

    def ShiftRow(self, s):  # check pass
        """
        Shift Row layer

        :param s: a 16-byte list --> list
        :return: no return
        """
        s[:] = list(s[::5] + s[4::5] + s[3::5] + s[2::5] + s[1::5])

    def InvShiftRow(self, s):  # check pass
        """
        Inverse of shift row layer

        :param s: a 16-byte list --> list
        :return: no return
        """
        s[:] = [s[0], s[13], s[10], s[7], s[4], s[1], s[14], s[11], s[8], s[5], s[2], s[15], s[12], s[9], s[6], s[3]]

    def MixCol(self, s):  # check pass
        """
        Mix column layer

        :param s: a 16-byte list --> list
        :return: no return
        """
        for i in range(4):
            s[4 * i], s[4 * i + 1], s[4 * i + 2], s[4 * i + 3] = \
                gmult(0x02, s[4 * i]) ^ gmult(0x03, s[4 * i + 1]) ^ gmult(0x01, s[4 * i + 2]) ^ gmult(0x01, s[4 * i + 3]), \
                gmult(0x01, s[4 * i]) ^ gmult(0x02, s[4 * i + 1]) ^ gmult(0x03, s[4 * i + 2]) ^ gmult(0x01, s[4 * i + 3]), \
                gmult(0x01, s[4 * i]) ^ gmult(0x01, s[4 * i + 1]) ^ gmult(0x02, s[4 * i + 2]) ^ gmult(0x03, s[4 * i + 3]), \
                gmult(0x03, s[4 * i]) ^ gmult(0x01, s[4 * i + 1]) ^ gmult(0x01, s[4 * i + 2]) ^ gmult(0x02, s[4 * i + 3])

    def InvMixCol(self, s):  # check pass
        """
        Inverse of mix column layer

        :param s: a 16-byte list --> list
        :return:
        """
        for i in range(4):
            s[4 * i], s[4 * i + 1], s[4 * i + 2], s[4 * i + 3] = \
                gmult(0x0e, s[4 * i]) ^ gmult(0x0b, s[4 * i + 1]) ^ gmult(0x0d, s[4 * i + 2]) ^ gmult(0x09, s[4 * i + 3]), \
                gmult(0x09, s[4 * i]) ^ gmult(0x0e, s[4 * i + 1]) ^ gmult(0x0b, s[4 * i + 2]) ^ gmult(0x0d, s[4 * i + 3]), \
                gmult(0x0d, s[4 * i]) ^ gmult(0x09, s[4 * i + 1]) ^ gmult(0x0e, s[4 * i + 2]) ^ gmult(0x0b, s[4 * i + 3]), \
                gmult(0x0b, s[4 * i]) ^ gmult(0x0d, s[4 * i + 1]) ^ gmult(0x09, s[4 * i + 2]) ^ gmult(0x0e, s[4 * i + 3])

    def encrypt(self, plain_text, key):  # check pass
        """
        AES encryption

        :param plain_text: plain text that needed to be encrypted --> bytes
        :param key: the key, perhap 128/192/256 bits --> bytes
        :return: cipher --> bytes
        """
        # check key length
        if len(key) not in [16, 24, 32]:
            raise ValueError("Invalid key length")

        # Calculate number of rounds
        number_of_rounds = {16: 10, 24: 12, 32: 14}
        rounds = number_of_rounds[len(key)]

        # Generate Round Keys
        self.generate_key(key, rounds)
        # print(self.round_key_box)  # check pass

        # start encryption from here
        skey = self.round_key_box[0] + self.round_key_box[1] + self.round_key_box[2] + self.round_key_box[3]
        state = list(plain_text)
        self.AddRoundkey(state, skey)

        # (rounds - 1) rounds
        for r in range(1, rounds):
            self.BySub(state)
            self.ShiftRow(state)
            self.MixCol(state)
            skey = self.round_key_box[4 * r] + self.round_key_box[4 * r + 1] + self.round_key_box[4 * r + 2] + self.round_key_box[4 * r + 3]
            self.AddRoundkey(state, skey)

        # the last round
        self.BySub(state)
        self.ShiftRow(state)
        skey = self.round_key_box[-4] + self.round_key_box[-3] + self.round_key_box[-2] + self.round_key_box[-1]
        self.AddRoundkey(state, skey)

        return bytes(state)

    def decrypt(self, cipher, key):  # check pass
        """
        AES decryption

        :param cipher:  cipher that needed to be decrypted --> bytes
        :param key:  the key, perhaps 128/192/256 bits --> bytes
        :return: the plain text --> bytes
        """
        # check key length
        if len(key) not in [16, 24, 32]:
            raise ValueError("Invalid key length")

        # Calculate number of rounds
        number_of_rounds = {16: 10, 24: 12, 32: 14}
        rounds = number_of_rounds[len(key)]

        # Generate Round Keys
        self.generate_key(key, rounds)
        # print(self.round_key_box)  # check pass

        # start encryption from here
        skey = self.round_key_box[-4] + self.round_key_box[-3] + self.round_key_box[-2] + self.round_key_box[-1]
        state = list(cipher)
        self.AddRoundkey(state, skey)

        # (rounds - 1) rounds
        for r in range(1, rounds):
            self.InvShiftRow(state)
            self.InvBySub(state)
            skey = self.round_key_box[-4*r-4] + self.round_key_box[-4*r-3] + self.round_key_box[-4*r-2] + self.round_key_box[-4*r-1]
            self.AddRoundkey(state, skey)
            self.InvMixCol(state)

        # the last round
        self.InvShiftRow(state)
        self.InvBySub(state)
        skey = self.round_key_box[0] + self.round_key_box[1] + self.round_key_box[2] + self.round_key_box[3]
        self.AddRoundkey(state, skey)

        return bytes(state)


'''
# Input the Key and Plaintext
plain_text = b'2C\xf6\xa8\x88Z0\x8d11\x98\xa2\xe07\x074'  # bytes format
# 3243f6a8885a308d313198a2e0370734

key = b'+~\x15\x16(\xae\xd2\xa6\xab\xf7\x15\x88\t\xcfO<'
# 2b7e151628aed2a6abf7158809cf4f3c
me = AES()
cipher = me.encrypt(plain_text, key)  # check pass
print(cipher)
print(me.decrypt(cipher, key))

'''

# GUI
if __name__ == '__main__':
    gui = """
            ------------------------------------
            |   # AES Cipher ECB_MODE GUI(2020)|
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
            plaintext = input("Input your plaintext(str): \n").strip().encode()  # input only accepts string
            key = input("Input your key(str): \n").strip().encode()
            sys = AES()
            print("Your Result:", sys.encrypt(plaintext, key))  # return bytes format
            print("____________________________________________")
        elif selection == '2':
            cipher = input("Input your cipher(str): \n").strip().encode()
            key = input("Input your key(str): \n").strip().encode()
            sys = AES()
            print("Your Result:", sys.decrypt(cipher, key))
            print("____________________________________________")
        elif selection == '3':
            print("Exit!")
            exit(0)
        else:
            exit("Invalid string!")

