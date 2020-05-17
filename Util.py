#! /usr/bin/python3.7
# -*- coding: utf-8 -*-
# Author: w366er

"""
Description:
1. Several common function in crypto.
    1. fore_8bits_padding
    2. str2bin and bin2str
    3. str2hex and hex2str
    4. Gaussian Elimination
"""


def fore_8bits_padding(s):
    """
    Padding bits string to 8*n bits long.

    :param s: bits string -> str
    :return: bits string -> str
    """
    return ''.join('0' for i in range((8 - len(s) % 8) % 8)) + s


def str2bin(s):
    """
    Invert string to bits string(without '0b')

    :param s: string -> str
    :return: bits string -> str
    """
    return ''.join(fore_8bits_padding(str(bin(ord(x))[2:])) for x in s)


def bin2str(s):
    """
    Invert bits string(without '0b') to string

    :param s: bits string -> str
    :return: string -> str
    """
    s = fore_8bits_padding(s)
    return ''.join(chr(int(s[8*i:8*i+8], 2)) for i in range(len(s) // 8))


def str2hex(s):
    """
    Invert string to hex string(without '0x')

    :param s: string -> str
    :return: hex string -> str
    """
    return bytes(s.encode()).hex()


def hex2str(s):
    """
    Invert hex string(without '0x') to string

    :param s: hex string -> str
    :return: string -> str
    """
    return bytes.fromhex(s)


def gmult(a, b):
    """
    Multiplication of GF(2^8)
    Reference: https://en.wikipedia.org/wiki/Finite_field_arithmetic#Rijndael's_(AES)_finite_field

    :param a:  Integer a --> int
    :param b:  Integer b --> int
    :return:  Multiplication result --> int
    """
    p = 0
    while a and b:
        if b & 0x1:
            p ^= a  # since we're in GF(2^m), addition is an XOR
        if a & 0x80:
            a = (a << 1) ^ 0x11b
        else:
            a <<= 1
        b >>= 1
    return p


def gaussian_elimination(A):
    """
    Solve m-unknown equations with gaussian elimination
    Source: https://martin-thoma.com/solving-linear-equations-with-gaussian-elimination/

    :param A: an m * (m + 1) matrix that needed to be solved -> list with two dimensions
    :return: result(following the sequence of unknowns) -> list
    """
    n = len(A)

    for i in range(n):
        # Search for maximum in this column
        maxEl = abs(A[i][i])
        maxRow = i
        for k in range(i + 1, n):
            if abs(A[k][i]) > maxEl:
                maxEl = abs(A[k][i])
                maxRow = k

        # Swap maximum row with current row (column by column)
        for k in range(i, n + 1):
            tmp = A[maxRow][k]
            A[maxRow][k] = A[i][k]
            A[i][k] = tmp

        # Make all rows below this one 0 in current column
        for k in range(i + 1, n):
            c = -A[k][i] / A[i][i]
            for j in range(i, n + 1):
                if i == j:
                    A[k][j] = 0
                else:
                    A[k][j] += c * A[i][j]

    # Solve equation Ax=b for an upper triangular matrix A
    x = [0 for i in range(n)]
    for i in range(n - 1, -1, -1):
        x[i] = A[i][n] / A[i][i]
        for k in range(i - 1, -1, -1):
            A[k][n] -= A[k][i] * x[i]
    return x
