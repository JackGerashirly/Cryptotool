#! /usr/bin/python3.7
# -*- coding: utf-8 -*-
# Author: w366er
import math
import random

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


def bytes_to_long(by):
    """
    Invert bytes to long int

    :param by:  bytes --> bytes
    :return: integer --> int
    """
    return int.from_bytes(by, byteorder='big', signed=False)


def long_to_bytes(i):
    """
    Invert long int to bytes

    :param i: integer --> int
    :return: bytes  --> bytes
    """
    return i.to_bytes((i.bit_length() + 7) // 8, 'big')


def extend_euclidean_algorithm(a, b):
    """
    Extend Euclidean Algorithm, which finds out x, y satisfy: a*x + b*y = gcd(a, b)

    * Attention:
        - x is likely to be negative
    :param a: integer a  --> int
    :param b: integer b  --> int
    :return:  integer x  --> int
    :return:  integer y  --> int
    :return:  integer q, also the gcd(a, b)  --> int
    """
    if b == 0:
        return 1, 0, a
    else:
        x, y, q = extend_euclidean_algorithm(b, a % b)
        x, y = y, (x - (a // b) * y)
        return x, y, q


def gmult(a, b):
    """
    Multiplication of GF(2^8) in AES
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


def euler_phi(n):
    """
    Calculate the euler phi of n

    :param n:  integer n  --> int
    :return:  euler phi of n  --> int
    """
    m = int(math.sqrt(n + 0.5))
    ans = n
    for i in range(2, m+1):
        if n % i == 0:
            ans = ans / i * (i - 1)
        while n % i == 0:
            n /= i
    if n > 1:
        ans = ans / n * (n - 1)
    return int(ans)


def exponential_by_square(x, e):
    """
    Square and Multiply Algorithm(Left-to-Right)

    * Attention:
        - The exponent can not be negative.

    :param x:  base number  --> int
    :param e:  exponent  --> int
    :return:  result  --> int
    """
    if e < 0:
        raise ValueError("The exponent can not be negative!")
    if e == 0:
        return x
    else:
        l = bin(e)[3:]
        r = x
        for i in l:
            r *= r
            if i == '1':
                r *= x
        return r


def mod_exponential_by_square(x, e, m):
    """
    Square and Multiply Algorithm in Modular Arithmetic(Left-to-right)

    * Attention:
        - The exponent can not be negative

    :param x:  base number  --> int
    :param e:  exponential --> int
    :param m:  modulus  --> int
    :return:  result  --> int
    """

    if e < 0:
        raise ValueError("The exponential can not be negatvie")
    x = x % m
    if e == 0:
        return x
    else:
        l = bin(e)[3:]
        r = x
        for i in l:
            r = (r * r) % m
            if i == "1":
                r = (r * x) % m
        return r


def modular_root(k, b, m):
    """
    Calculate the k-th modular root if it exists

    :param k:  exponent of x  --> int
    :param b:  remain of (x^k mod m)  --> int
    :param m:  modulus  --> int
    :return:  base  --> int
    """
    phi_m = euler_phi(m)
    if math.gcd(b, m) != 1 and math.gcd(k, phi_m) != 1:
        raise ValueError("Can not figure out!")
    inv_k = extend_euclidean_algorithm(k, phi_m)[0]
    while inv_k < 0:  # fix inv_k
        inv_k += phi_m
    x = mod_exponential_by_square(b, inv_k, m)
    return x


def fermat_primality_test(p, t=100):
    """
    Fermat primality test

    * Attention:
        - It is likely that p is composite when the result is true(Carmichael Numbers)
        - There are approximately 600 Carmichael Numbers between 1-1000000000.
        - The accuracy is high in this test.

    :param p:  number that needed to be tested  --> int
    :param t:  test times(default time: 100)  --> int
    :return:  test result(true if it is a likely prime, false if it is composite)  --> bool
    """
    if p <= 0:
        raise ValueError("p must be positive!")
    if p in [1, 2, 3]:
        return True

    while t:
        i = random.randint(2, p - 1)
        if pow(i, p-1, p) != 1:
            return False
        t -= 1
    return True


def miller_rabin_primality_test(n, t=20):
    """
    Miller Rabin primality test

    * Attention:
        - Carmichael Numbers can be tested properly in this method.
        - The lager t is, the higher the accuracy is.

    :param n:  number that needed to be tested  --> int
    :param t:  test times(default time: 100)  --> int
    :return:  test result  --> int
    """
    if n <= 0:
        raise ValueError("n must be positive!")
    if n in [1, 2, 3]:
        return True

    if n % 2 == 0:
        return False

    k = 0
    q = n - 1
    while q & 1 == 0:
        k += 1
        q = q >> 1

    while t:
        a = random.randint(2, n - 1)
        i = pow(a, q, n)
        if i == 1:
            return True
        else:
            for j in range(1, k):
                i = pow(a, 2**j*q, n)
                if i == n - 1:
                    return True
        t -= 1
    return False


def get_prime(n):
    """
    Generate prime numbers

        :param n: the bits of the prime number  --> int
        :return: prime number --> int
        """
    while 1:
        a = random.getrandbits(n)
        if a & 1 != 0:
            if miller_rabin_primality_test(a):
                return a
