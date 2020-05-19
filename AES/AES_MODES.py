# /usr/bin/python3.7
# -*- coding: utf-8 -*-
# Module request: AES_RAW(self)
# Author: w366er

from w366er_tool.AES import AES_RAW
"""
Description:
1. Implement of five main modes in block ciphers:
    - ECB(Electronic Code Book)
    - CBC(Block Cipher Chaining)
    - OFB(Output Feedback)
    - CFB(Cipher Feedback)
    - CTR/CM(Counter Mode)
2. The following codes use AES as an example of block cipher
3. Reference: 
    - https://en.wikipedia.org/wiki/Padding_(cryptography)
    - https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation
"""


def padding(s, mode="PKCS#7"):  # check pass
    """
    Padding for AES, here is two mode:
        - CMS mode, which pads with the same value as the number of padding bytes, Defined in RFC 5652, PKCS#5, PKCS#7
        (X.509 certificate) and RFC 1423 PEM.
        -Zero mode, which pads with \00

    Reference: https://asecuritysite.com/encryption/padding
    :param s: bytes that need to be padded  --> bytes
    :param mode: padding mode
    :return: padding result  --> bytes
    """
    pad_len = 16 - len(s) % 16
    if mode == "PKCS#7":
        s += bytes([pad_len]) * pad_len
    elif mode == "ZeroMode":
        s += b'\00' * pad_len
    else:
        raise ValueError("Invalid mode!")
    return s


def unpadding(s, mode="PKCS#7"):  # check pass
    """
    Unpadding for AES, here is two mode:
        - CMS mode
        - ZeroMode, implement is not written because it is difficult to distinguish the plaintext bytes
        and padding bytes

    :param s: bytes that need to be unpadded  --> bytes
    :param mode:  padding mode
    :return:  unpadding result
    """
    if mode == "PKCS#7":
        num = s[-1]
        if num > 16 or num < 0:  # check the last bytes
            raise ValueError("Invalid padding bytes!")
        s = s[:-num]
    elif mode == "ZeroMode":  # no implement for ZeroMode
        pass
    else:
        raise ValueError("Invalid mode!")
    return s


def encrypt_ECB_(plain_text, key, pad="PKCS#7"):  # check pass
    """
    Electronic Code Book Mode Encryption in AES

    :param plain_text:  plaintext that needed to be encrypted  --> bytes
    :param key:  AES key  --> bytes
    :param pad: padding mode  --> str
    :return:  cipher  --> bytes
    """
    plain_text = padding(plain_text, pad)
    cipher = b''
    for i in range(0, len(plain_text), 16):
        cipher += AES_RAW.new().encrypt(plain_text[i:i+16], key)
    return cipher


def decrypt_ECB_(cipher, key, pad="PKCS#7"):  # check pass
    """
    Electronic Code Book Mode Decryption in AES

    :param cipher:  cipher that needed to be decrypted  --> bytes
    :param key:  AES key --> bytes
    :param pad:  padding mode  --> str
    :return:  plaintext --> bytes
    """
    if len(cipher) % 16:  # check cipher length
        raise ValueError("Invalid cipher length!")
    plain_text = b''
    for i in range(0, len(cipher), 16):
        plain_text += AES_RAW.new().decrypt(cipher[i:i+16], key)
    plain_text = unpadding(plain_text, pad)
    return plain_text


def encrypt_CBC_(plain_text, key, IV, pad="PKCS#7"):  # check pass
    """
    Block Cipher Chaining Mode Encryption in AES

    :param plain_text:  plaintext that needed to be encrypted  --> bytes
    :param key:  AES key  --> bytes
    :param IV:  initial vector(16 bytes)  --> bytes
    :param pad: padding mode  --> str
    :return:  cipher --> bytes
    """
    if len(IV) != 16:  # check the IV length
        raise ValueError("Invalid IV!")
    plain_text = padding(plain_text, pad)
    cipher = b''
    v = IV
    for i in range(0, len(plain_text), 16):
        x = bytes([plain_text[i+b] ^ v[b] for b in range(16)])
        v = AES_RAW.new().encrypt(x, key)
        cipher += v
    return cipher


def decrypt_CBC_(cipher, key, IV, pad="PKCS#7"):  # check pass
    """
    Block Cipher ChainingMode Decryption in AES

    :param cipher: cipher that needed to be decrypted --> bytes
    :param key:  AES key  --> bytes
    :param IV: initial vector(16 bytes) --> bytes
    :param pad:  padding mode --> str
    :return:  plaintext  --> bytes
    """
    if len(IV) != 16:  # check the IV length
        raise ValueError("Invalid IV!")

    if len(cipher) % 16:  # check cipher length
        raise ValueError("Invalid cipher length!")
    plain_text = b''
    v = IV
    for i in range(0, len(cipher), 16):
        x = AES_RAW.new().decrypt(cipher[i:i+16], key)
        plain_text += bytes([x[b] ^ v[b] for b in range(16)])
        v = cipher[i:i+16]
    plain_text = unpadding(plain_text, pad)
    return plain_text


def encrypt_OFB_(plain_text, key, IV):  # check pass
    """
    Output Feedback Mode Encryption in AES

    * Attention:
        - OFB belongs to stream cipher mode, which can operate any size of plaintext and cipher,
        so there is no need for padding.
        - Whether in encryption or decryption in OFB mode, only AES_RAW encryption has been used.

    :param plain_text: plaintext that needed to be encrypted --> bytes
    :param key:  AES key  --> bytes
    :param IV:  initial vector(16 bytes)  --> bytes
    :return:  cipher  --> bytes
    """
    if len(IV) != 16:  # check the IV length
        raise ValueError("Invalid IV!")
    cipher = b''
    v = IV
    for i in range(0, len(plain_text), 16):  # check pass
        v = AES_RAW.new().encrypt(v, key)
        if i + 16 > len(plain_text):  # if the last block is incomplete
            x = plain_text[i:]
        else:
            x = plain_text[i:i+16]
        x = bytes([x[b] ^ v[b] for b in range(len(x))])
        cipher += x
    return cipher


def decrypt_OFB_(cipher, key, IV):  # check pass
    """
    Output Feedback Mode Decryption in AES

    :param cipher:  cipher that needed to be decrypted  --> bytes
    :param key: AES key  --> bytes
    :param IV:  initial vector(16 bytes)  --> bytes
    :return: plaintext --> bytes
    """
    if len(IV) != 16:  # check the IV length
        raise ValueError("Invalid IV!")

    plain_text = b''
    v = IV
    for i in range(0, len(cipher), 16):
        v = AES_RAW.new().encrypt(v, key)
        if i + 16 > len(cipher):  # if the last block is incomplete
            x = cipher[i:]
        else:
            x = cipher[i:i+16]
        x = bytes([x[b] ^ v[b] for b in range(len(x))])
        plain_text += x
    return plain_text


def encrypt_CFB_(plain_text, key, IV):  # check pass, but not the same as Crypto Package, confused...
    """
    Cipher Feedback Mode Encryption in AES

    * Attention(Very similar with OFB mode):
        - CFB belongs to stream cipher mode, which can operate any size of plaintext and cipher,
         so there is no need for padding.
        - Whether in encryption or decryption in CFB mode, only AES_RAW encryption has been used.

    :param plain_text:  plaintext that needed to be encrypted --> bytes
    :param key: AES key --> bytes
    :param IV:  initial vector(16 bytes)  --> bytes
    :return: cipher --> bytes
    """
    if len(IV) != 16:  # check the IV length
        raise ValueError("Invalid IV!")

    cipher = b''
    v = IV
    for i in range(0, len(plain_text), 16):  # check pass
        output = AES_RAW.new().encrypt(v, key)
        if i + 16 > len(plain_text):  # if the last block is incomplete
            x = plain_text[i:]
        else:
            x = plain_text[i:i+16]
        v = bytes([x[b] ^ output[b] for b in range(len(x))])
        cipher += v
    return cipher


def decrypt_CFB_(cipher, key, IV):  # check pass, but not the same as Crypto Package, confused...
    """
    Cipher Feedback Mode Decryption in AES

    :param cipher: cipher that needed to be decrypted  --> bytes
    :param key: AES key --> bytes
    :param IV:  initial vector(16 bytes)  --> bytes
    :return: plaintext  --> bytes
    """
    if len(IV) != 16:  # check the IV length
        raise ValueError("Invalid IV!")

    plain_text = b''
    v = IV
    for i in range(0, len(cipher), 16):
        output = AES_RAW.new().encrypt(v, key)
        if i + 16 > len(cipher):  # if the last block is incomplete
            v = cipher[i:]
        else:
            v = cipher[i:i+16]
        x = bytes([v[b] ^ output[b] for b in range(len(v))])
        plain_text += x
    return plain_text


def encrypt_CTR_(plain_text, key, IV):  # check pass
    """
    Counter Mode Encryption in AES, using increment-by-one method

    * Attention(Very similar with OFB mode):
        - CTR belongs to stream cipher mode, which can operate any size of plaintext and cipher,
         so there is no need for padding.
        - Whether in encryption or decryption in CTR mode, only AES_RAW encryption has been used.

    :param plain_text:  plaintext that needed to be encrypted  --> bytes
    :param key:  AES key  --> bytes
    :param IV:  fixed initial value/nonce(8 bytes)  --> bytes
    :return: cipher  --> bytes
    """
    if len(IV) != 8:  # check the IV length
        raise ValueError("Invalid IV!")

    counter = 0
    cipher = b''
    for i in range(0, len(plain_text), 16):
        v = IV + counter.to_bytes(8, 'big')
        output = AES_RAW.new().encrypt(v, key)
        if i + 16 > len(plain_text):  # if the last block is incomplete
            x = plain_text[i:]
        else:
            x = plain_text[i:i+16]
        x = bytes([x[b] ^ output[b] for b in range(len(x))])
        cipher += x
        counter += 1  # increment by one
    return cipher


def decrypt_CTR_(cipher, key, IV):  # check pass
    """
    Counter Mode Decryption in AES, using increment-by-one method

    :param cipher: cipher that need to be decrypted  --> bytes
    :param key: AES key  --> bytes
    :param IV: fixed initial vector/nonce(8 bytes)  --> bytes
    :return: plaintext --> bytes
    """
    if len(IV) != 8:  # check the IV length
        raise ValueError("Invalid IV!")

    counter = 0
    plain_text = b''
    for i in range(0, len(cipher), 16):
        v = IV + counter.to_bytes(8, 'big')
        output = AES_RAW.new().encrypt(v, key)
        if i + 16 > len(cipher):  # if the last block is incomplete
            x = cipher[i:]
        else:
            x = cipher[i:i+16]
        x = bytes([x[b] ^ output[b] for b in range(len(x))])
        plain_text += x
        counter += 1  # increment by one
    return plain_text


