# coding=utf8

import base64
import hashlib
import random
import math
from os import urandom
from sys import version_info
import secp256k1py.functions
from salsa20 import Salsa20_xor


class PrivateKey():
    def __init__(self, _d):
        self.d = _d

    @classmethod
    def restore(cls, hex_str):
        if version_info.major != 2:
            return cls(int(hex_str, 16))
        else:
            return cls(long(hex_str, 16))

    def __repr__(self):
        if version_info.major != 2:
            return hex(self.d)[2:]
        else:
            return hex(self.d)[2:-1]

    def generate_secret(self, publickey):
        """
        生成共享秘密
        :param publickey:
        :return:
        """
        point = secp256k1py.functions.scalar_mult(self.d, publickey.Q)
        x, y = point
        if version_info.major != 2:
            secret = "%s%s" % (left_padding(hex(x)[2:], 64), left_padding(hex(y)[2:], 64))
        else:

            secret = "%s%s" % (left_padding(hex(x)[2:-1], 64), left_padding(hex(y)[2:-1], 64))
        return secret


    def sign(self, message):
        """
        签名消息
        :param message:
        :return:
        """
        point = secp256k1py.functions.sign_message(self.d, message)
        x, y = point
        if version_info.major != 2:
            return "%s%s" % (left_padding(hex(x)[2:], 64), left_padding(hex(y)[2:], 64))
        else:
            return "%s%s" % (left_padding(hex(x)[2:-1], 64), left_padding(hex(y)[2:-1], 64))

    def decrypt(self, publicKey, b64encrypted, b64iv):
        """
        解压数据
        :param publicKey:
        :param b64encrypted:
        :param b64iv:
        :return:
        """
        if version_info.major != 2:
            secret = self.generate_secret(publicKey)
        else:
            secret = self.generate_secret(publicKey)
        key, raw_iv = secret2key(secret)

        raw_enc_bytes = base64.urlsafe_b64decode(b64encrypted) if b64iv else b64encrypted

        iv = base64.urlsafe_b64decode(b64iv) if b64iv else raw_iv
        if version_info.major != 2:
            raw_bytes = Salsa20_xor(raw_enc_bytes, iv, key)
            return raw_bytes.decode('utf8')
        else:
            return Salsa20_xor(raw_enc_bytes, iv, key)


class PublicKey():
    def __init__(self, _q):
        self.Q = _q

    @classmethod
    def restore(cls, hex_str):
        if len(hex_str) < 128:
            hex_x = hex_str[2:]
            if version_info.major != 2:
                x = int(hex_x, 16)
            else:
                x = long(hex_x, 16)
            y = secp256k1py.functions.get_y_by_x(x, hex_str[:2])
        else:
            hex_x = hex_str[:64]
            hex_y = hex_str[64:]
            if version_info.major != 2:
                x = int(hex_x, 16)
                y = int(hex_y, 16)
            else:
                x = long(hex_x, 16)
                y = long(hex_y, 16)
        point = (
            x,y
        )
        return cls(point)

    def verify(self, message, signature):
        """
        对消息验签
        :param message:
        :param signature:
        :return:
        """
        if version_info.major != 2:
            point = (
                int(signature[:64], 16),
                int(signature[64:], 16)
            )
        else:
            point = (
                long(signature[:64], 16),
                long(signature[64:], 16)
            )
        return secp256k1py.functions.verify_signature(self.Q, message, point)


    def encrypt(self, privateKey, message, raw=False):
        """
        用共享秘密加密数据
        :param privateKey:
        :return:
        """
        if version_info.major != 2:
            secret = privateKey.generate_secret(self)
        else:
            secret = privateKey.generate_secret(self)
        key, iv = secret2key(secret)
        enc = Salsa20_xor(message, iv, key)
        b64_enc = enc if raw else base64.urlsafe_b64encode(enc)
        b64_iv = base64.urlsafe_b64encode(iv)
        if version_info.major != 2:
            return dict(
                enc=b64_enc if raw else b64_enc.decode(),
                iv=b64_iv.decode()
            )
        else:
            return dict(
                enc=b64_enc,
                iv=b64_iv
            )

    def __repr__(self):
        x, y = self.Q
        if secp256k1py.functions.testBit(y, 0):
            pc = '03'
        else:
            pc = '02'
        if version_info.major != 2:
            hex_x = hex(x)[2:]
            #hex_y = hex(y)[2:]

        else:
            hex_x = hex(x)[2:-1]
            #hex_y = hex(y)[2:-1]
        #return "%s%s" % (left_padding(hex_x, 64), left_padding(hex_y, 64))
        return '%s%s' % (pc, left_padding(hex_x, 64))

class KeyPair():
    def __init__(self, private, public):
        self.privateKey = private
        self.publicKey = public


def make_keypair():
    """Generates a random private-public key pair."""
    private_key = random.randrange(1, secp256k1py.functions.curve.n)
    public_key = secp256k1py.functions.scalar_mult(private_key, secp256k1py.functions.curve.g)
    return KeyPair(PrivateKey(private_key), PublicKey(public_key))


def left_padding(s, width):
    fill_data = '00000000000000000'
    fill_width = width - len(s)
    if fill_width:
        return '%s%s' % (fill_data[:fill_width], s)
    return s


def secret2key(secret):
    if version_info.major != 2:
        btarray = bytes.fromhex(secret)
    else:
        btarray = secret.decode('hex')
    return btarray[:32], btarray[32: 40]
