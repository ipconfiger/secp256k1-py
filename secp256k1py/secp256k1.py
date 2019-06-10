# coding=utf8

import random
from secp256k1py.functions import *


class PrivateKey():
    def __init__(self, _d):
        self.d = _d

    @classmethod
    def restore(cls, hex_str):
        return cls(long(hex_str, 16))

    def __repr__(self):
        return hex(self.d)[2:-1]

    def generate_secret(self, publickey):
        """
        生成共享秘密
        :param publickey:
        :return:
        """
        point = scalar_mult(self.d, publickey.Q)
        x, y = point
        return "%s%s" % (hex(x)[2:-1], hex(y)[2:-1])

    def sign(self, message):
        """
        签名消息
        :param message:
        :return:
        """
        point = sign_message(self.d, message)
        x, y = point
        return "%s%s" % (hex(x)[2:-1], hex(y)[2:-1])



class PublicKey():
    def __init__(self, _q):
        self.Q = _q

    @classmethod
    def restore(cls, hex_str):
        point = (
            long(hex_str[:64], 16),
            long(hex_str[64:], 16)
        )
        return cls(point)

    def verify(self, message, signature):
        """
        对消息验签
        :param signature:
        :return:
        """
        point = (
            long(signature[:64], 16),
            long(signature[64:], 16)
        )
        return verify_signature(self.Q, message, point)

    def __repr__(self):
        x, y = self.Q
        return "%s%s" % (hex(x)[2:-1], hex(y)[2:-1])


class KeyPair():
    def __init__(self, private, public):
        self.privateKey = private
        self.publicKey = public


def make_keypair():
    """Generates a random private-public key pair."""
    private_key = random.randrange(1, curve.n)
    public_key = scalar_mult(private_key, curve.g)
    return KeyPair(PrivateKey(private_key), PublicKey(public_key))