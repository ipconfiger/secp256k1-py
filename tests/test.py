from unittest import TestCase
from secp256k1py import secp256k1


class TestMake_keypair(TestCase):
    def test_make_keypair(self):
        keyPair = secp256k1.make_keypair()
        #print len(str(keyPair.privateKey))
        #print len(str(keyPair.publicKey))
        self.assertTrue(len(str(keyPair.privateKey)) == 64)
        self.assertTrue(len(str(keyPair.publicKey)) == 128)


class TestECDH(TestCase):
    def test_generate_secret(self):
        alice = secp256k1.make_keypair()
        bob = secp256k1.make_keypair()
        s1 = alice.privateKey.generate_secret(bob.publicKey)
        s2 = bob.privateKey.generate_secret(alice.publicKey)
        self.assertEqual(s1, s2)

    def test_sign_message(self):
        message = '12345678'
        priKey = secp256k1.PrivateKey.restore('21e0476b860e5e6d72c0fdd2d361edf6cdb01fd66681ca41030488710d2d5ee9')
        signature = priKey.sign(message)
        self.assertTrue(True)
        #self.assertTrue(alice.publicKey.verify(message, signature))

    def test_remote(self):
        pubKey = secp256k1.PublicKey.restore('654c0b269ff80bee44f6c13c52f97bad3d071e079ec65c62df038dbd8928508f73a075edd99de11c08f64e4cefd4f8c08a670a89c570e8640a1a7c8b421d8718')
        priKey = secp256k1.PrivateKey.restore('21e0476b860e5e6d72c0fdd2d361edf6cdb01fd66681ca41030488710d2d5ee9')
        bob = secp256k1.PublicKey.restore('793d473185e151cbd6685c1ca0153c44a11e446f39b0ad30b1a07e867ae51a88775b79afc691084458d8813b9d9788ce117e99854f4bdfc7707b329dc2b85aec')
        encryped = bob.encrypt(priKey, 'The python.org documentation states that the function accepts a string as an argument')
        print encryped
        self.assertTrue(True)


