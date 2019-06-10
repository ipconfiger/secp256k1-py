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
        alice = secp256k1.make_keypair()
        signature = alice.privateKey.sign(message)
        self.assertTrue(alice.publicKey.verify(message, signature))

