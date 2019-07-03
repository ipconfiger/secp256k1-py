from unittest import TestCase
from secp256k1py import secp256k1, functions


class TestMake_keypair(TestCase):
    def test_make_keypair(self):
        for i in range(10):
            kp = secp256k1.make_keypair()
            str_pub = "%s" % kp.publicKey
            print('pub:%s' % str_pub)
            pub = secp256k1.PublicKey.restore(str_pub)
            self.assertEqual(kp.publicKey.Q, pub.Q)


class TestECDH(TestCase):
    def test_generate_secret(self):
        for i in range(100):
            alice = secp256k1.make_keypair()
            alice_pub = secp256k1.PublicKey.restore("%s" % alice.publicKey)
            alice_pri = secp256k1.PrivateKey.restore("%s" % alice.privateKey)

            bob = secp256k1.make_keypair()
            bob_pub = secp256k1.PublicKey.restore('%s' % bob.publicKey)
            bob_pri = secp256k1.PrivateKey.restore('%s' % bob.privateKey)

            secret1 = alice_pri.generate_secret(bob_pub)
            secret2 = bob_pri.generate_secret(alice_pub)
            self.assertEqual(secret1, secret2)

    def test_sign_message(self):
        print(functions.inverse_mod(1000, 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f))
        self.assertEqual(1, 1)


    def test_remote(self):
        with open('/Users/alex/study/test.csv', 'r') as f:
            lines = f.readlines()
            for line in lines:
                pub_str, pri_str = line.split(',')
                pubkey = secp256k1.PublicKey.restore(pub_str)
                prikey = secp256k1.PrivateKey.restore(pri_str)
                raw_txt = 'test test test'
                sig = prikey.sign(raw_txt.encode())
                self.assertTrue(pubkey.verify(raw_txt.encode(), sig))



