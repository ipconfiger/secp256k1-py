import base64
from unittest import TestCase
from secp256k1py import secp256k1, functions


class TestMake_keypair(TestCase):
    def test_make_keypair(self):
        kp = secp256k1.make_keypair()
        str_pub = "%s" % kp.publicKey
        str_pri = "%s" % kp.privateKey
        print('pub: %s' % str_pub)
        print('pri: %s' % str_pri)
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

    def test_encrypt_data(self):
        remote_pub = secp256k1.PublicKey.restore('02f20657420110456cf533b440ead4ff6cce5d7d811c842adaf20c819a62d2e700')
        local_private = secp256k1.PrivateKey.restore('d0b677941482d74f0ad03c67aec5a1e4dfc9babe51e241aa4a3fc2981ba159c')
        raw_text = "test test test"
        enc = remote_pub.encrypt(local_private, raw_text.encode())
        print(enc)
        self.assertEqual(1, 1)


    def test_decrypt(self):
        data = 'MDIwN2IwYTMzOTA1OTY5YWU1MzU4MDM5OTFkMTgxMTQxNzA2ODE4OWI2NTIwODU1N2EwMzI1ZmQwNWY2N2U5NzcwUn+2p7pyQA=='
        priKey = secp256k1.PrivateKey.restore('1241ae561074f703c259da27036af3510640bbd6a79ceed7eaea4b3b566befe9')
        bytes_data = base64.decodebytes(data.encode())
        remote_pubkey = secp256k1.PublicKey.restore(bytes_data[:66].decode())
        print(f'r_key:{remote_pubkey}')
        b64_data = bytes_data[66:]
        print(f'd:{b64_data}')
        print(priKey.decrypt(remote_pubkey, b64_data, None))

    def test_encrypt(self):
        raw_txt = "哇卡里马戏打"
        pubKey = secp256k1.PublicKey.restore('02be8d8a7b5056de7a7074236100d094ebe86cce33d62469956203022af1f3e556')
        me = secp256k1.make_keypair()
        encrypted = pubKey.encrypt(me.privateKey, raw_txt.encode('utf8'), raw=True)
        data_arr = bytearray(str(me.publicKey).encode())
        data_arr.extend(encrypted['enc'])
        b64_str = base64.urlsafe_b64encode(data_arr).decode()
        print(f"message:{b64_str}")


    def test_encrypt_and_decrypt(self):
        alice = secp256k1.make_keypair()
        bob = secp256k1.make_keypair()
        raw_text = "快使用双节棍呵呵哈黑"
        enc = alice.publicKey.encrypt(bob.privateKey, raw_text.encode(), raw=True)
        print("enc:%s" % enc)

        res = bob.privateKey.decrypt(alice.publicKey, enc['enc'], None)

        self.assertEqual(raw_text, res)


    def test_remote(self):
        with open('/Users/alex/study/test.csv', 'r') as f:
            lines = f.readlines()
            for line in lines:
                pub_str, pri_str, origin_x, origin_y = line.strip().split(',')
                pubkey = secp256k1.PublicKey.restore(pub_str)
                prikey = secp256k1.PrivateKey.restore(pri_str)
                x, y = pubkey.Q
                restore_y = hex(y)[2:]
                restore_x = hex(x)[2:]
                self.assertEqual(origin_x, restore_x)
                self.assertEqual(origin_y, restore_y)



