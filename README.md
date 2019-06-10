# secp256k1-py
Python version secp256k1 keypair generator signature and verify, ecdh secret sharing, for human mind

## Useage:


#### Installation
    pip install secp256k1py

#### Generate Keypair

    from secp256k1py import secp256k1
    keypair = secp256k1.make_keypair()
    
#### ECDH Share a secret 

    from secp256k1py import secp256k1
    alice = secp256k1.make_keypair()
    bob = secp256k1.make_keypair()
    s1 = alice.privateKey.generate_secret(bob.publicKey)
    s2 = bob.privateKey.generate_secret(alice.publicKey)
    # s2 and s2 should be same
    

#### ECDSA sing message and verify

    from secp256k1py import secp256k1
    message = '12345678'
    alice = secp256k1.make_keypair()
    signature = alice.privateKey.sign(message)
    alice.publicKey.verify(message, signature) # will return True
    

#### ECC Cipher: encrypt and decrypt data use salsa20
 
    from secp256k1py import secp256k1
    alice = secp256k1.make_keypair()
    bob = secp256k1.make_keypair()
    message = "hi bob, i am alice"
    enc_data = bob.publicKey.encrypt(alice.privateKey, message) # alice say to bob return {'enc': encrypted base64 string, 'iv': base64 iv string}
    
    print bob.privateKey.decrypt(alice.publicKey, enc_data['enc'], enc_data['iv']) 
    # will print :  hi bob, i am alice  
    

    
#Enjoy it!