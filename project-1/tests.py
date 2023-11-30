import sys
import nacl.utils
from nacl.public import PrivateKey, Box
from nacl import pwhash
from nacl.hash import blake2b, BLAKE2B_BYTES
from nacl.secret import SecretBox
from nacl.exceptions import CryptoError

# import nacl.encoding
# import nacl.utils
# from nacl.hash import blake2b

# msg = 16*b'256 BytesMessage'
# msg2 = 16*b'256 bytesMessage'

# auth_key = nacl.utils.random(size=64)
# # the simplest way to get a cryptographic quality auth_key
# # is to generate it with a cryptographic quality
# # random number generator

# auth1_key = nacl.utils.random(size=64)
# # generate a different key, just to show the mac is changed
# # both with changing messages and with changing keys

# mac0 = blake2b(msg, key=auth_key, encoder=nacl.encoding.HexEncoder)
# mac1 = blake2b(msg, key=auth1_key, encoder=nacl.encoding.HexEncoder)
# mac2 = blake2b(msg2, key=auth_key, encoder=nacl.encoding.HexEncoder)

# for i, mac in enumerate((mac0, mac1, mac2)):
#     print('Mac{0} is: {1}.'.format(i, mac))


# print('\n'.join(dir(pwhash)))
# kdf = pwhash.argon2i.kdf
# sys.exit()

# Generate Bob's private key, which must be kept secret
# skbob = PrivateKey.generate()

# # Bob's public key can be given to anyone wishing to send
# #   Bob an encrypted message
# pkbob = skbob.public_key

# # Alice does the same and then Alice and Bob exchange public keys
# skalice = PrivateKey.generate()
# pkalice = skalice.public_key

# # Bob wishes to send Alice an encrypted message so Bob must make a Box with
# #   his private key and Alice's public key
# bob_box = Box(skbob, pkalice)

# # This is our message to send, it must be a bytestring as Box will treat it
# #   as just a binary blob of data.
# message = b"This is our message to send, it must be a bytestring as Box will treat it"

# security_level_bytes = Box.NONCE_SIZE # == 24

# nonce = nacl.utils.random(security_level_bytes) # nonce HAS to be 24 bytes (Can't be 128 bits == 16 bytes)

# print(nonce)

# encrypted = bob_box.encrypt(message, nonce)

# print(encrypted)

# # Alice creates a second box with her private key to decrypt the message
# alice_box = Box(skalice, pkbob)

# # Decrypt our message, an exception will be raised if the encryption was
# #   tampered with or there was otherwise an error.
# plaintext = alice_box.decrypt(encrypted)
# print(plaintext.decode('utf-8'))

# print(type(pkbob))


def alice_sends_message(public_bob):

    # Step 2.a.1: Alice generates ephemeral key pair
    private_alice = PrivateKey.generate()
    public_alice = private_alice.public_key

    # Step 2.a.2: Alice and Bob derive a common secret using ECDH
    # secret_k1 = private_alice.exchange(public_bob)
    secret_k1 = Box(private_alice, public_bob).shared_key()
    print(secret_k1, len(secret_k1))
    
    # Step 2.a.3: Derive another key (secret_k2) using a Key Derivation Function (KDF)
    secret_k2 = blake2b(data=b'', key=secret_k1)
    secret_k2 = secret_k2[:32]
    print(secret_k2, len(secret_k2))

    # Step 2.a.4: Encrypt the message (attachment) using secret_k2
    cipher = SecretBox(secret_k2).encrypt(b"Hello, Bob!")

    # Step 2.a.5: Send the ciphertext, tag, and public_alice to Bob
    return cipher, public_alice

def bob_receives_message(cipher, public_alice, private_bob):
    # Step 2.b.2: Bob derives the common secret using ECDH
    # secret_k1 = private_bob.exchange(public_alice)
    secret_k1 = Box(private_bob, public_alice).shared_key()
    print(secret_k1, len(secret_k1))

    # Step 2.b.3: Derive the same key (secret_k2) using the same KDF
    secret_k2 = blake2b(data=b'', key=secret_k1)
    secret_k2 = secret_k2[:32]
    print(secret_k2, len(secret_k2))

    # Step 2.b.4: Decrypt the message using secret_k2
    try:
        decrypted_message = SecretBox(secret_k2).decrypt(cipher)
        print(f"Decrypted message: {decrypted_message.decode('utf-8')}")
    except CryptoError:
        print('rror: Message decryption failed.')

##################################################################


# Step 1: Bob generates key pair
private_bob = PrivateKey.generate()
public_bob = private_bob.public_key

# Alice sends a message to Bob
cipher, public_alice = alice_sends_message(public_bob)

# Bob receives and processes the message
bob_receives_message(cipher, public_alice, private_bob)