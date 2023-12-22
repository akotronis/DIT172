import sys

from nacl.bindings.utils import sodium_memcmp
from nacl.exceptions import CryptoError
from nacl.hash import blake2b
from nacl.public import PrivateKey, Box
from nacl.secret import SecretBox


class Person:
    def __init__(self, name):
        self.name = name.title()
        self.private = None
        self.public = None
        self.other_public = None
        self.common_secret = None
        self.derived_key = None
        self.encrypted_message =None
        self.message =None
        self.tag = None
        self.other_tag = None
        print(f'Hi I am {self.name}')

    def get_other_public(self, other_person):
        """
        Method that assigns to a person class instance
        as an attribute, the public key of another person
        """
        self.other_public = other_person.public
        print(f'{other_person.name}\'s public key: {self.other_public}')

    def make_key_pair(self):
        """
        Method that creates a private and a public key
        for the person class instance, via the `PrivateKey` class.
        Uses the Curve25519 algorithm which offers 128 bits of security
        and is designed for use with the elliptic curve Diffie–Hellman (ECDH)
        key agreement scheme.
        References:
        - https://pynacl.readthedocs.io/en/latest/public/#nacl.public.PrivateKey
        - https://en.wikipedia.org/wiki/Curve25519
        """
        self.private = PrivateKey.generate()
        self.public = self.private.public_key
        print(f'{self.name}\'s public key: {self.public}')
    
    def make_common_secret(self, other_person=None):
        """
        Method that uses the person class instance's private key
        and the public key of another person to create a shared key
        for this instance.
        References:
        - https://pynacl.readthedocs.io/en/latest/public/#nacl-public-box
        """
        other_public = self.other_public or other_person.public
        try:
            self.common_secret = Box(self.private, other_public).shared_key()
            print(f'{self.name} created the common secret: {self.common_secret}')
        except:
            print(f'I need my private key and {other_person.name}\'s pulic key')

    def make_derived_key(self):
        """
        Method that derives a key for the person class instance using
        the shared key instance's attribute
        References:
        - https://pynacl.readthedocs.io/en/latest/hashing/#key-derivation
        """
        derived_key = blake2b(data=b'', key=self.common_secret)
        # We truncate due to restriction of `SecretBox` class `key` kwarg
        self.derived_key = derived_key[:32]
        print(f'{self.name} created the derived key: {self.derived_key}')

    def make_message(self, message):
        """
        Method that encodes a message from input as an instance attribute
        """
        self.message = f'{message}'.encode()
        print(f'{self.name} created message: {self.message}')

    def encrypt_message(self):
        """
        Method that uses the instance's derived key to encrypt a message
        and store it as instance attribute using `SecretBox` class.
        `SecretBox` class:
        - it's input `key` must be 32 bytes
        - uses XSalsa20 stream cipher for encryption
        - include a 16 byte authenticator in encrypted message
          which is checked on decryption
          Authentication algorithm: Poly1305 MAC
        References:
        - https://pynacl.readthedocs.io/en/latest/secret/#example
        - https://libsodium.gitbook.io/doc/advanced/stream_ciphers/xsalsa20
        - https://pynacl.readthedocs.io/en/latest/secret/#reference
        - https://en.wikipedia.org/wiki/Poly1305
        """
        sbox = SecretBox(self.derived_key)
        self.encrypted_message = sbox.encrypt(self.message)
        print(f'{self.name}\'s encrypted message: {self.encrypted_message}')

    def make_tag(self):
        """
        Method that creates a tag instance attribute hashing
        an encrypted messge, used for integrity verification
        References:
        - https://pynacl.readthedocs.io/en/latest/hashing/#integrity-check-examples
        """
        self.tag = blake2b(self.encrypted_message)
        print(f'{self.name} created message integrity verification tag: {self.tag}')
    
    def get_requirements(self, encrypted_message, other_tag, other_public):
        """
        Method that gets required information from another person and
        stores it to class instance in order to perform integrity
        verification and decryption
        """
        self.encrypted_message = encrypted_message
        self.other_tag = other_tag
        self.other_public = other_public

    def verify_integrity(self):
        """
        Method that compares the tag of the class instance and another person's one
        to decide on message integrity
        References:
        - https://pynacl.readthedocs.io/en/latest/hashing/#integrity-check-examples
        """
        self.make_tag()
        tags_match = sodium_memcmp(self.other_tag, self.tag)
        if tags_match:
            print(f'Integrity verification SUCCESS')
        else:
            print(f'Integrity verification FAILED')
            sys.exit()
    
    def decrypt_message(self):
        """
        Method that uses the derived key of the class instance and
        an encrypted message received from another person and tries to
        decrypt it using `SecretBox` class
        References:
        - https://pynacl.readthedocs.io/en/latest/secret/#secret-key-encryption
        """
        try:
            decrypted_message = SecretBox(self.derived_key).decrypt(self.encrypted_message)
            self.message = decrypted_message
            print(f'{self.name}\'s SUCESSFULLY decrypted message: {self.message}')
        except CryptoError:
            print(f'ERROR: {self.name}\'s message decryption FAILED.')
            sys.exit()
        
#########################################################################################
#########################################################################################
#########################################################################################

print(f' BOB '.center(80, '='))
bob = Person('Bob')

# Bob makes key pair
bob.make_key_pair()

#########################################################################################

print(f' ALICE '.center(80, '='))
alice = Person('Alice')

# Alice gets Bob's public key
alice.get_other_public(bob)

# Alice makes key pair
alice.make_key_pair()

# Alice makes common secret
alice.make_common_secret()

# Alice makes derived key
alice.make_derived_key()

# Alice creates message
message = 'Hello Bob my friend!'
alice.make_message(message)

# Alice encrypts message
alice.encrypt_message()

# Alice creates verification tag
alice.make_tag()

#########################################################################################

################################################
# Change any of the below to test
# integrity verification failure
# alice.encrypted_message += b'!'
# alice.tag += b'!'
################################################

print(f' BOB '.center(80, '='))
# Bob takes requirements to decrypt message/verify integrity
bob.get_requirements(alice.encrypted_message, alice.tag, alice.public)

# Bob makes common key from Alice's public key
bob.make_common_secret(alice.public)
print(f'Is the same as Alices\'s?: {bob.common_secret == alice.common_secret}')

# Bob makes derived key
bob.make_derived_key()
print(f'Is the same as Alices\'s?: {bob.derived_key == alice.derived_key}')

# Bob verifies integrity of message sent by Alice
bob.verify_integrity()

# Bob decrypts message
bob.decrypt_message()