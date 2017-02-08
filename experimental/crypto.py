"""Crypto functions for implementing your secure file store client.

.. note::
    **Do not change any code in this file!**
"""

import os
from binascii import hexlify, unhexlify

from Crypto.Cipher import AES, ARC2, ARC4, Blowfish, CAST, DES, DES3, XOR
from Crypto.Hash import MD2, MD4, MD5, RIPEMD, SHA, SHA224, SHA256, SHA384, \
    SHA512
from Crypto.Cipher.blockalgo import MODE_ECB, MODE_CBC, MODE_CFB, MODE_OFB, \
    MODE_CTR

from Crypto.Hash import HMAC
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_PSS
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Util import Counter

# Set of block ciphers you can pick from.
name_to_cipher = {
    'AES': AES.new,
    'ARC2': ARC2.new,
    'ARC4': ARC4.new,
    'Blowfish': Blowfish.new,
    'CAST': CAST.new,
    'DES': DES.new,
    'DES3': DES3.new,
    'XOR': XOR.new
}

# Set of hash functions you can choose from.
name_to_hash = {
    'MD2': MD2.MD2Hash,
    'MD4': MD4.MD4Hash,
    'MD5': MD5.MD5Hash,
    'RIPEMEND': RIPEMD.RIPEMD160Hash,
    'SHA': SHA.SHA1Hash,
    'SHA224': SHA224.SHA224Hash,
    'SHA256': SHA256.SHA256Hash,
    'SHA384': SHA384.SHA384Hash,
    'SHA512': SHA512.SHA512Hash
}

# Set of block cipher modes of operation you can choose from.
name_to_mode = {
    'ECB': MODE_ECB,
    'CBC': MODE_CBC,
    'CFB': MODE_CFB,
    'OFB': MODE_OFB,
    'CTR': MODE_CTR
}


class CryptoError(RuntimeError):
    """An error which will be raised if anything happens wrong in any of the
    cryptographic methods.

    A CryptoError is raised when a function is called with invalid parameters
    (such as an invalid ciphername), or is called with the wrong types of
    arguments (not string for message, ciphertext, or symmetric key), or when
    an operation fails (such as trying to unpad an invalid padding).
    """
    pass


class Crypto(object):
    """A class grouping together all of the Crypto API functions.

    We provide a set of symmetric key ciphers, block cipher modes of operation,
    and cryptographic hash functions to select from. You must pass the name of
    the cipher, mode, or function you desire to the respective methods in the
    API. These names are defined in the dictionaries ``name_to_cipher``,
    ``name_to_mode``, and ``name_to_hash``.

    Ciphers:
        'AES', 'ARC2', 'ARC4', 'Blowfish', 'CAST', 'DES', 'DES3', 'XOR'

        See the PyCrypto `Cipher package
        <https://pythonhosted.org/pycrypto/Crypto.Cipher-module.html>`_
        for more details.

    Modes:
        'ECB', 'CBC', 'CFB', 'OFB', 'CTR'

        See the PyCrypto `blockalgo module
        <https://pythonhosted.org/pycrypto/Crypto.Cipher.blockalgo-module.html>`_
        for more details.

    Hash Functions:
        'MD2', 'MD4', 'MD5', 'RIPEMD', 'SHA', 'SHA224', 'SHA256',
        'SHA384', 'SHA512'

        See the PyCrypto `Hash package
        <https://pythonhosted.org/pycrypto/Crypto.Hash-module.html>`_
        for more details.
    """
    def __init__(self):
        """You should never have to create a new Crypto object yourself from
        within the Client class. You should assume that it will be passed to
        the Client's constructor automatically. You should store it and use it."""
        pass

    #####################
    # Utility Functions #
    #####################
    def get_random_bytes(self, n):
        """Returns n bytes of cryptographically-strong randomness, as a
        hex-encoded string.

        Uses the underlying PyCrypto Random package. Under the hood, this will
        read random bytes from the OS-provided RNG. On POSIX, this is
        /dev/urandom. On Windows, this is CryptGenRandom.

        This method is secure for cryptographic use. You should use it when you
        need a secure source of randomness. Or, you can simply use it always
        when you need randomness.

        :params int n: Number of random bytes to generate.
        :returns: n cryptographically-strong random bytes, as a hex-encoded
            string
        :rtype: str
        """
        return _bytes_to_hex(Random.new().read(n))

    def new_counter(self, nbits, initial_value=1, prefix='', suffix=''):
        """A fast counter implementation for use with block ciphers in CTR mode.

        See the PyCrypto `Counter module
        <https://pythonhosted.org/pycrypto/Crypto.Util.Counter-module.html>`_
        for more information about the underlying implementation.

        To use with :meth:`crypto.Crypto.symmetric_encrypt` and
        :meth:`crypto.Crypto.symmetric_decrypt`, use this method to create a
        new Counter object and pass it as the `counter` argument.

        :param int nbits: Length of the desired counter, in bits. It must be a
            multiple of 8.
        :param int initial_value: The initial value of the counter. Default
            value is 1.
        :param str prefix: The constant prefix of the counter block.
            A hex-encoded string of bytes.
            By default, no prefix is used.
        :param str suffix: The constant suffix of the counter block.
            A hex-encoded string of bytes.
            By default, no suffix is used.
        :returns: A new stateful counter callable object.
        """
        prefix_bytes = _hex_to_bytes(prefix)
        suffix_bytes = _hex_to_bytes(suffix)
        return Counter.new(nbits, initial_value=initial_value,
                           prefix=prefix_bytes, suffix=suffix_bytes)

    ##############################
    # Symmetric crypto functions #
    ##############################

    def symmetric_encrypt(self, message, key, cipher_name=None,
                          mode_name='ECB', IV=None, iv=None,
                          counter=None, ctr=None,
                          segment_size=None, **kwargs):
        """Encrypt data with the key for the chosen parameters.

        You must select a cipher name from the table name_to_cipher.
        You must provide all parameters required for your chosen cipher.

        This function will automatically pad the message to a multiple of the
        block size.

        Remember, symmetric keys can be simply random bytes.

        See PyCrypto `BlockAlgo class
        <https://pythonhosted.org/pycrypto/Crypto.Cipher.blockalgo.BlockAlgo-class.html>`_
        for more information about the underlying implementation.

        :param str message: The piece of data to encrypt.
        :param str key: The secret key to use in the symmetric cipher.
            Length varies depending on the cipher chosen. A string containing
            the hex-encoded bytes of the key.
        :param str cipher_name: Cipher to use, chosen from name_to_cipher
            table.
        :param str mode_name: Block mode of operation to use, chosen from
            name_to_mode table. Defaults to EBC mode.
        :param str IV: The initialization vector to use for encryption
            or decryption. It is ignored for MODE_ECB and MODE_CTR.
            For all other modes, it must be block_size bytes longs. Optional --
            when not present it will be given a default value of all zeroes.
            A string containing the hex-encoded bytes of the IV.
        :param callable counter: (Only MODE_CTR) A stateful function that
            returns the next counter block, which is a byte string of
            block_size bytes.
            It is recommended to use :meth:`crypto.Crypto.new_counter` to
            create a new counter object to pass as the parameter.
        :param int segment_size: (Only MODE_CFB) The number of bits the
            plaintext and ciphertext are segmented in.
            It must be a multiple of 8. If 0 or not specified, it will be
            assumed to be 8.

        :returns: the encrypted data
        :rtype: str, as long as the plaintext

        :raises CryptoError: If the cipher or mode name is invalid, or if
            message or key are not a strings.
        """
        if not isinstance(message, str):
            raise CryptoError("Message must be a string")
        if cipher_name not in name_to_cipher:
            raise CryptoError("Cipher not known " + str(cipher_name))
        if mode_name not in name_to_mode:
            raise CryptoError("Mode not known " + str(cipher_name))
        if IV:
            kwargs['IV'] = _hex_to_bytes(IV)
        elif iv:
            kwargs['IV'] = _hex_to_bytes(iv)
        else:
            kwargs['IV'] = b'0'*16
        if counter:
            kwargs['counter'] = counter
        elif ctr:
            kwargs['counter'] = ctr
        if segment_size:
            kwargs['segment_size'] = segment_size

        message_bytes = _string_to_bytes(message)
        message_bytes = self._pad(message_bytes, 16)
        key_bytes = _hex_to_bytes(key)
        mode = name_to_mode[mode_name]
        cipher = name_to_cipher[cipher_name](key_bytes, mode, **kwargs)
        return _bytes_to_hex(cipher.encrypt(message_bytes))

    def symmetric_decrypt(self, ciphertext, key, cipher_name=None,
                          mode_name='ECB', IV=None, iv=None,
                          counter=None, ctr=None,
                          segment_size=None, **kwargs):
        """Decrypt data with the key for the chosen parameters.

        You must select a cipher name from the table name_to_cipher.
        You must provide all parameters required for your chosen cipher.

        This function will automatically unpad the decrypted message.

        See PyCrypto `BlockAlgo class
        <https://pythonhosted.org/pycrypto/Crypto.Cipher.blockalgo.BlockAlgo-class.html>`_
        for more information about the underlying implementation.

        :param str ciphertext: The piece of data to decrypt.
        :param str key: The secret key to use in the symmetric cipher.
            Length varies depending on the cipher chosen. A string containing
            the hex-encoded bytes of the key.
        :param str cipher_name: Cipher to use, chosen from name_to_cipher
            table.
        :param str mode_name: Block mode of operation to use, chosen from
            name_to_mode table. Defaults to EBC mode.
        :param str IV: The initialization vector to use for encryption
            or decryption. It is ignored for MODE_ECB and MODE_CTR.
            For all other modes, it must be block_size bytes longs. Optional --
            when not present it will be given a default value of all zeroes.
            A string containing the hex-encoded bytes of the IV.
        :param callable counter: (Only MODE_CTR) A stateful function that
            returns the next counter block, which is a byte string of
            block_size bytes.
            It is recommended to use :meth:`crypto.Crypto.new_counter` to
            create a new counter object to pass as the parameter.
        :param int segment_size: (Only MODE_CFB) The number of bits the
            plaintext and ciphertext are segmented in.
            It must be a multiple of 8. If 0 or not specified, it will be
            assumed to be 8.

        :returns: the decrypted data
        :rtype: str

        :raises CryptoError: If the cipher or mode name is invalid, or the
            unpadding fails, or if ciphertext or key are not a strings.
        """
        if not isinstance(ciphertext, str):
            raise CryptoError("Ciphertext must be a string")
        if cipher_name not in name_to_cipher:
            raise CryptoError("Cipher not known")
        if mode_name not in name_to_mode:
            raise CryptoError("Mode not known")
        if IV:
            kwargs['IV'] = _hex_to_bytes(IV)
        elif iv:
            kwargs['IV'] = _hex_to_bytes(iv)
        else:
            kwargs['IV'] = b'0'*16
        if counter:
            kwargs['counter'] = counter
        elif ctr:
            kwargs['counter'] = ctr
        if segment_size:
            kwargs['segment_size'] = segment_size

        ciphertext_bytes = _hex_to_bytes(ciphertext)
        key_bytes = _hex_to_bytes(key)
        mode = name_to_mode[mode_name]
        cipher = name_to_cipher[cipher_name](key_bytes, mode, **kwargs)
        message = self._unpad(cipher.decrypt(ciphertext_bytes))
        return _bytes_to_string(message)

    def cryptographic_hash(self, message, hash_name=None):
        """Generates the printable digest of message using the named hash function.

        See the PyCrypto `HashAlgo class
        <https://pythonhosted.org/pycrypto/Crypto.Hash.hashalgo.HashAlgo-class.html>`_
        for more information about the underlying implementation.

        :param str message: The message to hash.
        :param str hash_name: Hash to use, chosen from name_to_hash table.

        :returns: The digest, a string of 2*digest_size characters.
            Contains only hexadecimal digits.
        :rtype: str

        :raises CryptoError: If name of hash is invalid, or message is not a
            string.
        """
        if not isinstance(message, str):
            raise CryptoError("Message must be a string")
        if hash_name not in name_to_hash:
            raise CryptoError("Hash not known.")
        message_bytes = _string_to_bytes(message)
        return name_to_hash[hash_name](message_bytes).hexdigest()

    def message_authentication_code(self, message, key, hash_name=None):
        """Generates the printable MAC of the message.

        This uses an HMAC, so you must provide the hash function to use, chosen
        from the name_to_hash table.

        See the PyCrypto `HMAC module
        <https://pythonhosted.org/pycrypto/Crypto.Hash.HMAC-module.html>`_
        for more information about the underlying implementation.

        :param str message: The message to authenticate.
        :param str key: Key for the MAC. A string containing
            the hex-encoded bytes of the key.
        :param str hash_name: Hash to use, chosen from name_to_hash table.

        :returns: The authentication tag, a string of 2*digest_size bytes.
            Contains only hexadecimal digits.
        :rtype: str

        :raises CryptoError: If name of hash is invalid, or if the key or
            message are not strings.
        """
        if not isinstance(key, str):
            raise CryptoError("Key must be a string")
        if not isinstance(message, str):
            raise CryptoError("Message must be a string")
        if hash_name not in name_to_hash:
            raise CryptoError("Hash not known")
        hashAlgo = name_to_hash[hash_name]
        key_bytes = _hex_to_bytes(key)
        message_bytes = _string_to_bytes(message)
        return HMAC.HMAC(key_bytes, msg=message_bytes,
                         digestmod=hashAlgo()).hexdigest()

    ###############################
    # Asymmetric crypto functions #
    ###############################

    def asymmetric_encrypt(self, message, public_key):
        """Produce the PKCS#1 OAEP encryption of the message.

        See the PyCrypto `PKCS1_OAEP module
        <https://pythonhosted.org/pycrypto/Crypto.Cipher.PKCS1_OAEP-module.html>`_
        for more information about the underlying implementation.
        PKCS#1 OAEP is a secure public-key encryption scheme -- it is
        semantically secure against adaptive chosen-ciphertext attacks.

        :param message: The message to encrypt.
            It can be of variable length, but not longer than the RSA modulus
            (in bytes) minus 2, minus twice the hash output size (64 bytes).
            For 2048 bit keys, this gives 2048/8-2-64 = 190 bytes.
        :type message: str or bytes
        :param public_key: The public key to encrypt with.
        :type public_key: An RSA key object

        :returns: The ciphertext in which the message is encrypted.
        :rtype: str

        :raises CryptoError: If message is not a string.

        :raises ValueError: If the RSA key length is not sufficiently long to
            deal with the given message.
        """
        if not isinstance(message, str):
            raise CryptoError("Message must be a string")

        message_bytes = _string_to_bytes(message)
        cipher = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)
        return _bytes_to_hex(cipher.encrypt(message_bytes))

    def asymmetric_decrypt(self, ciphertext, private_key):
        """Produce the PKCS#1 OAEP decryption of the ciphertext.

        See the PyCrypto `PKCS1_OAEP module
        <https://pythonhosted.org/pycrypto/Crypto.Cipher.PKCS1_OAEP-module.html>`_
        for more information about the underlying implementation.

        :param str ciphertext: The ciphertext that contains the message
            to recover.
        :param private_key: The private key to decrypt with.
        :type private_key: An RSA key object

        :returns: The original message
        :rtype: str

        :raises CryptoError: If the decryption fails.
        """
        cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
        try:
            ciphertext_bytes = _hex_to_bytes(ciphertext)
            return _bytes_to_string(cipher.decrypt(ciphertext_bytes))
        except:
            raise CryptoError("Decryption failed")

    def asymmetric_sign(self, message, private_key):
        """Produce the PKCS#1 PSS RSA signature of the message.

        See the PyCrypto `PKCS1_PSS module
        <https://pythonhosted.org/pycrypto/Crypto.Signature.PKCS1_PSS-module.html>`_
        for more information about the underlying implementation.
        PKCS#1 PSS is a secure signature scheme.

        :param str message: The message to sign.
        :param private_key: The private key to sign with.
        :type private_key: An RSA key object

        :returns: The signature.
        :rtype: str

        :raises CryptoError: If message is not a string.
        :raises ValueError: If the RSA key length is not sufficiently long to
            deal with the given hash algorithm (SHA512).
        :raises TypeError: If the RSA key has no private half.
        """
        if not isinstance(message, str):
            raise CryptoError("Message must be a string")

        h = SHA512.new()
        h.update(_string_to_bytes(message))
        signer = PKCS1_PSS.new(private_key)
        signature = signer.sign(h)
        return _bytes_to_hex(signature)

    def asymmetric_verify(self, message, signature, public_key):
        """Verify that a PKCS#1 PSS RSA signature is authentic.

        See the PyCrypto `PKCS1_PSS module
        <https://pythonhosted.org/pycrypto/Crypto.Signature.PKCS1_PSS-module.html>`_
        for more information about the underlying implementation.

        :param str message: The original message.
        :param str signature: The signature to be verified.
        :param public_key: The public key of the signer.
        :type public_key: An RSA key object

        :returns: True if verification is correct. False otherwise.
        :rtype: bool

        :raises CryptoError: If message or signature are not strings.
        """
        if not isinstance(message, str):
            raise CryptoError("Message must be a string")
        if not isinstance(signature, str):
            raise CryptoError("Signature must be a string")

        try:
            h = SHA512.new()
            h.update(_string_to_bytes(message))
            verifier = PKCS1_PSS.new(public_key)
            status = verifier.verify(h, _hex_to_bytes(signature))
            return status
        except:
            return False

    #########################################
    #           Private functions           #
    # STUDENTS: You won't need to use these #
    #########################################

    def _gen_asymmetric_keypair(self, size):
        key = RSA.generate(size)
        return key.publickey(), key

    def _save_keyfile(self, username, private_key):
        if not os.path.exists("keys/"):
            os.mkdir("keys/")
        keyfile = os.path.join("keys", username + ".pem")
        with open(keyfile, 'wb') as f:
            f.write(private_key.exportKey(format='PEM'))
        return True

    def _load_keyfile(self, username):
        keyfile = os.path.join("keys", username + ".pem")
        private_key = None
        if os.path.exists(keyfile):
            with open(keyfile, 'rb') as f:
                content = f.read()
                private_key = RSA.importKey(content)
        return private_key

    def _remove_keyfile(self, username):
        keyfile = os.path.join("keys", username + ".pem")
        if os.path.exists(keyfile):
            return os.remove(keyfile)

    def _pad(self, message, boundary=16):
        """PKCS7 padding

        Pads message's length to a multiple of the boundary size.

        Parameters:
          * message (bytes): The data to pad.
          * boundary (integer): The block size to pad.

        Returns:
          * A string of the message + the padding.
        """
        assert boundary < 256
        padding = boundary - len(message) % boundary
        out = bytes(range(1, padding + 1))
        return message + out

    def _unpad(self, message):
        """PKCS7 padding

        Unpads a message padded from the pad function.

        Parameters:
          * message (bytes): The data to unpad.

        Returns:
          * The original message without the padding.
        """
        skip = message[-1]
        for i in range(1, skip+1):
            if message[-i] != skip-i+1:
                raise CryptoError("Padding is invalid")
        return message[:-skip]


def _bytes_to_hex(b):
    return _bytes_to_string(hexlify(b))


def _hex_to_bytes(s):
    return unhexlify(s)


def _bytes_to_string(b):
    return str(b, 'utf-8')


def _string_to_bytes(s):
    return bytes(s, 'utf-8')


###################
# crypto.py tests #
###################
if __name__ == "__main__":
    crypto = Crypto()

    print("Testing key generation, saving, and loading")
    pubkey, key = crypto._gen_asymmetric_keypair(2048)
    crypto._save_keyfile("testuser", key)
    key_loaded = crypto._load_keyfile("testuser")
    assert key == key_loaded

    print("Testing asymmetric operations")
    m1 = "testing message of medium length"
    c1 = crypto.asymmetric_encrypt(m1, key)
    s1 = crypto.asymmetric_sign(c1, key)
    assert crypto.asymmetric_verify(c1, s1, pubkey)
    assert crypto.asymmetric_decrypt(c1, key) == m1

    print("Testing padding")
    m2 = "testing message of medium length"
    padded = crypto._pad(_string_to_bytes(m2), boundary=128)
    unpadded = _bytes_to_string(crypto._unpad(padded))
    assert unpadded == m2

    print("Testing symmetric operations")
    k2 = _bytes_to_hex(bytes(range(0, 8)))
    # m2padded = crypto.pad(m2, boundary=16)
    c2 = crypto.symmetric_encrypt(m2, k2, cipher_name='DES',
                                  mode_name='ECB')
    m3 = crypto.symmetric_decrypt(c2, k2, cipher_name='DES', mode_name='ECB')
    # m3 = crypto.unpad(b3)
    assert m3 == m2

    print("Testing hashes")
    h1 = crypto.cryptographic_hash(m1, hash_name='MD5')
    assert h1 == "886a34ec6c6475d1745c686f94e63fe7"

    print("Testing MACs")
    mac = crypto.message_authentication_code(m1, k2, hash_name='MD5')

    print("Testing RNG")
    random_bytes = crypto.get_random_bytes(4096)

    print("Testing counters")
    ctr = crypto.new_counter(16)
    assert ctr() == b'\x00\x01'
    assert ctr() == b'\x00\x02'

    iv1 = _bytes_to_hex(bytes(range(0, 8)))
    ctr1 = crypto.new_counter(64, prefix=iv1)
    k3 = _bytes_to_hex(bytes(range(0, 16)))
    c1 = crypto.symmetric_encrypt(m2, k3, cipher_name='AES', mode_name='CTR',
                                  counter=ctr1)
    ctr2 = crypto.new_counter(64, prefix=iv1)
    p1 = crypto.symmetric_decrypt(c1, k3, cipher_name='AES', mode_name='CTR',
                                  counter=ctr2)
    assert p1 == m2

    crypto._remove_keyfile("testuser")
