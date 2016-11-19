#!/usr/bin/env python

# This file is part of AesFS: an encryption filesystem for FUSE based on AES.
# Copyright 2016 (c) by jmastr
#
# AesFS is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# AesFS is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with AesFS.  If not, see <http://www.gnu.org/licenses/>.

import codecs

from os import urandom

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad

class Cryptr:
    """
    Handles the crypto parameters and the actual en- and decryption.
    """

    @staticmethod
    def get_rand_salt_len():
        return 16

    def __init__(self, *args, **kwargs):
        """
        Constructor.

        Args:
            *args: Variable length argument list. Not used.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Nothing.

        Raises:
            Nothing.
        """

        # Password to derive the keys from
        self.pw = kwargs.get('pw', '')

        # In bytes, doc says it should be at least 8 bytes and has not to be
        # kept secret. Must be chosen randomly though
        self.rand_salt = kwargs.get('rand_salt', urandom(Cryptr.get_rand_salt_len()))

        # In bytes, AES 256 needs 32 bytes
        crypt_key_len = 32

        # Doc says it should be at least 1000
        iterations = 2000

        # Use the PBKDF2 algorithm to obtain the encryption key
        self.crypt_key = PBKDF2(self.pw, self.rand_salt,
                                dkLen=crypt_key_len, count=iterations)

    def encrypt_ecb(self, pt):
        cipher = AES.new(self.crypt_key, AES.MODE_ECB)
        pt = pt.encode('utf-8')
        pt = pad(pt, AES.block_size)
        c = cipher.encrypt(pt)
        return c

    def decrypt_ecb(self, ct):
        cipher = AES.new(self.crypt_key, AES.MODE_ECB)
        p = cipher.decrypt(ct)
        p = unpad(p, AES.block_size)
        p = p.decode('utf-8')
        return p

    def encrypt_gcm(self, pt):
        cipher = AES.new(self.crypt_key, AES.MODE_GCM)
        n = cipher.nonce
        c = cipher.encrypt(pt)
        m = cipher.digest()
        if not n or not m or not c:
            return b''
        return n + m + c

    def decrypt_gcm(self, n, m, c):
        if not n or not m or not c:
            return b''
        cipher = AES.new(self.crypt_key, AES.MODE_GCM, n)
        p = cipher.decrypt(c)
        cipher.verify(m)
        return p

    def get_rand_salt(self):
        return self.rand_salt
