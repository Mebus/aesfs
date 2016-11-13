#!/usr/bin/env python

# ############################################################################
# AES filesystem (after commit 581053d)
# ############################################################################
#
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

# ############################################################################
# Passthrough filesystem (commit 581053d and before)
# ############################################################################
#
# Copyright (c) 2016, Stavros Korokithakis
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

from __future__ import with_statement

import os
import sys
import errno
import logging
import argparse

from fuse import FUSE, FuseOSError, Operations
from cryptr import Cryptr


class aesfs(Operations):
    """
    Implements callbacks from the FUSE library and adds crypto behavior.
    """

    def __init__(self, root, pw):
        self.root = root
        self.pw = pw
        self.cryptrs = {}

    # Helpers
    # =======

    def _full_path(self, partial):
        if partial.startswith("/"):
            partial = partial[1:]
        path = os.path.join(self.root, partial)
        return path

    def _real_offset(self, offset, i, read_size):
        return offset + (offset // read_size) * (16 + 16) + i * (16 + 16 + read_size) + Cryptr.rand_salt_len

    def _real_size(self, file_size, read_size):
        file_size -= Cryptr.rand_salt_len
        i = (file_size - 1) // (16 + 16 + read_size)
        file_size -= (i + 1) * (16 + 16)
        return file_size

    def _decrypt(self, length, offset, fh):
        os.lseek(fh, offset, os.SEEK_SET)
        n = os.read(fh, 16)
        m = os.read(fh, 16)
        c = os.read(fh, length)
        return self.cryptrs[fh].decrypt(n, m, c)

    def _encrypt(self, buf, offset, fh):
        os.lseek(fh, offset, os.SEEK_SET)
        os.write(fh, self.cryptrs[fh].encrypt(buf))

    # Filesystem methods
    # ==================

    def access(self, path, mode):
        full_path = self._full_path(path)
        logging.debug("access - {}".format(full_path))
        if not os.access(full_path, mode):
            raise FuseOSError(errno.EACCES)

    def chmod(self, path, mode):
        full_path = self._full_path(path)
        logging.info("chmod - {}".format(full_path))
        return os.chmod(full_path, mode)

    def chown(self, path, uid, gid):
        full_path = self._full_path(path)
        logging.info("chown - {}".format(full_path))
        return os.chown(full_path, uid, gid)

    def getattr(self, path, fh=None):
        full_path = self._full_path(path)
        logging.debug("getattr - {}".format(full_path))
        st = os.lstat(full_path)
        stat = dict((key, getattr(st, key)) for key in ('st_atime',
                                                        'st_ctime',
                                                        'st_gid',
                                                        'st_mode',
                                                        'st_mtime',
                                                        'st_nlink',
                                                        'st_size',
                                                        'st_uid'))
        if os.path.isfile(full_path):
            read_size = self.statfs(path)['f_frsize']
            file_size = stat['st_size']
            stat['st_size'] = self._real_size(file_size, read_size)
        return stat

    def readdir(self, path, fh):
        full_path = self._full_path(path)
        logging.debug("readdir - {}".format(full_path))

        dirents = ['.', '..']
        if os.path.isdir(full_path):
            dirents.extend(os.listdir(full_path))
        for r in dirents:
            yield r

    def readlink(self, path):
        full_path = self._full_path(path)
        logging.debug("readlink - {}".format(full_path))
        pathname = os.readlink(full_path)
        if pathname.startswith("/"):
            # Path name is absolute, sanitize it.
            return os.path.relpath(pathname, self.root)
        else:
            return pathname

    def mknod(self, path, mode, dev):
        full_path = self._full_path(path)
        logging.info("mknod - {}".format(full_path))
        return os.mknod(full_path, mode, dev)

    def rmdir(self, path):
        full_path = self._full_path(path)
        logging.info("rmdir - {}".format(full_path))
        return os.rmdir(full_path)

    def mkdir(self, path, mode):
        full_path = self._full_path(path)
        logging.info("mkdir - {}".format(full_path))
        return os.mkdir(full_path, mode)

    def statfs(self, path):
        full_path = self._full_path(path)
        logging.debug("statfs - {}".format(full_path))
        stv = os.statvfs(full_path)
        return dict((key, getattr(stv, key)) for key in ('f_bavail',
                                                         'f_bfree',
                                                         'f_blocks',
                                                         'f_bsize',
                                                         'f_favail',
                                                         'f_ffree',
                                                         'f_files',
                                                         'f_flag',
                                                         'f_frsize',
                                                         'f_namemax'))

    def unlink(self, path):
        full_path = self._full_path(path)
        logging.info("unlink - {}".format(full_path))
        return os.unlink(full_path)

    def symlink(self, name, target):
        full_path = self._full_path(target)
        logging.info("symlink - {}".format(full_path))
        return os.symlink(name, full_path)

    def rename(self, old, new):
        full_path_old = self._full_path(old)
        full_path_new = self._full_path(new)
        logging.info("rename - {} to {}".format(full_path_old, full_path_new))
        return os.rename(full_path_old, full_path_new)

    def link(self, target, name):
        full_path_name = self._full_path(name)
        full_path_trgt = self._full_path(trgt)
        logging.info("link - {} to {}".format(full_path_name, full_path_trgt))
        return os.link(full_path_trgt, full_path_name)

    def utimens(self, path, times=None):
        full_path = self._full_path(path)
        logging.info("utimens - {}".format(full_path))
        return os.utime(full_path, times)

    # File methods
    # ============

    def open(self, path, flags):
        full_path = self._full_path(path)
        # Open for reading even if only writing is requested, to get crypto
        # parameters:
        # * If flags % 2 == 0: reading. Change nothing
        # * If flags % 2 != 0: writing, e.g. 'w'(riting) or 'a'(ppending).
        #                      Change to 'w+' or 'a+' which lead to
        #                      additional read access
        # See: https://github.com/mafintosh/fuse-bindings/issues/25
        if flags % 2 != 0:
            flags += 1
        fh = os.open(full_path, flags)
        logging.info("open - {}, fh: {}".format(
            full_path,
            fh))
        rand_salt = os.read(fh, Cryptr.rand_salt_len)
        self.cryptrs[fh] = Cryptr(pw=self.pw, rand_salt=rand_salt)
        return fh

    def create(self, path, mode, fi=None):
        full_path = self._full_path(path)
        logging.info("create - {}".format(full_path))
        # Create cipher object and write necessary data at the beginning
        fh = os.open(full_path, os.O_RDWR | os.O_CREAT, mode)
        self.cryptrs[fh] = Cryptr(pw=self.pw)
        os.write(fh, self.cryptrs[fh].get_rand_salt())
        return fh

    def read(self, path, length, offset, fh):
        full_path = self._full_path(path)
        logging.info("read - {}, offset: {}, length: {}, fh: {}".format(
            full_path,
            offset,
            length,
            fh))
        pt = b''
        read_size = self.statfs(path)['f_frsize']
        file_size = self.getattr(path)['st_size']
        size = min(file_size, read_size)
        if size <= 0:
            return pt
        rounds = (length - 1) // read_size
        i = 0
        while True:
            start = self._real_offset(offset, i, read_size)
            pt += self._decrypt(size, start, fh)
            if i == rounds:
                break
            i += 1
        return pt

    def write(self, path, buf, offset, fh):
        full_path = self._full_path(path)
        logging.info("write - {}, offset: {}, fh: {}".format(
            full_path,
            offset,
            fh))
        read_size = self.statfs(path)['f_frsize']
        start = self._real_offset(offset, 0, read_size)
        length = len(buf)
        pt = b''
        if offset % read_size != 0:
            pt += self._decrypt(read_size - length, start, fh)
        pt += buf
        rounds = (length - 1) // read_size
        i = 0
        while True:
            start = self._real_offset(offset, i, read_size)
            self._encrypt(pt[i * read_size:(i + 1) * read_size], start, fh)
            if i == rounds:
                break
            i += 1
        return length

    def truncate(self, path, length, fh=None):
        full_path = self._full_path(path)
        read_size = self.statfs(path)['f_frsize']
        length = self._real_offset(0, 0, read_size)
        logging.info("truncate - {}, length: {}".format(
            full_path,
            length))
        with open(full_path, 'r+') as f:
            f.truncate(length)

    def flush(self, path, fh):
        full_path = self._full_path(path)
        logging.info("release - {}, fh: {}".format(
            full_path,
            fh))
        return os.fsync(fh)

    def release(self, path, fh):
        full_path = self._full_path(path)
        logging.info("release - {}, fh: {}".format(
            full_path,
            fh))
        del self.cryptrs[fh]
        return os.close(fh)

    def fsync(self, path, fdatasync, fh):
        full_path = self._full_path(path)
        logging.info("fsync - {}".format(full_path))
        return self.flush(path, fh)


def main(mountpoint, root, foreground, verbosity):
    if verbosity >= 2:
        logging.basicConfig(level=logging.DEBUG)
        foreground = True
    elif verbosity >= 1:
        logging.basicConfig(level=logging.INFO)
        foreground = True
    pw = 'HJy6V3ZDSMqf7LhTcKQJFesmzjCAVOiA'
    FUSE(aesfs(root, pw), mountpoint, nothreads=True, foreground=foreground)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("encrypted", metavar="~/encrypted/",
                        help="folder containing your encrypted files")
    parser.add_argument("decrypted", metavar="~/decrypted/",
                        help="mountpoint containing the decrypted " +
                        "versions of your files")
    parser.add_argument("-f", "--foreground", action="store_true",
                        help="let the program run in the foreground")
    parser.add_argument("-V", "--verbosity", action="count", default=0,
                        help="implies -f, increase verbosity: " +
                        "-V: INFO, -VV: DEBUG")
    parser.add_argument("-v", "--version", action='version',
                        version='0.3.0')
    args = parser.parse_args()

    main(args.decrypted, args.encrypted, args.foreground, args.verbosity)
