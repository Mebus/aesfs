/**
 * This file is part of AesFS: an encryption filesystem for FUSE based on AES.
 * Copyright 2016 (c) by jmastr
 *
 * AesFS is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * AesFS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with AesFS.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "wrap.hpp"

#include <stdlib.h>

struct fuse_operations aesfs_oper;

int main(int argc, char *argv[])
{

    aesfs_oper.getattr      = xmp_getattr;
    aesfs_oper.access       = xmp_access;
    aesfs_oper.readlink     = xmp_readlink;
    aesfs_oper.readdir      = xmp_readdir;
    aesfs_oper.mknod        = xmp_mknod;
    aesfs_oper.mkdir        = xmp_mkdir;
    aesfs_oper.symlink      = xmp_symlink;
    aesfs_oper.unlink       = xmp_unlink;
    aesfs_oper.rmdir        = xmp_rmdir;
    aesfs_oper.rename       = xmp_rename;
    aesfs_oper.link         = xmp_link;
    aesfs_oper.chmod        = xmp_chmod;
    aesfs_oper.chown        = xmp_chown;
    aesfs_oper.truncate     = xmp_truncate;
#ifdef HAVE_UTIMENSAT
    aesfs_oper.utimens      = xmp_utimens;
#endif
    aesfs_oper.open         = xmp_open;
    aesfs_oper.read         = xmp_read;
    aesfs_oper.write        = xmp_write;
    aesfs_oper.statfs       = xmp_statfs;
    aesfs_oper.release      = xmp_release;
    aesfs_oper.fsync        = xmp_fsync;
#ifdef HAVE_POSIX_FALLOCATE
    aesfs_oper.fallocate    = xmp_fallocate;
#endif
#ifdef HAVE_SETXATTR
    aesfs_oper.setxattr     = xmp_setxattr;
    aesfs_oper.getxattr     = xmp_getxattr;
    aesfs_oper.listxattr    = xmp_listxattr;
    aesfs_oper.removexattr  = xmp_removexattr;
#endif

    umask(0);

    // realpath - return the canonicalized absolute pathname
    set_rootdir(realpath(argv[1], NULL));

    // Cut out the root directory and only give FUSE the mount point etc.
    // e.g. ~/encrypted/ ~/decrypted/ -f -> ~/decrypted/ -f
    for(int i = 1; i < argc; i++)
    {
        argv[i] = argv[i + 1];
    }
    argc--;

    return fuse_main(argc, argv, &aesfs_oper, NULL);
}
