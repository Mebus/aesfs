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

#ifndef aesfs_hpp
#define aesfs_hpp

#include "cryptr.hpp"
#include "utils.hpp"

#define FUSE_USE_VERSION 26

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef linux
/* For pread()/pwrite()/utimensat() */
#define _XOPEN_SOURCE 700
#endif

#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>
#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif

#include <boost/log/trivial.hpp>

class AesFS {

private:

    static AesFS *_instance;

    Cryptr _file_name_cryptr;

    const char *_root;

    void FullPath(char dest[PATH_MAX], const char *path);

public:

    static AesFS *Instance();

    AesFS();
    ~AesFS();

    void SetRootDir(const char *path);
    void SetFileNameCryptr(const string password, const string rand_salt);

    int Getattr(const char *path, struct stat *stbuf);
#ifndef __APPLE__
    int Access(const char *path, int mask);
#endif
    int Readlink(const char *path, char *buf, size_t size);
    int Readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi);
    int Mknod(const char *path, mode_t mode, dev_t rdev);
    int Mkdir(const char *path, mode_t mode);
    int Unlink(const char *path);
    int Rmdir(const char *path);
    int Symlink(const char *from, const char *to);
    int Rename(const char *from, const char *to);
    int Link(const char *from, const char *to);
    int Chmod(const char *path, mode_t mode);
    int Chown(const char *path, uid_t uid, gid_t gid);
    int Truncate(const char *path, off_t size);
#ifdef HAVE_UTIMENSAT
    int Utimens(const char *path, const struct timespec ts[2]);
#endif
    int Open(const char *path, struct fuse_file_info *fi);
    int Read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi);
    int Write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi);
    int Statfs(const char *path, struct statvfs *stbuf);
    int Release(const char *path, struct fuse_file_info *fi);
    int Fsync(const char *path, int isdatasync, struct fuse_file_info *fi);
#ifdef HAVE_POSIX_FALLOCATE
    int Fallocate(const char *path, int mode, off_t offset, off_t length, struct fuse_file_info *fi);
#endif
#ifdef HAVE_SETXATTR
    int Setxattr(const char *path, const char *name, const char *value, size_t size, int flags);
    int Getxattr(const char *path, const char *name, char *value, size_t size);
    int Listxattr(const char *path, char *list, size_t size);
    int Removexattr(const char *path, const char *name);
#endif

};

#endif //aesfs_hpp
