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

#ifndef wrap_hpp
#define wrap_hpp

#include "aesfs.hpp"

#define FUSE_USE_VERSION 26

#include <fuse.h>
#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif

void set_rootdir(const char *path);
void set_file_name_cryptr(const string password, const string rand_salt);

int xmp_getattr(const char *path, struct stat *stbuf);
#ifndef __APPLE__
int xmp_access(const char *path, int mask);
#endif
int xmp_readlink(const char *path, char *buf, size_t size);
int xmp_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi);
int xmp_mknod(const char *path, mode_t mode, dev_t rdev);
int xmp_mkdir(const char *path, mode_t mode);
int xmp_unlink(const char *path);
int xmp_rmdir(const char *path);
int xmp_symlink(const char *from, const char *to);
int xmp_rename(const char *from, const char *to);
int xmp_link(const char *from, const char *to);
int xmp_chmod(const char *path, mode_t mode);
int xmp_chown(const char *path, uid_t uid, gid_t gid);
int xmp_truncate(const char *path, off_t size);
#ifdef HAVE_UTIMENSAT
int xmp_utimens(const char *path, const struct timespec ts[2]);
#endif
int xmp_open(const char *path, struct fuse_file_info *fi);
int xmp_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi);
int xmp_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi);
int xmp_statfs(const char *path, struct statvfs *stbuf);
int xmp_release(const char *path, struct fuse_file_info *fi);
int xmp_fsync(const char *path, int isdatasync, struct fuse_file_info *fi);
#ifdef HAVE_POSIX_FALLOCATE
int xmp_fallocate(const char *path, int mode, off_t offset, off_t length, struct fuse_file_info *fi);
#endif
#ifdef HAVE_SETXATTR
int xmp_setxattr(const char *path, const char *name, const char *value, size_t size, int flags);
int xmp_getxattr(const char *path, const char *name, char *value, size_t size);
int xmp_listxattr(const char *path, char *list, size_t size);
int xmp_removexattr(const char *path, const char *name);
#endif

#endif //wrap_hpp
