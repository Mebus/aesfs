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
#include "aesfs.hpp"

int xmp_getattr(const char *path, struct stat *stbuf)
{
    return AesFS::Instance()->Getattr(path, stbuf);
}

int xmp_access(const char *path, int mask)
{
    return AesFS::Instance()->Access(path, mask);
}

int xmp_readlink(const char *path, char *buf, size_t size)
{
    return AesFS::Instance()->Readlink(path, buf, size);
}

int xmp_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi)
{
    return AesFS::Instance()->Readdir(path, buf, filler, offset, fi);
}

int xmp_mknod(const char *path, mode_t mode, dev_t rdev)
{
    return AesFS::Instance()->Mknod(path, mode, rdev);
}

int xmp_mkdir(const char *path, mode_t mode)
{
    return AesFS::Instance()->Mkdir(path, mode);
}

int xmp_unlink(const char *path)
{
    return AesFS::Instance()->Unlink(path);
}

int xmp_rmdir(const char *path)
{
    return AesFS::Instance()->Rmdir(path);
}

int xmp_symlink(const char *from, const char *to)
{
    return AesFS::Instance()->Symlink(from, to);
}

int xmp_rename(const char *from, const char *to)
{
    return AesFS::Instance()->Rename(from, to);
}

int xmp_link(const char *from, const char *to)
{
    return AesFS::Instance()->Link(from, to);
}

int xmp_chmod(const char *path, mode_t mode)
{
    return AesFS::Instance()->Chmod(path, mode);
}

int xmp_chown(const char *path, uid_t uid, gid_t gid)
{
    return AesFS::Instance()->Chown(path, uid, gid);
}

int xmp_truncate(const char *path, off_t size)
{
    return AesFS::Instance()->Truncate(path, size);
}

#ifdef HAVE_UTIMENSAT
int xmp_utimens(const char *path, const struct timespec ts[2])
{
    return AesFS::Instance()->Utimens(path, ts);
}
#endif

int xmp_open(const char *path, struct fuse_file_info *fi)
{
    return AesFS::Instance()->Open(path, fi);
}

int xmp_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
    return AesFS::Instance()->Read(path, buf, size, offset, fi);
}

int xmp_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
    return AesFS::Instance()->Write(path, buf, size, offset, fi);
}

int xmp_statfs(const char *path, struct statvfs *stbuf)
{
    return AesFS::Instance()->Statfs(path, stbuf);
}

int xmp_release(const char *path, struct fuse_file_info *fi)
{
    return AesFS::Instance()->Release(path, fi);
}

int xmp_fsync(const char *path, int isdatasync, struct fuse_file_info *fi)
{
    return AesFS::Instance()->Fsync(path, isdatasync, fi);
}

#ifdef HAVE_POSIX_FALLOCATE
int xmp_fallocate(const char *path, int mode, off_t offset, off_t length, struct fuse_file_info *fi)
{
    return AesFS::Instance()->Fallocate(path, mode, offset, length, fi);
}
#endif

#ifdef HAVE_SETXATTR
int xmp_setxattr(const char *path, const char *name, const char *value, size_t size, int flags)
{
    return AesFS::Instance()->Setxattr(path, name, value, size, flags);
}

int xmp_getxattr(const char *path, const char *name, char *value, size_t size)
{
    return AesFS::Instance()->Getxattr(path, name, value, size);
}

int xmp_listxattr(const char *path, char *list, size_t size)
{
    return AesFS::Instance()->Listxattr(path, list, size);
}

int xmp_removexattr(const char *path, const char *name)
{
    return AesFS::Instance()->Removexattr(path, name);
}
#endif
