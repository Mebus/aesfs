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

/**
 * FUSE: Filesystem in Userspace
 * Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>
 * Copyright (C) 2011       Sebastian Pipping <sebastian@pipping.org>
 *
 * This program can be distributed under the terms of the GNU GPL.
 * See the file COPYING.
 */

#include "aesfs.hpp"

AesFS* AesFS::_instance = NULL;

AesFS* AesFS::Instance()
{
    if(_instance == NULL)
    {
        _instance = new AesFS();
    }
    return _instance;
}

AesFS::AesFS()
{
}

AesFS::~AesFS()
{
}

int AesFS::Getattr(const char *path, struct stat *stbuf)
{
    int res;

    res = lstat(path, stbuf);
    if (res == -1)
        return -errno;

    return 0;
}

int AesFS::Access(const char *path, int mask)
{
    int res;

    res = access(path, mask);
    if (res == -1)
        return -errno;

    return 0;
}

int AesFS::Readlink(const char *path, char *buf, size_t size)
{
    int res;

    res = readlink(path, buf, size - 1);
    if (res == -1)
        return -errno;

    buf[res] = '\0';
    return 0;
}


int AesFS::Readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi)
{
    DIR *dp;
    struct dirent *de;

    (void) offset;
    (void) fi;

    dp = opendir(path);
    if (dp == NULL)
        return -errno;

    while ((de = readdir(dp)) != NULL) {
        struct stat st;
        memset(&st, 0, sizeof(st));
        st.st_ino = de->d_ino;
        st.st_mode = de->d_type << 12;
        if (filler(buf, de->d_name, &st, 0))
            break;
    }

    closedir(dp);
    return 0;
}

int AesFS::Mknod(const char *path, mode_t mode, dev_t rdev)
{
    int res;

    /* On Linux this could just be 'mknod(path, mode, rdev)' but this
       is more portable */
    if (S_ISREG(mode)) {
        res = open(path, O_CREAT | O_EXCL | O_WRONLY, mode);
        if (res >= 0)
            res = close(res);
    } else if (S_ISFIFO(mode))
        res = mkfifo(path, mode);
    else
        res = mknod(path, mode, rdev);
    if (res == -1)
        return -errno;

    return 0;
}

int AesFS::Mkdir(const char *path, mode_t mode)
{
    int res;

    res = mkdir(path, mode);
    if (res == -1)
        return -errno;

    return 0;
}

int AesFS::Unlink(const char *path)
{
    int res;

    res = unlink(path);
    if (res == -1)
        return -errno;

    return 0;
}

int AesFS::Rmdir(const char *path)
{
    int res;

    res = rmdir(path);
    if (res == -1)
        return -errno;

    return 0;
}

int AesFS::Symlink(const char *from, const char *to)
{
    int res;

    res = symlink(from, to);
    if (res == -1)
        return -errno;

    return 0;
}

int AesFS::Rename(const char *from, const char *to)
{
    int res;

    res = rename(from, to);
    if (res == -1)
        return -errno;

    return 0;
}

int AesFS::Link(const char *from, const char *to)
{
    int res;

    res = link(from, to);
    if (res == -1)
        return -errno;

    return 0;
}

int AesFS::Chmod(const char *path, mode_t mode)
{
    int res;

    res = chmod(path, mode);
    if (res == -1)
        return -errno;

    return 0;
}

int AesFS::Chown(const char *path, uid_t uid, gid_t gid)
{
    int res;

    res = lchown(path, uid, gid);
    if (res == -1)
        return -errno;

    return 0;
}

int AesFS::Truncate(const char *path, off_t size)
{
    int res;

    res = truncate(path, size);
    if (res == -1)
        return -errno;

    return 0;
}

#ifdef HAVE_UTIMENSAT
int AesFS::Utimens(const char *path, const struct timespec ts[2])
{
    int res;

    /* don't use utime/utimes since they follow symlinks */
    res = utimensat(0, path, ts, AT_SYMLINK_NOFOLLOW);
    if (res == -1)
        return -errno;

    return 0;
}
#endif

int AesFS::Open(const char *path, struct fuse_file_info *fi)
{
    int res;

    res = open(path, fi->flags);
    if (res == -1)
        return -errno;

    close(res);
    return 0;
}

int AesFS::Read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
    int fd;
    int res;

    (void) fi;
    fd = open(path, O_RDONLY);
    if (fd == -1)
        return -errno;

    res = pread(fd, buf, size, offset);
    if (res == -1)
        res = -errno;

    close(fd);
    return res;
}

int AesFS::Write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
    int fd;
    int res;

    (void) fi;
    fd = open(path, O_WRONLY);
    if (fd == -1)
        return -errno;

    res = pwrite(fd, buf, size, offset);
    if (res == -1)
        res = -errno;

    close(fd);
    return res;
}

int AesFS::Statfs(const char *path, struct statvfs *stbuf)
{
    int res;

    res = statvfs(path, stbuf);
    if (res == -1)
        return -errno;

    return 0;
}

int AesFS::Release(const char *path, struct fuse_file_info *fi)
{
    /* Just a stub.	 This method is optional and can safely be left
       unimplemented */

    (void) path;
    (void) fi;
    return 0;
}

int AesFS::Fsync(const char *path, int isdatasync, struct fuse_file_info *fi)
{
    /* Just a stub.	 This method is optional and can safely be left
       unimplemented */

    (void) path;
    (void) isdatasync;
    (void) fi;
    return 0;
}

#ifdef HAVE_POSIX_FALLOCATE
int AesFS::Fallocate(const char *path, int mode, off_t offset, off_t length, struct fuse_file_info *fi)
{
    int fd;
    int res;

    (void) fi;

    if (mode)
        return -EOPNOTSUPP;

    fd = open(path, O_WRONLY);
    if (fd == -1)
        return -errno;

    res = -posix_fallocate(fd, offset, length);

    close(fd);
    return res;
}
#endif

#ifdef HAVE_SETXATTR
/* xattr operations are optional and can safely be left unimplemented */
int AesFS::Setxattr(const char *path, const char *name, const char *value, size_t size, int flags)
{
    int res = lsetxattr(path, name, value, size, flags);
    if (res == -1)
        return -errno;
    return 0;
}

int AesFS::Getxattr(const char *path, const char *name, char *value, size_t size)
{
    int res = lgetxattr(path, name, value, size);
    if (res == -1)
        return -errno;
    return res;
}

int AesFS::Listxattr(const char *path, char *list, size_t size)
{
    int res = llistxattr(path, list, size);
    if (res == -1)
        return -errno;
    return res;
}

int AesFS::Removexattr(const char *path, const char *name)
{
    int res = lremovexattr(path, name);
    if (res == -1)
        return -errno;
    return 0;
}
#endif /* HAVE_SETXATTR */
