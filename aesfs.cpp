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

void AesFS::FullPath(char dest[PATH_MAX], const char *path)
{
    if (path[0] == '/')
    {
        path++;
    }

    string s(path);
    if (strlen(path))
    {
        vector<string> partial;
        char *pch, *saveptr;
        pch = strtok_r ((char*)s.c_str(), "/", &saveptr);
        while (pch != NULL)
        {
            string e = fromPythonObject(_file_name_cryptr.EncryptECB(pch));
            string b = b64encode(e);
            replace(b.begin(), b.end(), '/', '_');
            partial.push_back(b);
            pch = strtok_r (NULL, "/", &saveptr);
        }
        s = join(partial, "/");
    }

    strcpy(dest, _root);
    strncat(dest, "/", 1);
    strncat(dest, s.c_str(), PATH_MAX);
}

void AesFS::SetRootDir(const char *path)
{
    _root = path;
}

void AesFS::SetFileNameCryptr(const string password, const string rand_salt)
{
    _file_name_cryptr = Cryptr(password, rand_salt);
}

AesFS::AesFS()
{
}

AesFS::~AesFS()
{
}

int AesFS::Getattr(const char *path, struct stat *stbuf)
{
    char fullPath[PATH_MAX];
    FullPath(fullPath, path);
    BOOST_LOG_TRIVIAL(debug) << "Getattr - " << fullPath;

    int res;

    res = lstat(fullPath, stbuf);
    if (res == -1)
        return -errno;

    return 0;
}

#ifndef __APPLE__
int AesFS::Access(const char *path, int mask)
{
    char fullPath[PATH_MAX];
    FullPath(fullPath, path);
    BOOST_LOG_TRIVIAL(debug) << "Access - " << fullPath;

    int res;

    res = access(fullPath, mask);
    if (res == -1)
        return -errno;

    return 0;
}
#endif

int AesFS::Readlink(const char *path, char *buf, size_t size)
{
    char fullPath[PATH_MAX];
    FullPath(fullPath, path);
    BOOST_LOG_TRIVIAL(debug) << "Readlink - " << fullPath;

    int res;

    res = readlink(fullPath, buf, size - 1);
    if (res == -1)
        return -errno;

    buf[res] = '\0';
    return 0;
}


int AesFS::Readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi)
{
    char fullPath[PATH_MAX];
    FullPath(fullPath, path);
    BOOST_LOG_TRIVIAL(debug) << "Readdir - " << fullPath;

    DIR *dp;
    struct dirent *de;

    (void) offset;
    (void) fi;

    dp = opendir(fullPath);
    if (dp == NULL)
        return -errno;

    while ((de = readdir(dp)) != NULL) {
        string file_name(de->d_name);
        if (file_name == "." ||
                file_name == ".." ||
                file_name == ".aesfs.json")
        {
            continue;
        }
        replace(file_name.begin(), file_name.end(), '_', '/');
        string e = b64decode(file_name);
        string d = fromPythonObject(_file_name_cryptr.DecryptECB(e));
        strncpy(de->d_name, d.c_str(), d.length() + 1);
        de->d_namlen = d.length();

        struct stat st;
        memset(&st, 0, sizeof(st));
        st.st_ino = de->d_ino;
        st.st_mode = de->d_type << 12;
        if (filler(buf, de->d_name, &st, 0))
        {
            break;
        }
    }

    closedir(dp);
    return 0;
}

int AesFS::Mknod(const char *path, mode_t mode, dev_t rdev)
{
    char fullPath[PATH_MAX];
    FullPath(fullPath, path);
    BOOST_LOG_TRIVIAL(debug) << "Mknod - " << fullPath;

    int res;

    /* On Linux this could just be 'mknod(path, mode, rdev)' but this
       is more portable */
    if (S_ISREG(mode)) {
        res = open(fullPath, O_CREAT | O_EXCL | O_WRONLY, mode);
        if (res >= 0)
            res = close(res);
    } else if (S_ISFIFO(mode))
        res = mkfifo(fullPath, mode);
    else
        res = mknod(fullPath, mode, rdev);
    if (res == -1)
        return -errno;

    return 0;
}

int AesFS::Mkdir(const char *path, mode_t mode)
{
    char fullPath[PATH_MAX];
    FullPath(fullPath, path);
    BOOST_LOG_TRIVIAL(debug) << "Mkdir - " << fullPath;

    int res;

    res = mkdir(fullPath, mode);
    if (res == -1)
        return -errno;

    return 0;
}

int AesFS::Unlink(const char *path)
{
    char fullPath[PATH_MAX];
    FullPath(fullPath, path);
    BOOST_LOG_TRIVIAL(debug) << "Unlink - " << fullPath;

    int res;

    res = unlink(fullPath);
    if (res == -1)
        return -errno;

    return 0;
}

int AesFS::Rmdir(const char *path)
{
    char fullPath[PATH_MAX];
    FullPath(fullPath, path);
    BOOST_LOG_TRIVIAL(debug) << "Rmdir - " << fullPath;

    int res;

    res = rmdir(fullPath);
    if (res == -1)
        return -errno;

    return 0;
}

int AesFS::Symlink(const char *from, const char *to)
{
    char fullPathFrom[PATH_MAX];
    char fullPathTrgt[PATH_MAX];
    FullPath(fullPathFrom, from);
    FullPath(fullPathTrgt, to);
    BOOST_LOG_TRIVIAL(debug) << "Symlink from - " << fullPathFrom << " to " << fullPathTrgt;

    int res;

    res = symlink(fullPathFrom, fullPathTrgt);
    if (res == -1)
        return -errno;

    return 0;
}

int AesFS::Rename(const char *from, const char *to)
{
    char fullPathFrom[PATH_MAX];
    char fullPathTrgt[PATH_MAX];
    FullPath(fullPathFrom, from);
    FullPath(fullPathTrgt, to);
    BOOST_LOG_TRIVIAL(debug) << "Rename from - " << fullPathFrom << " to " << fullPathTrgt;

    int res;

    res = rename(fullPathFrom, fullPathTrgt);
    if (res == -1)
        return -errno;

    return 0;
}

int AesFS::Link(const char *from, const char *to)
{
    char fullPathFrom[PATH_MAX];
    char fullPathTrgt[PATH_MAX];
    FullPath(fullPathFrom, from);
    FullPath(fullPathTrgt, to);
    BOOST_LOG_TRIVIAL(debug) << "Link from - " << fullPathFrom << " to " << fullPathTrgt;

    int res;

    res = link(fullPathFrom, fullPathTrgt);
    if (res == -1)
        return -errno;

    return 0;
}

int AesFS::Chmod(const char *path, mode_t mode)
{
    char fullPath[PATH_MAX];
    FullPath(fullPath, path);
    BOOST_LOG_TRIVIAL(info) << "Chmod - " << fullPath;

    int res;

    res = chmod(fullPath, mode);
    if (res == -1)
        return -errno;

    return 0;
}

int AesFS::Chown(const char *path, uid_t uid, gid_t gid)
{
    char fullPath[PATH_MAX];
    FullPath(fullPath, path);
    BOOST_LOG_TRIVIAL(info) << "Chown - " << fullPath;

    int res;

    res = lchown(fullPath, uid, gid);
    if (res == -1)
        return -errno;

    return 0;
}

int AesFS::Truncate(const char *path, off_t size)
{
    char fullPath[PATH_MAX];
    FullPath(fullPath, path);
    BOOST_LOG_TRIVIAL(info) << "Truncate - " << fullPath;

    int res;

    res = truncate(fullPath, size);
    if (res == -1)
        return -errno;

    return 0;
}

#ifdef HAVE_UTIMENSAT
int AesFS::Utimens(const char *path, const struct timespec ts[2])
{
    char fullPath[PATH_MAX];
    FullPath(fullPath, path);
    BOOST_LOG_TRIVIAL(debug) << "Utimens - " << fullPath;

    int res;

    /* don't use utime/utimes since they follow symlinks */
    res = utimensat(0, fullPath, ts, AT_SYMLINK_NOFOLLOW);
    if (res == -1)
        return -errno;

    return 0;
}
#endif

int AesFS::Open(const char *path, struct fuse_file_info *fi)
{
    char fullPath[PATH_MAX];
    FullPath(fullPath, path);
    BOOST_LOG_TRIVIAL(info) << "Open - " << fullPath;

    int res;

    res = open(fullPath, fi->flags);
    if (res == -1)
        return -errno;

    close(res);
    return 0;
}

int AesFS::Read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
    char fullPath[PATH_MAX];
    FullPath(fullPath, path);
    BOOST_LOG_TRIVIAL(info) << "Read - " << fullPath;

    int fd;
    int res;

    (void) fi;
    fd = open(fullPath, O_RDONLY);
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
    char fullPath[PATH_MAX];
    FullPath(fullPath, path);
    BOOST_LOG_TRIVIAL(info) << "Write - " << fullPath;

    int fd;
    int res;

    (void) fi;
    fd = open(fullPath, O_WRONLY);
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
    char fullPath[PATH_MAX];
    FullPath(fullPath, path);
    BOOST_LOG_TRIVIAL(debug) << "Statfs - " << fullPath;

    int res;

    res = statvfs(fullPath, stbuf);
    if (res == -1)
        return -errno;

    return 0;
}

int AesFS::Release(const char *path, struct fuse_file_info *fi)
{
    char fullPath[PATH_MAX];
    FullPath(fullPath, path);
    BOOST_LOG_TRIVIAL(info) << "Release - " << fullPath;

    /* Just a stub.	 This method is optional and can safely be left
       unimplemented */

    (void) fullPath;
    (void) fi;
    return 0;
}

int AesFS::Fsync(const char *path, int isdatasync, struct fuse_file_info *fi)
{
    char fullPath[PATH_MAX];
    FullPath(fullPath, path);
    BOOST_LOG_TRIVIAL(info) << "Fsync - " << fullPath;

    /* Just a stub.	 This method is optional and can safely be left
       unimplemented */

    (void) fullPath;
    (void) isdatasync;
    (void) fi;
    return 0;
}

#ifdef HAVE_POSIX_FALLOCATE
int AesFS::Fallocate(const char *path, int mode, off_t offset, off_t length, struct fuse_file_info *fi)
{
    char fullPath[PATH_MAX];
    FullPath(fullPath, path);
    BOOST_LOG_TRIVIAL(debug) << "Fallocate - " << fullPath;

    int fd;
    int res;

    (void) fi;

    if (mode)
        return -EOPNOTSUPP;

    fd = open(fullPath, O_WRONLY);
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
    char fullPath[PATH_MAX];
    FullPath(fullPath, path);
    BOOST_LOG_TRIVIAL(debug) << "Setxattr - " << fullPath;

    int res = lsetxattr(fullPath, name, value, size, flags);
    if (res == -1)
        return -errno;
    return 0;
}

int AesFS::Getxattr(const char *path, const char *name, char *value, size_t size)
{
    char fullPath[PATH_MAX];
    FullPath(fullPath, path);
    BOOST_LOG_TRIVIAL(debug) << "Getxattr - " << fullPath;

    int res = lgetxattr(fullPath, name, value, size);
    if (res == -1)
        return -errno;
    return res;
}

int AesFS::Listxattr(const char *path, char *list, size_t size)
{
    char fullPath[PATH_MAX];
    FullPath(fullPath, path);
    BOOST_LOG_TRIVIAL(debug) << "Listxattr - " << fullPath;

    int res = llistxattr(fullPath, list, size);
    if (res == -1)
        return -errno;
    return res;
}

int AesFS::Removexattr(const char *path, const char *name)
{
    char fullPath[PATH_MAX];
    FullPath(fullPath, path);
    BOOST_LOG_TRIVIAL(debug) << "Removexattr - " << fullPath;

    int res = lremovexattr(fullPath, name);
    if (res == -1)
        return -errno;
    return 0;
}
#endif /* HAVE_SETXATTR */
