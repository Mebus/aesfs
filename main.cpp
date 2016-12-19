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
#include <iostream>
using namespace std;

#include <boost/log/trivial.hpp>
#include <boost/log/expressions.hpp>
namespace logging = boost::log;

#include <boost/program_options.hpp>
namespace po = boost::program_options;

struct fuse_operations aesfs_oper;

void init_log(size_t verbosity)
{
    // Always flush the logs
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    if (verbosity >= 2)
    {
        logging::core::get()->set_filter
        (
            logging::trivial::severity >= logging::trivial::debug
        );
    }
    else if (verbosity >= 1)
    {
        logging::core::get()->set_filter
        (
            logging::trivial::severity >= logging::trivial::info
        );
    }
    else
    {
        logging::core::get()->set_filter
        (
            logging::trivial::severity >= logging::trivial::warning
        );
    }
}

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

    init_log(0);

    umask(0);

    try
    {
        po::options_description optional("optional arguments");
        optional.add_options()
                ("help,h", "show this help message and exit")
                ;

        po::variables_map vm;
        po::store(po::parse_command_line(argc, argv, optional), vm);
        po::notify(vm);

        if (vm.count("help"))
        {
            cout << optional << endl;
            return 0;
        }

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
    catch(exception& e)
    {
        cerr << "error: " << e.what();
        return 1;
    }
    catch(...)
    {
        cerr << "Exception of unknown type!";
    }
}
