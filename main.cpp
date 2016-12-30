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
#include "utils.hpp"

#include <boost/log/trivial.hpp>
#include <boost/log/expressions.hpp>
namespace logging = boost::log;

#include <boost/program_options.hpp>
namespace po = boost::program_options;

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
using namespace boost::property_tree;

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
#ifndef __APPLE__
    aesfs_oper.access       = xmp_access;
#endif
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

    // Program options
    try
    {
        string appName = fs::basename(argv[0]);

        bool foreground;
        string verbosity;

        string encrypted;
        string decrypted;

        po::options_description optional("optional arguments");
        optional.add_options()
                ("help,h", "show this help message and exit")
                ("foreground,f", "let the program run in the foreground")
                ("verbosity,V", po::value<string>(&verbosity)->implicit_value(""), "implies -f, increase verbosity: -V: INFO, -VV: DEBUG")
                ("version,v", "show program's version number and exit")
                ;

        po::options_description positional("positional arguments");
        positional.add_options()
                ("encrypted", po::value<string>(&encrypted))
                ("decrypted", po::value<string>(&decrypted))
                ;

        po::options_description options;
        options.add(optional).add(positional);

        po::options_description visible;
        visible.add(optional);

        po::positional_options_description positional_options;
        positional_options.add("encrypted", 1);
        positional_options.add("decrypted", 1);

        po::variables_map vm;
        po::store(po::command_line_parser(argc, argv)
                  .options(options)
                  .positional(positional_options)
                  .run(),
                  vm);
        po::notify(vm);

        if (vm.count("help"))
        {
            cout << "usage: " << appName << " [options] ~/encrypted/ ~/decrypted/" << endl << endl;
            cout << "positional arguments:" << endl;
            cout << "  ~/encrypted/" << "\t\t  " << "folder containing your encrypted files" << endl;
            cout << "  ~/decrypted/" << "\t\t  " << "mountpoint containing the decrypted versions of your files" << endl;
            cout << visible << endl;
            return 0;
        }
        if (vm.count("version"))
        {
            cout << "0.9.0-alpha" << endl;
            return 0;
        }
        if (!vm.count("encrypted") || !vm.count("decrypted"))
        {
            cerr << "error: the following arguments are required: ~/encrypted/, ~/decrypted/" << endl;
            return 1;
        }
        if (vm.count("foreground"))
        {
            foreground = true;
        }
        if (vm.count("verbosity"))
        {
            verbosity += "V";
            // Check that the string contains only 'V's
            if (verbosity.find_first_not_of('V') != string::npos) {
                cerr << "error: invalid verbosity level" << endl;
                return 1;
            }
            foreground = true;
            init_log(verbosity.size());
        }

        // realpath - return the canonicalized absolute pathname
        char *root = realpath(encrypted.c_str(), NULL);
        set_rootdir(root);

        // Setup encryption folder
        fs::path config_file = fs::path(root) / fs::path(".aesfs.json");
        if (!fs::is_empty(fs::path(root)) && !fs::exists(config_file))
        {
            cerr << "Encryption folder must be empty for initial setup" << endl;
            return 1;
        }

        if (!fs::exists(config_file))
        {
        }
        else
        {
            ptree pt;
            read_json(config_file.string(), pt);
            string masterkey = b64decode(pt.get<string>("masterkey"));
            // Random salt
            string r = masterkey.substr( 0, 16);
            // Nonce
            string n = masterkey.substr(16, 16);
            // MAC
            string m = masterkey.substr(32, 16);
            // Length: 0020(hex) := 32(dec)
            unsigned int l = stoul(hex(masterkey.substr(48, 2)), NULL, 16);
            // Ciphertext
            string c = masterkey.substr(50, l);
            // Decrypt actual masterkey
            Cryptr masterkey_cryptr("", r);
            masterkey = fromPythonObject(masterkey_cryptr.DecryptGCM(n, m, c));
            // Create file name cryptr
            string rand_salt = b64decode(pt.get<string>("rand_salt"));
            set_file_name_cryptr(masterkey, rand_salt);
        }

        // Cut out the root directory and only give FUSE the mount point etc.
        // e.g. ~/encrypted/ ~/decrypted/ -f -> ~/decrypted/ -f
        argv[1] = (char*)decrypted.c_str();
        argc = 2;
        if (foreground)
        {
            string f = "-f";
            argv[2] = (char*)f.c_str();
            argc = 3;
        }
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
