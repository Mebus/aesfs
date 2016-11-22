// This file is part of AesFS: an encryption filesystem for FUSE based on AES.
// Copyright 2016 (c) by jmastr
//
// AesFS is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// AesFS is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with AesFS.  If not, see <http://www.gnu.org/licenses/>.

#include <string>
using std::string;

#include <boost/python.hpp>
using boost::python::object;
using boost::python::handle;

class Cryptr
{
public:
    Cryptr(string _pw, string _rand_salt);
    ~Cryptr() {}

    static int GetSaltLength() { return 16; }
    object EncryptECB(string pt);
    object DecryptECB(string ct);
    object EncryptGCM(string pt);
    object DecryptGCM(string n, string m, string c);
    object GetSalt();
};

Cryptr::Cryptr(string _pw, string _rand_salt)
{
}

object Cryptr::EncryptECB(string pt)
{
    return object(handle<>(PyBytes_FromStringAndSize("", 0)));
}

object Cryptr::DecryptECB(string ct)
{
    return object(handle<>(PyBytes_FromStringAndSize("", 0)));
}

object Cryptr::EncryptGCM(string pt)
{
    return object(handle<>(PyBytes_FromStringAndSize("", 0)));
}

object Cryptr::DecryptGCM(string n, string m, string c)
{
    return object(handle<>(PyBytes_FromStringAndSize("", 0)));
}

object Cryptr::GetSalt()
{
    return object(handle<>(PyBytes_FromStringAndSize("", 0)));
}

BOOST_PYTHON_MODULE(libcryptr)
{
    using namespace boost::python;

    class_<Cryptr>("Cryptr", init<string, string>())
            .def("get_rand_salt_len", &Cryptr::GetSaltLength)
            .staticmethod("get_rand_salt_len")
            .def("encrypt_ecb", &Cryptr::EncryptECB)
            .def("decrypt_ecb", &Cryptr::DecryptECB)
            .def("encrypt_gcm", &Cryptr::EncryptGCM)
            .def("decrypt_gcm", &Cryptr::DecryptGCM)
            .def("get_rand_salt", &Cryptr::GetSalt)
    ;
}
