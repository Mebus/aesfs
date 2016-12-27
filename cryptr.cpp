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

#include "cryptr.hpp"

Cryptr::Cryptr(string _pw, string _rand_salt)
{
    pw = (byte*)_pw.c_str();

    if (_rand_salt.empty())
    {
        AutoSeededRandomPool prng;

        SecByteBlock r(GetSaltLength());
        prng.GenerateBlock(r, r.size());

        rand_salt = new byte[GetSaltLength()];
        std::memcpy(rand_salt, r.BytePtr(), GetSaltLength());
    }
    else
    {
        rand_salt = (byte*)_rand_salt.c_str();
    }

    size_t plen = strlen((const char*)pw);
    unsigned int iterations = 2000;

    PKCS5_PBKDF2_HMAC<SHA1> pbkdf2;
    pbkdf2.DeriveKey(derived, sizeof(derived), 0, pw, plen, rand_salt, (size_t)GetSaltLength(), iterations);
}

object Cryptr::EncryptECB(string pt)
{
    ECB_Mode< AES >::Encryption e;
    e.SetKey(derived, sizeof(derived));

    string c;

    // The StreamTransformationFilter adds padding
    //  as required. ECB and CBC Mode must be padded
    //  to the block size of the cipher.
    StringSource(pt, true,
        new StreamTransformationFilter(e,
            new StringSink(c)
        ) // StreamTransformationFilter
    ); // StringSource

    return object(handle<>(PyBytes_FromStringAndSize(c.c_str(), c.length())));
}

object Cryptr::DecryptECB(string ct)
{
    string p;

    ECB_Mode< AES >::Decryption d;
    d.SetKey(derived, sizeof(derived));

    // The StreamTransformationFilter removes
    //  padding as required.
    StringSource s(ct, true,
        new StreamTransformationFilter(d,
            new StringSink(p)
        ) // StreamTransformationFilter
    ); // StringSource

    return object(handle<>(PyBytes_FromStringAndSize(p.c_str(), p.length())));
}

object Cryptr::EncryptGCM(string pt)
{
    AutoSeededRandomPool prng;

    SecByteBlock key(derived, sizeof(derived));

    SecByteBlock iv(AES::BLOCKSIZE);
    prng.GenerateBlock(iv, iv.size());
    string n((const char*)iv.BytePtr(), iv.SizeInBytes());

    GCM< AES >::Encryption e;
    e.SetKeyWithIV(key, key.size(), iv, iv.size());

    string c;

    // The StreamTransformationFilter adds padding
    //  as required. GCM and CBC Mode must be padded
    //  to the block size of the cipher.
    StringSource(pt, true,
        new AuthenticatedEncryptionFilter(e,
            new StringSink(c)
        ) // StreamTransformationFilter
    ); // StringSource

    // Extract TAG
    int cl = c.length() - TAG_SIZE;
    string m = c.substr(cl, c.length());

    // Ciphertext without TAG
    c = c.substr(0, cl);

    // Length of ciphertext two bytes hex encoded, e.g.
    // 4096 := 1000, 32 := 0020
    stringstream ls;
    ls.fill('0');
    ls.width(4);
    ls << hex << cl;

    string l;
    StringSource(ls.str(), true,
        new HexDecoder(
            new StringSink(l)
        ) // HexDecoder
    ); // StringSource

    string r = n + m + l + c;

    return object(handle<>(PyBytes_FromStringAndSize(r.c_str(), r.length())));
}

object Cryptr::DecryptGCM(string n, string m, string c)
{
    SecByteBlock key(derived, sizeof(derived));

    byte *nonce = (byte*)n.c_str();
    SecByteBlock iv(nonce, NONCE_SIZE);

    GCM< AES >::Decryption d;
    d.SetKeyWithIV(key, key.size(), iv, iv.size());

    string p;

    // The StreamTransformationFilter removes
    //  padding as required.
    StringSource s(c + m, true,
        new AuthenticatedDecryptionFilter(d,
            new StringSink(p)
        ) // StreamTransformationFilter
    ); // StringSource

    return object(handle<>(PyBytes_FromStringAndSize(p.c_str(), p.length())));
}

object Cryptr::GetSalt()
{
    return object(handle<>(PyBytes_FromStringAndSize((const char*)rand_salt, GetSaltLength())));
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
