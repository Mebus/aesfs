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

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <string>
using std::hex;
using std::string;
using std::stringstream;

#include <boost/python.hpp>
using boost::python::object;
using boost::python::handle;

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "cryptopp/integer.h"
using CryptoPP::Integer;

#include "cryptopp/pwdbased.h"
using CryptoPP::PKCS5_PBKDF2_HMAC;

#include "cryptopp/sha.h"
using CryptoPP::SHA1;

#include "cryptopp/hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include "cryptopp/filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::AuthenticatedEncryptionFilter;
using CryptoPP::AuthenticatedDecryptionFilter;

#include "cryptopp/aes.h"
using CryptoPP::AES;

#include "cryptopp/modes.h"
using CryptoPP::ECB_Mode;

#include "cryptopp/gcm.h"
using CryptoPP::GCM;

#include "cryptopp/secblock.h"
using CryptoPP::SecByteBlock;

class Cryptr
{
private:
    static const int TAG_SIZE   = 16;
    static const int SALT_SIZE  = 16;
    static const int NONCE_SIZE = 16;

    byte *pw;
    byte *rand_salt;

    byte derived[AES::MAX_KEYLENGTH];
public:
    Cryptr(string _pw, string _rand_salt);
    Cryptr() {}
    ~Cryptr() {}

    static int GetSaltLength() { return SALT_SIZE; }
    object EncryptECB(string pt);
    object DecryptECB(string ct);
    object EncryptGCM(string pt);
    object DecryptGCM(string n, string m, string c);
    object GetSalt();
};
