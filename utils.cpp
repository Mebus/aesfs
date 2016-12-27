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

#include "utils.hpp"

string b64encode(string decoded)
{
    unsigned int pad = (3 - decoded.length() % 3) % 3;
    string result(it_base64_t(decoded.begin()), it_base64_t(decoded.end()));
    result.append(pad, '=');
    return result;
}

string b64decode(string encoded)
{
    string result;
    unsigned int pad = count(encoded.begin(), encoded.end(), '=');
    replace(encoded.begin(), encoded.end(),'=','A'); // replace '=' by base64 encoding of '\0'
    result = string(it_binary_t(encoded.begin()), it_binary_t(encoded.end())); // decode
    result.erase(result.end() - pad, result.end());  // erase padding '\0' characters
    return result;
}

string fromPythonObject(const boost::python::object obj)
{
    return string(boost::python::extract<string>(obj));
}
