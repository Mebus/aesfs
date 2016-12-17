# AesFS: an encryption filesystem for FUSE based on AES

**Note:** I use it for my real data, but I also have a backup of my unencrypted
files.

## Introduction

Simple AES-256-GCM encryption filesystem for FUSE written in Python.

## Pre-requirements

### macOS Sierra

```
$ brew install cmake boost boost-python cryptopp python
```

## Installation

Runs with `Python 2.7.12` (macOS, Linux) or `Python 3.5.x` (Linux). Just
install the dependencies:

### fusepy

```
$ pip install fusepy
```

### Python 2.7.12:

fusepy needs the default encoding to be set to `utf-8`. You can check that with:
```
$ python2
Python 2.7.12 (default, Nov  7 2016, 11:55:55)
[GCC 6.2.1 20160830] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> import sys
>>> sys.getdefaultencoding()
'utf-8'
>>>
```

If it says `'ascii` you have to change it to `utf-8`:
```
$ printf "import sys\n\nsys.setdefaultencoding('utf-8')\n" | \
    sudo tee --append /usr/lib/python2.7/site-packages/sitecustomize.py > /dev/null
```

### libcryptr

On macOS:
```
$ mkdir build
$ cd build
$ cmake -DPYTHON_LIBRARY=/usr//local/Cellar/python/2.7.12_2/Frameworks/Python.framework/Versions/2.7/lib/libpython2.7.dylib ..
$ make all
$ mv libcryptr.dylib ../libcryptr.so && cd ..
```

On Linux:
```
$ mkdir build
$ cd build
$ cmake ..
$ make all
$ mv libcryptr.so ../libcryptr.so && cd ..
```

## Usage

Simplest way of running the application. Create two folders:

```
$ mkdir ~/encrypted/ ~/decrypted/
```

and execute:

```
$ python aesfs.py ~/encrypted/ ~/decrypted/
```

This will start the application in background.

Place your files into the `~/decrypted/` and they will be mirrored AES-256-GCM
encrypted to the `~/encrypted/` folder.

**Optionally:** You can move the `~/encrypted/` folder into your Dropbox, Google
Drive, etc.

For further options execute:

```
$ python aesfs.py -h
```

## Tested on

* macOS Sierra
* Arch Linux

