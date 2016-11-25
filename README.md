# AesFS: an encryption filesystem for FUSE based on AES

**Note:** Not ready for real data! Experimental!

## Introduction

Simple AES-256-GCM encryption filesystem for FUSE written in Python.

## Installation

Runs with `Python 2.7.x` or `Python 3.5.x`. Just install the dependencies:

```
$ pip install fusepy pycryptodome
```

### Python 2.7.x:

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

Tested on:

* macOS Sierra
* Arch Linux

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

