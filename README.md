# AesFS: an encryption filesystem for FUSE based on AES

**Note:** Not ready for real data! Experimental!

## Introduction

Simple AES-256-GCM encryption filesystem for FUSE written in Python.

## Installation

Runs with `Python 2.7.x` or `Python 3.5.x`. Just install the dependencies:

```
$ pip install fusepy pycryptodome
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

