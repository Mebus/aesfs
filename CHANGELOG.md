### 0.6.0

* Add Crypto++ implementation
* Align Python and C++ implementations
* Add C++ Boost wrapper for Cryptr
* Use normal parameters instead of args/kwargs
* Use function instead of variable

### 0.5.0

* Open file for writing not only appending
* Log flags for os.open()
* Find the correct start of block if offset % read\_size != 0
* Log path instead of full\_path
* Fix variable not found
* Use \*nix style wording
* Use padding function from library

### 0.4.0

* Remove hard-coded password and read it from prompt
* Use a master key to en-/decrypt files
* Make sure root directory is empty initially
* Save/load random salt to/from configuration file
* Add file/directory name en- and decryption
