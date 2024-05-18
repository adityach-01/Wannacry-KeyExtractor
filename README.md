WannaCry KeyExtractor
========

WARNING
=======

This software has only been tested and known to work under Windows XP, 7 x86, 2003, Vista and Windows Server 2008.


Introduction
============

This software allows to recover the prime numbers of the RSA private key that are used by Wanacry by creating a full memory dump of the Wanacry encryption process and searching for the primes in the created dump file. Although Wanacry destroys the keys using Windows Crypto API, the main issue is that the ``CryptDestroyKey`` and ``CryptReleaseContext`` does not erase the prime numbers from memory before freeing the associated memory. This means that creating a full dump of the encrypting process may contain the prime numbers if we are lucky, that is the associated memory hasn't been reallocated and erased.

From what I have observed, creating a dump during the encryption process increases the chances that the primes are still in the memory, so its best to run this software while encryption is taking place. For more information about the working of Wanacry, refer to the resources in doc/.


Usage
=====

You can use the binary ``KeyExtractor.exe`` in the bin/ folder. It will locate the encryption PID by itself. If it can't, you might need to run the executable by using ``-custom`` flag, which would then ask you to specify the executable name and parent directory to the software. 
If you already have the dump file and the public key file and want to extract the private key, invoke the executable using ``-nodump`` flag, and then specify the absolute path of the dump file and the pubic key. Otherwise, run the executable with no flags.

If the key had been succeesfully generated, you will just need to use the "Decrypt" button of the malware to decrypt your files!. Make sure that the private key resides in the same directory in which Wanacry executable is started. Sample public key and corresponding dump file has been placed in data/ folder, you can use those to generate a sample private key.


Compile from source
===================

You can make changes to the source code and compile from the source as well. Install the ``boost`` library on the system and specify its path in the makefile by changing ``BOOST_LIB_PATH`` inside makefile. 
After this is done, go inside the keyExtractor/ folder and run ``make``. After this, the executable named ``KeyExtractor.exe`` will be created and can be used.


