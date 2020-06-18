FEHASHMAC Version 2.1   07.09.2016
==================================
Harald von Fellenberg <hvf@hvf.ch>
:Author Initials: hvf
:toc:
:icons:
:numbered:
:website: http://fehashmac.sourceforge.net/

////////////////////////////////////////////////////////////
generate the file README.html from this file with

$ replexec.pl README.raw > README.txt
$ a2x -f xhtml README.txt

These two steps can be executed with

$ make
////////////////////////////////////////////////////////////

.Download
**************************************************************

The latest and all earlier releases can be downloaded from
http://fehashmac.sourceforge.net
**************************************************************


New Features
------------

*07.09.2016: Replace SHA3, keccak with new code base*

*02.08.2016: General cleanup.* 
            One potential buffer overrun in keccak has been fixed.
            The code has been checked against STACK for null pointers,
            three finding have been fixed. Doc has been reorganized.
            A shell script, md5sum2md5 has been added to convert
            from md5sum syntax to md5 style.

*11.07.2016: MD6 algorithms have been added.* 
            md6-224, md6-256, md6-384, md6-512, 
            although they had been retired from the SHA3 competition.
            Performance comparisons are available in the Doc directory.

*29.02.2016: SHA3 algorithms are now based on FIPS 202 issued August 2015.*
            shake128, shake256 support now extendable length output,
            the previously defined algos xofshake128, xofshake256 are
            now superseded by shake128, shake256 and are therefore abandoned.

*20.05.2015: KMAC implemented for SHA3 algorithms and XOFs.*
            README updated. Algorithm kmac-all selects all algorithms
			that support KMAC, all-b64 selects all algos that support
			Base64 encoding, and similarly kmac-all-b64. The KMAC key can
			either be an ASCII string (up to 253 bytes long, --key=xxx) or a 
			hex string (--hexkey=nnn), whose length in bits may be specified
			with --keylength=bbb (max value 254*8-1= 2031 bits).

*01.05.2015: Extendable Output Functions (XOFs) xofshake128, xofshake256.*
            Output length can be specified to an arbitrary number of
            bytes up to 9 Exabytes or infinity. BASE64 output is OK.

*27.02.2015: BASE64 support for SHAKE.*
            SHAKE can now produce BASE64 output.

*18.01.2015: SHA3 performance:*  +
            SHA3 is now implemented based on the 
            KeccakWidth1600Opt64LCu6 version in the 
            KeccakCodePackage (downloaded on 11.12.2014): 
            +$ git clone https://github.com/gvanas/KeccakCodePackage+
            This version gives good performance both
            on 32 and 64 bit Intel platforms as well as on an
            AMD GEODE based appliance. Reports about other platforms
            like SPARC are welcome.

*02.01.2015: The 6 SHA3 algorithms are now supported,*  +
            based on the
            Draft FIPS Pub 202 (May 2014): sha3-224, sha3-256,
            sha3-384, sha3-512 and the two extendable output functions
            (XOF) shake128 and shake256. Test vectors are included.
            Our implementation is based on the reference implementation,
            a more efficient implementation will follow in an update.

*28.01.2012: Multiple algorithms (including HMACs) can be specified
            simultaneously.* +
            The data files are read only once, and all
            hashes are calculated in parallel.
            As an option, algorithm "all" expands to the list of all
            known algorithms, which are thus calculated in parallel for
            each data file or string. 
            Likewise, algorithm "hmac-all" expands to all known 
            HMAC algorithms.
            The results of the --check option and the test cases are 
            nicely summarized.

*29.03.2011: Support for the sha512-224 sha512-256 algorithms*

*14.04.2011: HMAC test vectors added* for MD5, SHA1, RMD128, RMD160.
            List of algorithms is now sorted alphabetically.

*13.04.2011: Support for all SHA-3 finalists:* BLAKE, GROESTL, JH, KECCAK,
            SKEIN for 224. 256. 384, 512 bits hash length, 
            SKEIN also for 1024 bits.
            They all support bitwise operation, bitwise test vectors are
            included (taken from the SHA-3 submissions).
            HMAC support upgraded to FIPS PUB 198-1 (2008),
            HMAC test vectors added for sha{224, 256, 384, 512}.

Purpose
-------

FEHASHMAC is a collection of publicly known hash algorithms integrated
          into a command-line utility. FEHASHMAC also contains a set
          of known test vectors and results for each algorithm
          such that the correct implementation for each hardware
          platform and compiler version can directly be verified.

FEHASHMAC supports bitwise hash calculation for algorithms with
          available bitwise test vectors. Currently this applies to
          the SHA algorithms: sha1, sha224, sha256, sha384, sha512,
          and to the SHA-3 algorithms: sha3-224, sha3-256, sha3-384,
          sha3-512, shake128, shake256. The so-called Gillogly bitwise
          input has only been tested for sha1, but is also implemented
          in the SHA-2 hashes.

Bitwise hash calculation is also supported in sha512-224, sha512-256,
          whirl, but there are no bitwise test vectors available.

FEHASHMAC can also calculate hashed message authentication codes (HMAC)
          as specified in RFC 2104 and extended to arbitrary-length
          keys in FIPS PUB 198-1. The HMAC key can be specified as an
          ASCII string or as a hex string, and HMACs can be calculated
          for files, strings, and hex strings. 
          For SHA3, the KMAC message authentication is available, not HMAC.

To simplify usage, symbolic links with the algorithm name allow to call
fehashmac without the -a option. A prepended hmac- will automatically
enable HMAC mode. Likewise with kmac- and -b64 for KMAC and Base64.

Hashes and HMACs/KMACs of files can be verified with the --check option.

.Supported Algorithms (52) in 14 families:
**************************************************************

blake224 blake256 blake384 blake512 

gost 

groestl224 groestl256 groestl384 groestl512 

jh224 jh256 jh384 jh512 

keccak224 keccak256 keccak384 keccak512 

lash160 lash256 lash384 lash512 

md2 md4 md5 md6-224 md6-256 md6-384 md6-512

rmd128 rmd160 rmd256 rmd320 

sha1 

sha224 sha256 sha384 sha512 sha512-224 sha512-256 

sha3-224 sha3-256 sha3-384 sha3-512 shake128 shake256 

skein1024 skein224 skein256 skein384 skein512 

tiger2 

whirl 
**************************************************************

.Supported HMAC Algorithms (46): 
**************************************************************

hmac-blake224 hmac-blake256 hmac-blake384 hmac-blake512 

hmac-gost 

hmac-groestl224 hmac-groestl256 hmac-groestl384 hmac-groestl512 

hmac-jh224 hmac-jh256 hmac-jh384 hmac-jh512 

hmac-keccak224 hmac-keccak256 hmac-keccak384 hmac-keccak512 

hmac-lash160 hmac-lash256 hmac-lash384 hmac-lash512 

hmac-md2 hmac-md4 hmac-md5 
         hmac-md6-224 hmac-md6-256 hmac-md6-384 hmac-md6-512

hmac-rmd128 hmac-rmd160 hmac-rmd256 hmac-rmd320 

hmac-sha1 

hmac-sha224 hmac-sha256 hmac-sha384 hmac-sha512 hmac-sha512-224 
            hmac-sha512-256 

hmac-skein224 hmac-skein256 hmac-skein384 hmac-skein512
            hmac-skein1024 

hmac-tiger2 

hmac-whirl 
**************************************************************

.Supported KMAC Algorithms (6): 
**************************************************************

kmac-sha3-224 kmac-sha3-256 kmac-sha3-384 kmac-sha3-512 
              kmac-shake128 kmac-shake256 
**************************************************************

.Algorithms with Base64 Encoding (2): 
**************************************************************

shake128-b64 shake256-b64 
**************************************************************

.KMAC Algorithms with Base64 Encoding (2): 
**************************************************************

kmac-shake128-b64 kmac-shake256-b64 

**************************************************************

.Extendable Output Length (XOF) Algorithms (2):
**************************************************************

shake128 shake256 

**************************************************************

SHA3 supports KMAC, not HMAC . (Gilles van Assche, private
communication, 11.12.2014).


Usage
-----

Hash of a String
~~~~~~~~~~~~~~~~

	$ fehashmac -a md5 -s abc 
	# fehashmac -a md5 -s abc 
	md5 ("abc") = 900150983cd24fb0d6963f7d28e17f72
	
	or shorter:
	$ md5 -s abc

Hash of a Hex String
~~~~~~~~~~~~~~~~~~~~

	$ fehashmac -a md5 -M 0123456789abcdef
	# fehashmac -a md5 -M 0123456789abcdef 
	a1cd1d1fc6491068d91007283ed84489
	
Hash of One or More Files
~~~~~~~~~~~~~~~~~~~~~~~~~

	$ fehashmac -a sha1 /etc/passwd /etc/group /dev/null
	# fehashmac -a sha1 /etc/passwd /etc/group /dev/null 
	sha1 (/etc/passwd) = 3bfe53dda1882d0a60c8a01e3167c0a2f54635dc
	sha1 (/etc/group) = c999fc8f29b1a00a9f539b6b1f3d92816d2f8a49
	sha1 (/dev/null) = da39a3ee5e6b4b0d3255bfef95601890afd80709
	
	or shorter:
	$ sha1 /etc/passwd /etc/group /dev/null


Verify File Hashes
~~~~~~~~~~~~~~~~~~

	$ fehashmac -c some.sha1
	# fehashmac -c some.sha1 
	/etc/passwd: OK sha1
	/etc/group: OK sha1
	/dev/null: OK sha1
	
	Summary:
	--------
	Lines read:             4
	Hash entries read:      3
	Files found:            3
	Files OK:               3
	
	where some.sha1 contains the output of the example above.

HMAC of a String, Key is a String
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	$ fehashmac -a hmac-rmd256 -K Boss -s 'Yes,we can!'
	# fehashmac -a hmac-rmd256 -K Boss -s Yes,we can! 
	key (hmac) = Boss
	hmac-rmd256 ("Yes,we can!") = 2b2a8cf6cfd56b54d3a80a2067edff63d14ed06ef3c26b1ac972bba224274c89
	
	or shorter:
	$ hmac-rmd256 -K Boss -s 'Yes,we can!'

KMAC of a String, Key is a String
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	$ kmac-sha3-224 -K Boss -s 'Yes,we can!'
	# kmac-sha3-224 -K Boss -s Yes,we can! 
	key (kmac) = Boss
	sha3-224 ("Yes,we can!") = 354888bd9b45d43a33a3bfa1e88c5a7aeaefbade9e5d6d74034c316e
	
HMAC of One or More Files, Key is a Hex String
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	$ hmac-tiger2 --hexkey=fedcba9876543210 /etc/passwd /etc/group /dev/null
	# hmac-tiger2 --hexkey=fedcba9876543210 /etc/passwd /etc/group /dev/null 
	hexkey (hmac) = fedcba9876543210
	hmac-tiger2 (/etc/passwd) = 504b4be47f83b7a627f65606e3801d06400c9f0b1dd1947c
	hmac-tiger2 (/etc/group) = 4e1d9d34be3ed215ab220795a9215e40d0808ce4cefbbac8
	hmac-tiger2 (/dev/null) = 5b6a8380f59ecc8b3a97ce6be78c762fa16e30dbe2216e96
	
KMAC of One or More Files, Key is a Hex String
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	$ kmac-sha3-256 --hexkey=fedcba9876543210 /etc/passwd /etc/group /dev/null
	# kmac-sha3-256 --hexkey=fedcba9876543210 /etc/passwd /etc/group /dev/null 
	hexkey (kmac) = fedcba9876543210
	kmac-sha3-256 (/etc/passwd) = 022e401e71b5b1231fd41c58d006dad80fb72c2be2c8c606a462e5527584792e
	kmac-sha3-256 (/etc/group) = 38dcd3cfa3e7e8f360db1f437da902fc4b9c796864717c8caec2d1593cfe4fa5
	kmac-sha3-256 (/dev/null) = 67be22796350e0572605fd02b6519f91a14885339624f55c842dc795f4e15211
	

Bitwise Hash of a Hex String (For Supporting Algorithms)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	$ fehashmac -a sha1 --hexstring=98 --bits=5
	# fehashmac -a sha1 --hexstring=98 --bits=5 
	29826b003b906e660eff4027ce98af3531ac75ba
	
Multiple Hashes and/or HMACs
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
   
   Two hashes of some files, each file is read only once

	$ fehashmac -a md5,sha256 /etc/passwd /etc/group
	# fehashmac -a md5,sha256 /etc/passwd /etc/group 
	md5 (/etc/passwd) = 90f9c382b158f8c0ead223a147e317a0
	sha256 (/etc/passwd) = 1dca0e87a20ae69ba7721ce2ce579273781b64692122586716c39cd7bcb52ccb
	md5 (/etc/group) = 0ebfde8edd40a1109f63021a89fc0303
	sha256 (/etc/group) = 46b518d054ef83f79e00ccc9f607453d566acef5bbf59b959042d09ee0766c97
	
Hashes, HMACs and KMACs of Some Files
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	$ fehashmac -a md5,sha256,hmac-md5,hmac-sha256,kmac-sha3-384 --key="Jefe" /etc/passwd /etc/group
	# fehashmac -a md5,sha256,hmac-md5,hmac-sha256,kmac-sha3-384 --key=Jefe /etc/passwd /etc/group 
	key (hmac) = Jefe
	key (kmac) = Jefe
	md5 (/etc/passwd) = 90f9c382b158f8c0ead223a147e317a0
	sha256 (/etc/passwd) = 1dca0e87a20ae69ba7721ce2ce579273781b64692122586716c39cd7bcb52ccb
	hmac-md5 (/etc/passwd) = ab05e97e1d70a4ef877fe6231adefceb
	hmac-sha256 (/etc/passwd) = 50a3ba1ab5216ff8954b21537b24edeb41f273b0ada3756b2ad48e0850aada0e
	kmac-sha3-384 (/etc/passwd) = bf75b2e8a814d15865f89c37e149c4d99dfbd8fecf9584429b6709a513b6ccb8b3181973a266732744a3e230768a2419
	md5 (/etc/group) = 0ebfde8edd40a1109f63021a89fc0303
	sha256 (/etc/group) = 46b518d054ef83f79e00ccc9f607453d566acef5bbf59b959042d09ee0766c97
	hmac-md5 (/etc/group) = 19303c4b7602bde7ac01ed843be19c85
	hmac-sha256 (/etc/group) = f00a3d4b5c5ef1719c4a77ed11114eea4ba443049713de04ef2315ba435e9ccd
	kmac-sha3-384 (/etc/group) = 25f4bc24f4c748e3d8bf400d2947655a8dff6eae30dce9bb8f85500c54dfec86530337536f17596b0e93437fbcb006b0
	
Extendable Output Functions (XOFs) shake128, shake256
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	The default output length is 512 bytes, it can be modified by the --xoflength=nnn parameter, 
	possible values are up to 2**63-1 or -1 for infinity. Base64 output for any desired length is supported.

	$ fehashmac -a shake128 /etc/passwd /etc/group
	# fehashmac -a shake128 /etc/passwd /etc/group 
	length (xof) = 512
	shake128 (/etc/passwd) = 446aebc39db4ff0da57b50f99848073ca9c74095eb42c99fd260679951739070153aa69a4d4e6868519cbfb0b09cfc5c3f5690c0f2777b6282f7bbfbb9b5729cba8a74930744fd422de43c3fd9a4446e1f0bf425d4c5d9e65a9a6cb33b1bb91681fd6e46c58e76dbe678d93c150ca976faab8b1c527026c3d0b9e72b7f59df7d6ebe1c4054af9e06fb7ffe0d9e15524c580a876977b092fdf66e35beba09edac66dbde9cbdc17e22ecc34ebac8c8d4e13e3a25cf30c40486c3daa82f6d8e2dffcb7146f0fae95b660530d8f2ba3f68cf65902e5c1da8ff7f0276d11cc27963007814b1fb4e595d8bef8ff43bbdca7884905c14d5dd77f0359bb452a181196150fd83c152efc9bebb91469a520789b05825242e84f4ce9322ab7b86d336e7b6ae5843d29a807ac68c9461e2841e9184a55a8c66789948ca1e998ed2f37258078a47a10e7deb7f7248e51c1ac3ac5bda142b4252e5b4967d61d6fe26d538a7594ce93238ff66381983188710cae34d66100f553f9cd30ef7da85448f2d3ebeb261af31da21a5ab4f4cafc9479b36abb2b52671a2e354b9d70d6f06a867523e01b61fcd1f35e6e08515141e4fb4abc536dff7e2862fc9fcb57c5e2a4f8d20744b6cc78cc79658d1aa5f83d47a6858d96f4d41056ca5a57e712466dc57ba6de1cbda0237b182ef2b96c1413fc556a9b5d6ef1485e28295e552616da135aad55eecac
	length (xof) = 512
	shake128 (/etc/group) = 413d12520dec126d0087c73c342549bd204168eb48537fb4eb8a613ce0b8f920b609c8b555b0565d758683db0480f8db958e93c07692e8013052e6288417f6b730c2d96e92e0a7c48a93f3215a91dbeb321cff94996b554e228a4d7e2e4a5a51d5aae25f4282069c2653355efb016adc736133802e81f0b39877a9bd60bb9e7c48111b05edc98c90da8eac9be15593aa89be7ceb29ca354a8a134bea3da7aa80b6e1bb91088e09e260f7e73a766216cd27c7918da39e33b44ce93022060b361baffdb35376eb8c47d9a2e4d4946c58c7286876d8714c5148065be3dca5682abb91206ea6b59f4fd28ad20aaca96c5ff1253849833a92b8f89bbee2f889804022f966be70eb7a9f74f65a86e8507c03a8056a29df6d4f3a5bb80e60441c3c88ca6af7051f3603a8f07cb04a9e37a2ab834d628a53a84fd35260b1ec04a01b3906709f61e3cd11a24ccca7bfce3006dca01db711f415502fa5d1ad40416889df3eb9f322e91e878c883c27f5fe6b43f4a378e84b8a2940498f1401980f98e6fd6b27bc94cfd4d42e59bd1036a82d71f5e58f5046ec7498192f14a07689fd1164ab0c48cbfccc5de2ac68d1305a045c35cf490e1a4d69c31ea3bca7ec59e03515806d49dea44f8df8ec52a291ff8324016ca3ad2a1a8011bdfe18bb85614b6d064ac17d0a97c16b039668098db9b54772be965e630812db73f2287099a6bcb0bd98
	
	$ fehashmac -a shake128-b64 --xoflength=64 /dev/null
	# fehashmac -a shake128-b64 --xoflength=64 /dev/null 
	length (xof) = 64
	shake128-b64 (/dev/null) = f5wrpOiPgn1hYEVQdgWFPtc7gJP277yI6xpurPpm7yY8se6piABLkxA8+wru/SpobgH6Sljoo2OcqKHj+a5X4g==
	
	$ fehashmac -a shake128-b64 --xoflength=211 /dev/null | fehashmac -c
	# fehashmac -c 
	/dev/null: OK shake128-b64, match truncated to 211 bytes
	
	Summary:
	--------
	Lines read:             3
	Hash entries read:      2
	XOF lengths found:      1
	Files found:            1
	Files OK:               1
	

All Hash Algorithms Applied To One File
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	$ fehashmac -a all /etc/passwd
	# fehashmac -a all /etc/passwd 
	blake224 (/etc/passwd) = 5fd99e8979837079ae223ad68af6d1928c762bf429b7cfe174245576
	blake256 (/etc/passwd) = a4ae8d9a1b0ad470bcea3a1140998acf453aab0c66e4fbda0019f1a456ed84a5
	blake384 (/etc/passwd) = d77ab28fbad60d5443f4ab5d107c803627602ef892e62de281d02e441aac9d38efd29e5b663fc1c42386ab786d3c3be0
	blake512 (/etc/passwd) = d11e04bf00b4e00ed6cc3975094f03bbe82f79c63d31abe8e5e0af2501479d66bc89fb2854946cdbba279415161d75b3c9ada99d727b6009a5c09efac3413a25
	gost (/etc/passwd) = bc8137313eadc348209f897395177611e0bad256b67789d874dcd4f15d2c4751
	groestl224 (/etc/passwd) = 950f45295957caeea691b936644beceac969cd482e2dad8ebfea78c0
	groestl256 (/etc/passwd) = 349530e76cce8a9f4b9151827c7e6861a56f439290e7eccc8fc62936d0422cf8
	groestl384 (/etc/passwd) = 41d85c8793ab7dfb4b5ebc79667a1ee74833b42a23f77b7e92815ebaaafcda42ce939df33d3f41504858bbfc42ae0275
	groestl512 (/etc/passwd) = a7027dd91495d00733711368f764a68bb35f75e30cc6fdfe066fcf298c246a83643c583606ebb521b1c9ca00606230a9366e58a2b14342dca673fee8a10a761d
	jh224 (/etc/passwd) = b807c9c32b44a5c88bef9df8a0c1a90fb542856b0fdb3a4989885df5
	jh256 (/etc/passwd) = be9d3fbd60df419b03176a9a47e19b21acc96beb45ff2743c044dc1fad91beb4
	jh384 (/etc/passwd) = b71a44243910bfc0323b0256382bd0d2ece4ccb2f626e5a56f900819398cf5a822ecb816c79451f501ee78f82b0de814
	jh512 (/etc/passwd) = 67a09e29a88d16af6b20a803fe089dfc91944e2e4c8e6ac3746c12db3d436c6913c59a83894e24734b66f315ca421c6b860309f733e46dcdf29b1e4747d8cec0
	keccak224 (/etc/passwd) = ff3632ea650e6edc19330267676ae24022aeba3e7dba30138ea18e7e
	keccak256 (/etc/passwd) = 1e9fd31cbf6423a6372296afab38f5670f623a80eb8d29a4e21e2d875f850e77
	keccak384 (/etc/passwd) = 0b5f1eedda03e8883a4eb8c31f961c933b5fba4a77a384160dcb3105586dbfa398487ed7aa6e3d43ea3d9ccfa4e21e81
	keccak512 (/etc/passwd) = 9b39bcb1d876fff584e59679d68d7c4ae674fca048257d9cb39b3129dfd06f298989ce766e3789e4b16e03c07112894ed59d3cfdeb61d5b187bc09f7b860fc6c
	lash160 (/etc/passwd) = 82b266a5d097d0b8fe9445cf8c7cdaa7f64b2d49
	lash256 (/etc/passwd) = ea7dfdad74eea1a2471839a96dc3dc46e5273e53fd68784aad13030489c7755f
	lash384 (/etc/passwd) = 8a02d11d6a695bee523be0b9fa32bd42b7dec42dc697cbd001efdc6343a3ec6a49183838b49007bc0c41a045a1fb3fb1
	lash512 (/etc/passwd) = 768fec22c08de5d140970fe6974fc4eb2ace1ae7e565b17612fa123e1a110f813acc84b0e88704388f804bbb0395d92c4762a3e5810bffed083a62753eff86a9
	md2 (/etc/passwd) = 2aa6c7156cc1d8fe78a0d6895b9a0af1
	md4 (/etc/passwd) = 85e43cf8444563a8c35740feb30cba19
	md5 (/etc/passwd) = 90f9c382b158f8c0ead223a147e317a0
	md6-224 (/etc/passwd) = 692ae8839528641dcc748303e3545559b96b772fd4ae185c395e8dc3
	md6-256 (/etc/passwd) = a7d94be74bf41a27a0b6849e7a46f6c66c815f7ad0c1f78836e3a8f1082c8a46
	md6-384 (/etc/passwd) = d331f5be7e744bfcffe1ffbd7a3cc12eb8a2ddc41164b0d0366918b1d7efba4d40fe5cd18d6bd76618509040be834f74
	md6-512 (/etc/passwd) = dc7ce3d82b203066201b4cd2aa3ae47bbd9a94c1ff94fb0b6349ae2220d98fcefa38d31e8a56834a2a611b514796b2b3893184e8a3a9b0d7b3911f564c2b79fc
	rmd128 (/etc/passwd) = 7ad71d706e704c64a91c05c67b355657
	rmd160 (/etc/passwd) = 6b0237b5cdaec387ad025c8c691ece421b5d568c
	rmd256 (/etc/passwd) = 77361c4f6e10e4b82578fd8283c019a36723a738cab1672ff3bbd02ddde9a49e
	rmd320 (/etc/passwd) = 45a79b1aafa458db8a454e04c7d6d007d652f2b9b1592fd394553a0e3dd200e5fe36919791dfd8e6
	sha1 (/etc/passwd) = 3bfe53dda1882d0a60c8a01e3167c0a2f54635dc
	sha224 (/etc/passwd) = 3c64f0a9f76addd782a179bcd8ae534da1db01a0b68b72af3237e8b0
	sha256 (/etc/passwd) = 1dca0e87a20ae69ba7721ce2ce579273781b64692122586716c39cd7bcb52ccb
	sha3-224 (/etc/passwd) = 913f0fa046888efeea3fb18fc7db7a6087f8429972233a8163a33032
	sha3-256 (/etc/passwd) = 4a639bd068c7be1aa031c865a44d1d35fcb86dafe743872106a439aa20e4095a
	sha3-384 (/etc/passwd) = 527fb45f6de25fc3ba4df6c50d33931f7f5cfda75ac3cae16bd8a5abddc74ae42b84efb1108676b9bd267587ac539c91
	sha3-512 (/etc/passwd) = b39b9a171d0021ed9bb378a2f2ef32436dd160a08059c9e2fb66bd1b4bf91d4e3313c6d0f6cd6d3472c6a82df85b03cdeadc4fa0f2850afb95df0ffd8f969807
	sha384 (/etc/passwd) = 768941051d17dd3d651983a7b28425aed421844fea79ca17441db8cc20cd2f0ac10f04157aa2ab28a2609893c2be7fbf
	sha512 (/etc/passwd) = f1ef7da16818ba15f7f9263dfe11cd6acf0817b8e78e1d7b4994d6f7bf94e9aa7d54eb2a79b6d4e2d2aa93780ad48215792d09a6997489351b3d285be8937a9c
	sha512-224 (/etc/passwd) = 797064e83f9b40533e6308d0b8ccf1700099e02ec0a4b4393ab552fd
	sha512-256 (/etc/passwd) = c320e7bee940f8eb362a51982c275d73fe8210c5097dab3d796d399b9d1b93a6
	length (xof) = 512
	shake128 (/etc/passwd) = 446aebc39db4ff0da57b50f99848073ca9c74095eb42c99fd260679951739070153aa69a4d4e6868519cbfb0b09cfc5c3f5690c0f2777b6282f7bbfbb9b5729cba8a74930744fd422de43c3fd9a4446e1f0bf425d4c5d9e65a9a6cb33b1bb91681fd6e46c58e76dbe678d93c150ca976faab8b1c527026c3d0b9e72b7f59df7d6ebe1c4054af9e06fb7ffe0d9e15524c580a876977b092fdf66e35beba09edac66dbde9cbdc17e22ecc34ebac8c8d4e13e3a25cf30c40486c3daa82f6d8e2dffcb7146f0fae95b660530d8f2ba3f68cf65902e5c1da8ff7f0276d11cc27963007814b1fb4e595d8bef8ff43bbdca7884905c14d5dd77f0359bb452a181196150fd83c152efc9bebb91469a520789b05825242e84f4ce9322ab7b86d336e7b6ae5843d29a807ac68c9461e2841e9184a55a8c66789948ca1e998ed2f37258078a47a10e7deb7f7248e51c1ac3ac5bda142b4252e5b4967d61d6fe26d538a7594ce93238ff66381983188710cae34d66100f553f9cd30ef7da85448f2d3ebeb261af31da21a5ab4f4cafc9479b36abb2b52671a2e354b9d70d6f06a867523e01b61fcd1f35e6e08515141e4fb4abc536dff7e2862fc9fcb57c5e2a4f8d20744b6cc78cc79658d1aa5f83d47a6858d96f4d41056ca5a57e712466dc57ba6de1cbda0237b182ef2b96c1413fc556a9b5d6ef1485e28295e552616da135aad55eecac
	length (xof) = 512
	shake256 (/etc/passwd) = 14a2e3c72b4f4bdb198792d9a6a14e72590daf1d37c368739f7fbdc8d32c261b424759eb43ad3796dd68ea3ddd2ce6d6b3388494fd41f95d2abcbef703f58361fab87e80382d529c818afda59310cb80a7ef027747e9c05b453567fed1fc2b46865e64ec3bab077f9e4b74491af24fea583978ec52337965f1f9a5861be6334307c0ca8f63fed9701e6de6afcd38403c25d2fb27eb7cfd254e753cce132a45d53ab131f9b291006ac342339e62e3e72bc105fb4447e3ef0fbb365fc23c6ae57b5c6df19241db547e0b1046502055b12a771de2f84b6284e2a294dc4afb1c204c38fddbfd994a86e5d5b06e77acfbd5dfad3c195ca3eb45df408030b4bd57c8671dd114ed9969957a21d406c067bbc501c0bb7f0da008304e0a72abb0c02a418011573c5eab1b60cbd1a845f3d9f3992a9e5845e6339743981cbfe606c1c1936f76adf28e53ec0e53def3f3f411352468fa7c8bc64498cb9361b07ccc41c39ac43dd04613ea909b73618b6d9eedcbba4d08b8988e4e6c6e07d6b9a3e87deee983673ccd1a1b6dd34c7524514b9b50dd9ae52752f8fe40a59c2c7b201037e5f6bdfeb36a2b07fb36e050a9b32c5d231f16460caffdc4b31bf1fc959711e7b74eb3c5b3c049af320b0030f6d67030cfbe6082762538bda41726e21fde3a6df77c6d8436fdea87c2085cbf484b936d44236676190655c2fa661acae0b5e017e58eee
	skein1024 (/etc/passwd) = b6ec924e32787fb5e0b560e215a24b25d3ea574cd184deef5f6d880bfffedb086b8a1601b6a30de7af3001427aafd414105e8f14a508c4a53fb8339865d12caac0d24278ac7a58e4f35ee2114479457f7df26f2ac55adf66564b7d53b7dd25373388b61b549425fdf93704af7d542a0aef40de6ec398b0d037aa3a6cc67285e6
	skein224 (/etc/passwd) = a451ac1f1b1cd0336451a33cd6b4794eb38776e8de06a9e4ea605e28
	skein256 (/etc/passwd) = ae564daa3cae7b9df14d598c4243d841cb124d26034d338c6577bdb83967588c
	skein384 (/etc/passwd) = 0789e9529d44dc38d4e39e58b78eba216a3d7db905f70a2d882b943fb116a92e3b00c3113e328971f8bf3902b8fa1e86
	skein512 (/etc/passwd) = 4de0302dba3c2a784f10c4e9038cc16ae2da1dc2e5cceef731dbbea812a9786b73a8998e4fb921b0bff6596fe18ae11ad58d761c2271134e985de3cbaad821b0
	tiger2 (/etc/passwd) = 5fe6c1805dd4d1791f3093b65922bdfd97eb537b76e358b1
	whirl (/etc/passwd) = d614410d244613d2f542c0abc1a8be75d5ee59c954d964b11090d89e0863fabafd1f9d91de320fdfa1725c574bec1d5d0127ff7b7056d56a5fc0a055f587c43c
	
If you wish to include all Base64 encodings, use

	$ fehashmac -a all,all-b64 /etc/passwd

Test Suite
~~~~~~~~~~
	
	sha1 has tests for byte and bit strings and HMAC

	$ sha1 --test
	# sha1 --test 
	sha1 Test Suite:
	sha1 ("abc")  = a9993e364706816aba3e25717850c26c9cd0d89d  OK
	sha1 ("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")  = 84983e441c3bd26ebaae4aa1f95129e5e54670f1  OK
	sha1 ("a") (repeated 1000000 times) = 34aa973cd4c4daa4f61eeb2bdbad27316534016f  OK
	Tests passed: 3, tests failed: 0.
	
	sha1 Bitwise Test Suite:
	sha1 ("bitstring=110#148|11") = ce7387ae577337be54ea94f82c842e8be76bc3e1  OK
	sha1 ("bitstring=110#149") = de244f063142cb2f4c903b7f7660577f9e0d8791  OK
	sha1 ("bitstring=110#149|1") = a3d2982427ae39c8920ca5f499d6c2bd71ebf03c  OK
	sha1 ("bitstring=110#149|11") = 351aab58ff93cf12af7d5a584cfc8f7d81023d10  OK
	sha1 ("bitstring=110#170") = 996386921e480d4e2955e7275df3522ce8f5ab6e  OK
	sha1 ("bitstring=110#170|1") = bb5f4ad48913f51b157eb985a5c2034b8243b01b  OK
	sha1 ("bitstring=110#170|11") = 9e92c5542237b957ba2244e8141fdb66dec730a5  OK
	sha1 ("bitstring=110#171") = 2103e454da4491f4e32dd425a3341dc9c2a90848  OK
	sha1 ("bitstring=011#490") = b4b18049de405027528cd9e74b2ec540d4e6f06b  OK
	sha1 ("bitstring=011#490|0") = 34c63356b308742720ab966914eb0fc926e4294b  OK
	sha1 ("bitstring=011#490|01") = 75face1802b9f84f326368ab06e73e0502e9ea34  OK
	sha1 ("bitstring=011#491") = 7c2c3d62f6aec28d94cdf93f02e739e7490698a1  OK
	sha1 ("hexstring=98, bits=5") = 29826b003b906e660eff4027ce98af3531ac75ba  OK
	sha1 ("bitstring=10011") = 29826b003b906e660eff4027ce98af3531ac75ba  OK
	sha1 ("hexstring=5e, bits=8") = 5e6f80a34a9798cafc6a5db96cc57ba4c4db59c2  OK
	sha1 ("hexstring=49b2aec2 594bbe3a 3b117542 d94ac880, bits=123") = 6239781e03729919c01955b3ffa8acb60b988340  OK
	sha1 ("hexstring=9a7dfdf1 ecead06e d646aa55 fe757146, bits=128") = 82abff6605dbe1c17def12a394fa22a82b544a35  OK
	sha1 ("hexstring=65f93299 5ba4ce2c b1b4a2e7 1ae70220 aacec896 2dd4499cbd7c887a 94eaaa10 1ea5aabc 529b4e7e 43665a5a f2cd03fe678ea6a5 005bba3b 082204c2 8b9109f4 69dac92a aab3aa7c11a1b32a e0, bits=611") = 8c5b2a5ddae5a97fc7f9d85661c672adbf7933d4  OK
	sha1 ("hexstring=f78f9214 1bcd170a e89b4fba 15a1d59f 3fd84d22 3c9251bdacbbae61 d05ed115 a06a7ce1 17b7beea d24421de d9c32592bd57edea e39c39fa 1fe8946a 84d0cf1f 7beead17 13e2e0959897347f 67c80b04 00c20981 5d6b10a6 83836fd5 562a56cab1a28e81 b6576654 631cf165 66b86e3b 33a108b0 5307c00aff14a768 ed735060 6a0f85e6 a91d396f 5b5cbe57 7f9b38807c7d523d 6d792f6e bc24a4ec f2b3a427 cdbbfb, bits=1304") = cb0082c8f197d260991ba6a460e76e202bad27b3  OK
	Tests passed: 19, tests failed: 0.
	
	sha1 HMAC Test Suite:
	hexkey (hmac) = 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b
	hmac-sha1 ("Hi There")  = b617318655057264e28bc0b6fb378c8ef146be00  OK
	
	key (hmac) = Jefe
	hmac-sha1 ("what do ya want for nothing?")  = effcdf6ae5eb2fa2d27416d5f184df9c259a7c79  OK
	
	hexkey (hmac) = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
	hmac-sha1 ("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd")  = 125d7342b9ac11cd91a39af48aa17b4f63f175d3  OK
	
	hexkey (hmac) = 0102030405060708090a0b0c0d0e0f10111213141516171819
	hmac-sha1 ("cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd")  = 4c9007f4026250c6bc8414f9bf50c86c2d7235da  OK
	
	hexkey (hmac) = 0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c
	hmac-sha1 ("Test With Truncation")  = 4c1a03424b55e07fe7f27be1d58bb9324a9a5a04  OK
	
	hexkey (hmac) = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
	hmac-sha1 ("Test Using Larger Than Block-Size Key - Hash Key First")  = aa4ae5e15272d00e95705637ce8a3b55ed402112  OK
	
	hexkey (hmac) = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
	hmac-sha1 ("Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data")  = e8e99d0f45237d786d6bbaa7965c7808bbff1a91  OK
	
	Tests passed: 7, tests failed: 0.
	
	Summary of Test Results
	-----------------------
	
	sha1        Hash tests          : passed  3, failed 0
	sha1        Bitwise hash tests  : passed 19, failed 0
	sha1        HMAC tests          : passed  7, failed 0
	
	Categories: 3, Tests: 29, passed 29, failed 0.
	
    Note: all test cases for all algorithms can be executed using

	$ fehashmac -a all --test

shake128, shake256, can use Base64
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	$ shake128-b64 /etc/passwd
	# shake128-b64 /etc/passwd 
	length (xof) = 512
	shake128-b64 (/etc/passwd) = RGrrw520/w2le1D5mEgHPKnHQJXrQsmf0mBnmVFzkHAVOqaaTU5oaFGcv7CwnPxcP1aQwPJ3e2KC97v7ubVynLqKdJMHRP1CLeQ8P9mkRG4fC/Ql1MXZ5lqabLM7G7kWgf1uRsWOdtvmeNk8FQypdvqrixxScCbD0LnnK39Z331uvhxAVK+eBvt//g2eFVJMWAqHaXewkv32bjW+ugntrGbb3py9wX4i7MNOusjI1OE+OiXPMMQEhsPaqC9tji3/y3FG8PrpW2YFMNjyuj9oz2WQLlwdqP9/AnbRHMJ5YwB4FLH7Tlldi++P9Du9yniEkFwU1d138DWbtFKhgRlhUP2DwVLvyb67kUaaUgeJsFglJC6E9M6TIqt7htM257auWEPSmoB6xoyUYeKEHpGEpVqMZniZSMoemY7S83JYB4pHoQ59639ySOUcGsOsW9oUK0JS5bSWfWHW/ibVOKdZTOkyOP9mOBmDGIcQyuNNZhAPVT+c0w732oVEjy0+vrJhrzHaIaWrT0yvyUebNquytSZxouNUudcNbwaoZ1I+AbYfzR815uCFFRQeT7SrxTbf9+KGL8n8tXxeKk+NIHRLbMeMx5ZY0apfg9R6aFjZb01BBWylpX5xJGbcV7pt4cvaAjexgu8rlsFBP8VWqbXW7xSF4oKV5VJhbaE1qtVe7Kw=
	
    Alternate: $ shake128 --base64 /etc/passwd
    The --base64 (or shorter --b64) flag applies base64 output to all supporting algorithms.

Help Information
----------------

................................................................................
	$ fehashmac -h
	# fehashmac -h 
	Usage: fehashmac [ options ] [ file ..]
	 -or-  fehashmac -c [file]
	 -or-  fehashmac -t
	Generic Hash and HMAC Program fehashmac V2.1 07.09.2016
	Harald von Fellenberg (hvf at hvf dot ch)
	Supports HMAC (RFC 2104, FIPS PUB 198-1) for all hash algorithms.
	Supports SHA3 and SHAKE (FIPS PUB 202, August 2015).
	Supports base64 encoded output for SHAKE.
	Supports arbitrary extendable output lengths for SHAKE128, SHAKE256.
	Supports KMAC (http://keyak.noekeon.org/Keyak-1.2.pdf) for SHA3 algorithms.
	The previous algos XOFSHAKE are now integrated in SHAKE and are obsolete.
	Multiple hashes can be calculated simultaneously, files are read only once.
	
	The supported hash algorithms are (52): blake224 blake256 blake384 
	blake512 gost groestl224 groestl256 groestl384 groestl512 jh224 
	jh256 jh384 jh512 keccak224 keccak256 keccak384 keccak512 lash160 
	lash256 lash384 lash512 md2 md4 md5 md6-224 md6-256 md6-384 md6-512 
	rmd128 rmd160 rmd256 rmd320 sha1 sha224 sha256 sha3-224 sha3-256 
	sha3-384 sha3-512 sha384 sha512 sha512-224 sha512-256 shake128 
	shake256 skein1024 skein224 skein256 skein384 skein512 tiger2 
	whirl 
	
	The supported HMAC algorithms are (46): hmac-blake224 hmac-blake256 
	hmac-blake384 hmac-blake512 hmac-gost hmac-groestl224 hmac-groestl256 
	hmac-groestl384 hmac-groestl512 hmac-jh224 hmac-jh256 hmac-jh384 
	hmac-jh512 hmac-keccak224 hmac-keccak256 hmac-keccak384 hmac-keccak512 
	hmac-lash160 hmac-lash256 hmac-lash384 hmac-lash512 hmac-md2 
	hmac-md4 hmac-md5 hmac-md6-224 hmac-md6-256 hmac-md6-384 hmac-md6-512 
	hmac-rmd128 hmac-rmd160 hmac-rmd256 hmac-rmd320 hmac-sha1 hmac-sha224 
	hmac-sha256 hmac-sha384 hmac-sha512 hmac-sha512-224 hmac-sha512-256 
	hmac-skein1024 hmac-skein224 hmac-skein256 hmac-skein384 hmac-skein512 
	hmac-tiger2 hmac-whirl 
	
	The supported KMAC algorithms are (6): kmac-sha3-224 kmac-sha3-256 
	kmac-sha3-384 kmac-sha3-512 kmac-shake128 kmac-shake256 
	
	The supported algorithms with base64 encoding are (2): shake128-b64 
	shake256-b64 
	
	The supported KMAC algorithms with base64 encoding are (2): kmac-shake128-b64 
	kmac-shake256-b64 
	
	The supported algorithms with extendable output length (XOF) are (2): shake128 
	shake256 
	
	Options and arguments:
	  -a algo[,algo,...]    - choose algorithm(s), see list below
	  --algorithm=algo[,algo,...]  - choose algorithm(s), see list below
	                          these two arguments can be specified multiple times
	                          the files to be hashed are only read once.
	  -a hmac-algo[,...]    - choose HMAC algorithm with hash algo.
	                          Hash and HMAC algos may be freely mixed.
	  -a kmac-algo[,...]    - choose KMAC algorithm with hash algo.
	  -a algo-b64[,...]     - choose base64 encoding for hash algo.
	  -a all                - choose all hash algorithms
	  -a hmac-all           - choose all HMAC algorithms
	  -a kmac-all           - choose all KMAC algorithms
	  -a all-b64            - choose all algorithms that support base64 encoding
	  -a kmac-all-b64       - choose all algorithms that support KMAC and base64 encoding
	  -s string             - digests string for one algorithm
	  --string=string       - digests string for one algorithm
	  --bitstring=bitstring - digests bitstring (Jim Gillogly format, bbb#nnn|bb..)
	  --hexstring=hexstring - digests hexstring (like -M, --M=)
	  -t                    - runs time trial for all algorithms
	  --time                - runs time trial for all algorithms
	  -x                    - runs test script for one algorithm
	  --test                - runs test script for one algorithm
	  file ...              - digests file(s) for one algorithm
	  (none)                - digests standard input for one algorithm
	  -c [file]             - checks digests read from file or stdin
	  --check[=file]        - checks digests read from file or stdin
	  --bits=nn             - message length in number of bits (for SHA only)
	  -M hexstring          - message in hexadecimal
	  --M=hexstring         - message in hexadecimal
	  -h                    - print this text
	  --help                - print this text
	  --list                - print list of algorithms, one per line
	
	  HMAC options:
	  -K keystring          - HMAC key as ASCII string
	  --K=keystring         - HMAC key as ASCII string
	  --key=keystring       - HMAC key as ASCII string
	  --hexkey=hexkeystring - HMAC key in hexadecimal
	
	  KMAC options:
	  -K keystring          - KMAC key as ASCII string
	  --K=keystring         - KMAC key as ASCII string
	  --key=keystring       - KMAC key as ASCII string
	  --hexkey=hexkeystring - KMAC key in hexadecimal
	  --keylength=nnn       - length of KMAC key in bits (only for hexkey!)
	
	  Base64 options:
	  --b64                 - produce digest in base64 format (if supported)
	  --base64              - produce digest in base64 format (if supported)
	
	 XOF options:
	  --xoflength=longint   - length for extendable length output in bytes
	  --xoflength=0         - default length, 512 bytes
	  --xoflength=-1        - indefinite length
	                          length goes up to 9223372036854775807 (2**63-1) bytes
	
	
	Algorithm   Hash Size  Block Size  Bitwise    HMAC test  Base64
	            (bits)     (bytes)     Operation  Vectors
	blake224     224         64        yes          
	blake256     256         64        yes          
	blake384     384        128        yes          
	blake512     512        128        yes          
	gost         256         32        no           
	groestl224   224         64        yes          
	groestl256   256         64        yes          
	groestl384   384        128        yes          
	groestl512   512        128        yes          
	jh224        224         64        yes          
	jh256        256         64        yes          
	jh384        384         64        yes          
	jh512        512         64        yes          
	keccak224    224        144        yes          
	keccak256    256        136        yes          
	keccak384    384        104        yes          
	keccak512    512         72        yes          
	lash160      160         40        no           
	lash256      256         64        no           
	lash384      384         96        no           
	lash512      512        128        no           
	md2          128         16        no           
	md4          128         64        no           
	md5          128         64        no         yes  
	md6-224      224        512        yes          
	md6-256      256        512        yes          
	md6-384      384        512        yes          
	md6-512      512        512        yes          
	rmd128       128         64        no         yes  
	rmd160       160         64        no         yes  
	rmd256       256         64        no           
	rmd320       320         64        no           
	sha1         160         64        yes        yes  
	sha224       224         64        yes        yes  
	sha256       256         64        yes        yes  
	sha3-224     224        144        yes        no support  
	sha3-256     256        136        yes        no support  
	sha3-384     384        104        yes        no support  
	sha3-512     512         72        yes        no support  
	sha384       384        128        yes        yes  
	sha512       512        128        yes        yes  
	sha512-224   224        128        yes, no testvectors          
	sha512-256   256        128        yes, no testvectors          
	shake128    4096        168        yes        no support  yes
	shake256    4096        136        yes        no support  yes
	skein1024   1024        128        yes          
	skein224     224         32        yes          
	skein256     256         32        yes          
	skein384     384         64        yes          
	skein512     512         64        yes          
	tiger2       192         64        no           
	whirl        512         64        yes, no testvectors          
	
	References:
	blake224  : BLAKE homepage http://www.131002.net/blake/
	blake256  : BLAKE homepage http://www.131002.net/blake/
	blake384  : BLAKE homepage http://www.131002.net/blake/
	blake512  : BLAKE homepage http://www.131002.net/blake/
	gost      : GOST R 34.11-94, the Russian equivalent of SHA.
	            http://www.autochthonous.org/crypto/gosthash.tar.gz
	groestl224: GROESTL homepage http://www.groestl.info/
	groestl256: GROESTL homepage http://www.groestl.info/
	groestl384: GROESTL homepage http://www.groestl.info/
	groestl512: GROESTL homepage http://www.groestl.info/
	jh224     : JH homepage http://www3.ntu.edu.sg/home/wuhj/research/jh/
	jh256     : JH homepage http://www3.ntu.edu.sg/home/wuhj/research/jh/
	jh384     : JH homepage http://www3.ntu.edu.sg/home/wuhj/research/jh/
	jh512     : JH homepage http://www3.ntu.edu.sg/home/wuhj/research/jh/
	keccak224 : KECCAK homepage http://keccak.noekeon.org/
	keccak256 : KECCAK homepage http://keccak.noekeon.org/
	keccak384 : KECCAK homepage http://keccak.noekeon.org/
	keccak512 : KECCAK homepage http://keccak.noekeon.org/
	lash160   : http://csrc.nist.gov/pki/HashWorkshop/2006/Papers/SAARINEN_lash4-1_ORIG.pdf
	lash256   : http://csrc.nist.gov/pki/HashWorkshop/2006/Papers/SAARINEN_lash4-1_ORIG.pdf
	lash384   : http://csrc.nist.gov/pki/HashWorkshop/2006/Papers/SAARINEN_lash4-1_ORIG.pdf
	lash512   : http://csrc.nist.gov/pki/HashWorkshop/2006/Papers/SAARINEN_lash4-1_ORIG.pdf
	md2       : RFC1319, http://www.ietf.org/rfc/rfc1319.txt
	md4       : RFC1320, http://www.ietf.org/rfc/rfc1320.txt
	md5       : RFC1321, http://www.ietf.org/rfc/rfc1321.txt
	md6-224   : http://groups.csail.mit.edu/cis/md6/
	md6-256   : http://groups.csail.mit.edu/cis/md6/
	md6-384   : http://groups.csail.mit.edu/cis/md6/
	md6-512   : http://groups.csail.mit.edu/cis/md6/
	rmd128    : http://www.esat.kuleuven.ac.be/~bosselae/ripemd160.html
	rmd160    : http://www.esat.kuleuven.ac.be/~bosselae/ripemd160.html
	rmd256    : http://www.esat.kuleuven.ac.be/~bosselae/ripemd160.html
	rmd320    : http://www.esat.kuleuven.ac.be/~bosselae/ripemd160.html
	sha1      : FIPS PUB 180-4, March 2012, http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf
	sha224    : FIPS PUB 180-4, March 2012, http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf
	sha256    : FIPS PUB 180-4, March 2012, http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf
	sha3-224  : FIPS PUB 202, August 2015, http://dx.doi.org/10.6028/NIST.FIPS.202
	sha3-256  : FIPS PUB 202, August 2015, http://dx.doi.org/10.6028/NIST.FIPS.202
	sha3-384  : FIPS PUB 202, August 2015, http://dx.doi.org/10.6028/NIST.FIPS.202
	sha3-512  : FIPS PUB 202, August 2015, http://dx.doi.org/10.6028/NIST.FIPS.202
	sha384    : FIPS PUB 180-4, March 2012, http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf
	sha512    : FIPS PUB 180-4, March 2012, http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf
	sha512-224: FIPS PUB 180-4, March 2012, http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf
	sha512-256: FIPS PUB 180-4, March 2012, http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf
	shake128  : FIPS PUB 202, August 2015, http://dx.doi.org/10.6028/NIST.FIPS.202
	shake256  : FIPS PUB 202, August 2015, http://dx.doi.org/10.6028/NIST.FIPS.202
	skein1024 : SKEIN homepage http://www.skein-hash.info/
	skein224  : SKEIN homepage http://www.skein-hash.info/
	skein256  : SKEIN homepage http://www.skein-hash.info/
	skein384  : SKEIN homepage http://www.skein-hash.info/
	skein512  : SKEIN homepage http://www.skein-hash.info/
	tiger2    : http://www.cs.technion.ac.il/~biham/Reports/Tiger/
	            This code implements the Tiger 2 padding (like MD5)
	whirl     : http://www.larc.usp.br/~pbarreto/WhirlpoolPage.html
	
...............................................................................
