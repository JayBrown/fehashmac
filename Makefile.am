## Makefile.am
## Process this file with automake to create Makefile.in
## hvf 24.03.06
## hvf 20.10.2008 lash algorithms included
## hvf 02.11.2008 move lash algo into lib
## hvf 19.01.2009 add hmac to symlinks
## hvf 17.08.2009 adapt to libtool 2.2.4
## hvf 29.03.2011 include also SHA512/256 and SHA512/224
## hvf 07.04.2011 include BLAKE224, BLAKE256, BLAKE384, BLAKE512
## hvf 09.04.2011 include GROESTL224, GROESTL256, GROESTL384, GROESTL512
## hvf 10.04.2011 include JH224, JH256, JH384, JH512
## hvf 11.04.2011 include KECCAK224, KECCAK256, KECCAK384, KECCAK512
## hvf 12.04.2011 include SKEIN224, SKEIN256, SKEIN384, SKEIN512, SKEIN1024
## hvf 21.12.2014 include SHA3-224, SHA3-256, SHA3-384, SHA3-512, SHAKE128, SHAKE256
## hvf 27.02.2015 include SHAKE128-b64, SHAKE256-b64
## hvf 01.05.2015 include XOFSHAKE128, XOFSHAKE128-b64, XOFSHAKE256, XOFSHAKE256-b64
## hvf 29.02.2016 remove XOFSHAKE128, XOFSHAKE128-b64, XOFSHAKE256, XOFSHAKE256-b64
## hvf 09.03.2015 include MD6-224, MD6-256, MD6-384, MD6-512
## hvf 01.08.2016 include md5sum2md5

ACLOCAL_AMFLAGS	= -I m4

## EXTRA_DIST contains files and directories
## that must be included in the distribution

EXTRA_DIST		= include Doc README.html docbook-xsl.css src/md5sum2md5

## SUBDIRS are subdirectories that want to be configured

SUBDIRS			= lib src

## extra install instructions - here we want to generate some links

HASHLIST	= md2 md4 md5 \
			sha1 sha224 sha256 sha384 sha512 sha512-224 sha512-256 \
			rmd128 rmd160 rmd256 rmd320 \
			whirl gost \
			lash160 lash256 lash384 lash512 tiger2 \
			blake224 blake256 blake384 blake512 \
			groestl224 groestl256 groestl384 groestl512 \
			jh224 jh256 jh384 jh512 \
			keccak224 keccak256 keccak384 keccak512 \
			skein224 skein256 skein384 skein512 skein1024 \
			sha3-224 sha3-256 sha3-384 sha3-512 shake128 shake256 \
			shake128-b64 shake256-b64 \
            md6-224 md6-256 md6-384 md6-512

## sha3-* and shake* are not used with HMAC, private communication from Gilles Van Assche

HMACLIST	= hmac-md2 hmac-md4 hmac-md5 \
			hmac-sha1 hmac-sha224 hmac-sha256 hmac-sha384 hmac-sha512 \
			hmac-sha512-224 hmac-sha512-256 \
			hmac-rmd128 hmac-rmd160 hmac-rmd256 hmac-rmd320 \
			hmac-whirl hmac-gost \
			hmac-lash160 hmac-lash256 hmac-lash384 hmac-lash512 hmac-tiger2 \
			hmac-blake224 hmac-blake256 hmac-blake384 hmac-blake512 \
			hmac-groestl224 hmac-groestl256 hmac-groestl384 hmac-groestl512 \
			hmac-jh224 hmac-jh256 hmac-jh384 hmac-jh512 \
			hmac-keccak224 hmac-keccak256 hmac-keccak384 hmac-keccak512 \
			hmac-skein224 hmac-skein256 hmac-skein384 hmac-skein512 \
			hmac-skein1024 \
            hmac-md6-224 hmac-md6-256 hmac-md6-384 hmac-md6-512

KMACLIST	= kmac-sha3-224 kmac-sha3-256 kmac-sha3-384 kmac-sha3-512 \
			kmac-shake128 kmac-shake256 

B64LIST		= shake128-b64 shake256-b64 

KMACB64LIST	= kmac-shake128-b64 kmac-shake256-b64 

REMOVELIST  = xofshake128 xofshake256 xofshake128-b64 xofshake256-b64 \
            kmac-xofshake128 kmac-xofshake256 kmac-xofshake128-b64 \
            kmac-xofshake256-b64

ALLLIST		= $(HASHLIST) $(HMACLIST) $(KMACLIST) $(B64LIST) $(KMACB64LIST)

install-exec-hook:
	cd $(DESTDIR)$(bindir); \
	   rm -f $(ALLLIST) $(REMOVELIST); \
	   for i in $(ALLLIST); do \
		$(LN_S) -f fehashmac $$i; done

## extra uninstall instructions: delete the links created at install time

uninstall-local:
	cd $(DESTDIR)$(bindir); \
	   rm -f $(ALLLIST) $(REMOVELIST);

