## Makefile.am
## process this file with automake to produce Makefile.in
## hvf 27.03.06 31.01.2007 12.02.2007 19.10.2008
## hvf 02.11.2008 integrate LASH
## hvf 14.11.2008 integrate Tiger2
## hvf 20.01.2009 create LASH tables on the fly
## hvf 29.03.2011 include also sha512-224 and sha512-256 algorithms
## hvf 04.04.2011 integrate BLAKE
## hvf 09.04.2011 integrate GROESTL
## hvf 10.04.2011 integrate JH
## hvf 10.04.2011 integrate KECCAK
## hvf 11.04.2011 integrate SKEIN
## hvf 01.02.2012 add readdigest.c digeststring.c
## hvf 03.03.2012 add hash-a-file.c
## hvf 21.12.2014 integrate SHA3 (FIPS 202 Draft)
## hvf 08.01.2015 use optimized version of SHA3 (64 bit)
## hvf 02.02.2015 add base64.c
## hvf 08.03.2016 integrate MD6 (md6_compress.c md6_mode.c md6_nist.c)

## define where the Include-files can be found

INCLUDES    = -I$(top_srcdir)/include

noinst_LTLIBRARIES	= libfehashmac.la
libfehashmac_la_SOURCES	= md2.c md4.c md5.c \
						rmd128.c rmd160.c rmd256.c rmd320.c \
						sha1.c sha224-256.c sha384-512.c \
						whirl.c gost.c \
						lash-mktables.c \
						lash160.c lash256.c lash384.c lash512.c \
						tiger2.c tiger-sboxes.c \
						blake_opt32.c groestl-opt.c jh_ansi_opt32.c \
						skein_SHA3api_ref.c skein.c skein_block.c \
						fehashmac-common.c readdigest.c digeststring.c \
						hash-a-file.c \
						KeccakHash.c KeccakSponge.c KeccakNIST.c \
						KeccakP-1600-opt64.c \
						base64.c \
                        md6_compress.c md6_mode.c md6_nist.c

nodist_libfehashmac_la_SOURCES = 

CLEANFILES    =

## set CFLAGS

AM_CFLAGS	= -Wall

##prng: prng.c ../include/lash.h
##	$(CC) -O -g3 -I../include $< -o $@

## define the target that is to be built

##bin_PROGRAMS		= lash_prng

## define the source files for each target

##lash_prng_SOURCES	= lash_prng.c
##lash_main160_SOURCES	= lash_main160.c ../lib/lash160.c

