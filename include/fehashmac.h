/*
 * Generic Hash and HMAC Program
 *
 * Copyright (C) 2009 Harald von Fellenberg <hvf@hvf.ch>
 *
 * This program is free software; you can redistribute it and/or modify 
 * it under the terms of the GNU General Public License as published by 
 * the Free Software Foundation; either version 3 of the License, or 
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but 
 * WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

/*  fehashmac.h	Generic header file for common definitions
 *
 *	hvf 15.9.01
 *	add LASH160	hvf 19.10.2008
 *	hvf 29.12.2008 add bitwise test vectors
 *	hvf 31.01.2009 align with SHA3-C-API
 *  hvf 29.03.2011 add SHA512-224 and SHA512-256 test vectors
 *	hvf 05.04.2011 add BLAKE
 *  hvf 24.12.2014 add SHA3 stuff
 *	hvf 30.12.2014 add hmac_OK flag (sha3-*, shake* don't support HMAC)
 *  hvf 27.02.2015 add base64_OK flag
 *  hvf 08.03.2016 add MD6
 */

#ifndef _FEHASHMAC_H_
#define _FEHASHMAC_H_

#include	"generic.h"
#include	"sha.h"
#include	"mdx.h"
#include	"rmdx.h"
#include	"whirl.h"
#include	"gost.h"
#include	"lash.h"
#include	"tiger.h"
#include	"blake_opt32.h"
#include	"groestl-opt.h"
#include	"jh_ansi_opt32.h"
#include	"skein_SHA3api_ref.h"
#include	"KeccakHash.h"
#include	"md6_nist.h"

#define DEBUG
#undef  DEBUG

typedef struct {
    char    *string;
	int		keytype;
	int		 repeat;
    char    *digest;
} TestVector;

typedef struct {
	char	*hexstring;
	char	*bitstring;
	int		type;
	int		bitsize;
	char	*digest;
	char	*bitreference;
} TestVectorBitwise;

// we have only one reference for HMAC, RFC 2104 for md5

typedef struct {
	char	*key;
	char	*hexkey;
	int		keytype;
	char	*string;
	char	*hexstring;
	char	stringtype;
	char	*digest;
	char	*hmacreference;
} HMACTestVector;

#define	IS_HEXSTRING 1
#define	IS_BITSTRING 2
#define IS_ASCIISTRING 3

// we need this typedef for casting 
typedef	HashReturn (*HASHINIT)	(hashState *, int, ... );	

struct hash_algo {
	/* the name of the hash algorithm */
	char *name;
	/* the init function, inits a ptr	*/
	/* extra data can be supplied in a third parameter */
	HashReturn (*init)	(hashState *, int, ... );	
	/* the update function	*/
	HashReturn (*update) (hashState, const BitSequence *, DataLength);	
	/* the final function	*/
	HashReturn (*final) (hashState, BitSequence *);
	/* the all-in-one function */
	HashReturn (*hash) (int, const BitSequence *, DataLength, BitSequence *);
	/* the free function	*/
	void (*free)	(hashState);
	/* hash into byte array	*/
	HashReturn (*hashtobyte)(hashState, BYTE *out);	
	/* the read file function	*/
	HashReturn (*file)	(hashState, FILE *in);
	/* pointer to an array of test vectors */
	TestVector		*testvector;
	/* pointer to array of bitwise test vectors */
	TestVectorBitwise	*testvector_b;
	/* ptr to HMAC test vectors */
	HMACTestVector	*hmactestvector;
	/* the length of the produced hash output (bytes)	*/
	int  hash_length;
	/* length of input buffer in bytes */
	int  inputbuffer_length;
	/* bibliographic reference of algorithm */
	char *reference;
	/* 1 if bitwise ops are supported */
	/* 2 if bitwise ops are supported, but no published test vectors avail. */
	int  bitwise_support;
	// int  hmac_OK;	// cleared for sha3-*, shake*
	int  mac_OK;	// 1 for HMAC, 2 for KMAC (bitmask)
	int  base64_OK;	// set if base64 output of hash is OK
	int  xof_OK_defaultLength;	/* set to default length if variable 
								 * output length is OK (XOFSHAKExxx) */
};

/* HMAC, KMAC selectors	*/
#define hmac_OK(bitmask) ((bitmask) & 0x01)
#define kmac_OK(bitmask) ((bitmask) & 0x02)

/*	linked list of algorithms that we use for each file	*/

struct	use_algo	{
	char				*name;		/* name of algo, including hmac- */
	struct	hash_algo	*a;			/* ptr to algo */
	hashState			context;	/* opaque handle	*/
	BYTE				*ipad;		/* padding buffer for HMAC */
	BYTE				*opad;		/* padding buffer for HMAC */
	BYTE				*keypack;	/* keypack buffer for KMAC */
	int					keypacklen;	/* length of keypack in bytes */
	struct	use_algo	*next;		/* forward link */
	int					hmacflag;	/* 1 if hmac requested */
	int					kmacflag;	/* 1 if kmac requested */
	struct	extra		extra;		/* extra data for XOFSHAKEnnn	*/
};

/* generic head of all contextes	*/
typedef struct {
    /* required field: hashbitlen   */
    unsigned int    hashbitlen;

    /* magic token - SHA3-xxx in LSB notation   */
    DataLength      magic;
} GEN_CTX;


/*	test results are returned in this struct	*/

struct	test_results	{
	char					*name;		/* name of algo */
	char					*test_type;	/* name of test type */
	struct	test_results	*next;	/* forward link */
	int						tests_ok;
	int						tests_failed;
};


extern TestVector SHA1_testvector[];
extern TestVector SHA224_testvector[];
extern TestVector SHA256_testvector[];
extern TestVector SHA384_testvector[];
extern TestVector SHA512_testvector[];
extern TestVector SHA512_224_testvector[];
extern TestVector SHA512_256_testvector[];

extern TestVector SHA3_224_testvector[];
extern TestVector SHA3_256_testvector[];
extern TestVector SHA3_384_testvector[];
extern TestVector SHA3_512_testvector[];
extern TestVector SHAKE128_testvector[];
extern TestVector SHAKE256_testvector[];

extern TestVectorBitwise SHA1_testvector_bitwise[];
extern TestVectorBitwise SHA224_testvector_bitwise[];
extern TestVectorBitwise SHA256_testvector_bitwise[];
extern TestVectorBitwise SHA384_testvector_bitwise[];
extern TestVectorBitwise SHA512_testvector_bitwise[];

extern TestVectorBitwise SHA3_224_testvector_bitwise[];
extern TestVectorBitwise SHA3_256_testvector_bitwise[];
extern TestVectorBitwise SHA3_384_testvector_bitwise[];
extern TestVectorBitwise SHA3_512_testvector_bitwise[];
extern TestVectorBitwise SHAKE128_testvector_bitwise[];
extern TestVectorBitwise SHAKE256_testvector_bitwise[];

extern TestVector MD6_224_testvector[];
extern TestVector MD6_256_testvector[];
extern TestVector MD6_384_testvector[];
extern TestVector MD6_512_testvector[];

extern TestVectorBitwise MD6_224_testvector_bitwise[];
extern TestVectorBitwise MD6_256_testvector_bitwise[];
extern TestVectorBitwise MD6_384_testvector_bitwise[];
extern TestVectorBitwise MD6_512_testvector_bitwise[];

extern TestVector MD2_testvector[];
extern TestVector MD4_testvector[];
extern TestVector MD5_testvector[];

extern TestVector RIPEMD128_testvector[];
extern TestVector RIPEMD160_testvector[];
extern TestVector RIPEMD256_testvector[];
extern TestVector RIPEMD320_testvector[];

extern TestVector WHIRL_testvector[];

extern TestVector GOST_testvector[];

extern TestVector LASH160_testvector[];
extern TestVector LASH256_testvector[];
extern TestVector LASH384_testvector[];
extern TestVector LASH512_testvector[];

extern TestVector TIGER_testvector[];

extern TestVector BLAKE224_testvector[];
extern TestVectorBitwise BLAKE224_testvector_bitwise[];
extern TestVector BLAKE256_testvector[];
extern TestVectorBitwise BLAKE256_testvector_bitwise[];
extern TestVector BLAKE384_testvector[];
extern TestVectorBitwise BLAKE384_testvector_bitwise[];
extern TestVector BLAKE512_testvector[];
extern TestVectorBitwise BLAKE512_testvector_bitwise[];

extern TestVector GROESTL224_testvector[];
extern TestVectorBitwise GROESTL224_testvector_bitwise[];
extern TestVector GROESTL256_testvector[];
extern TestVectorBitwise GROESTL256_testvector_bitwise[];
extern TestVector GROESTL384_testvector[];
extern TestVectorBitwise GROESTL384_testvector_bitwise[];
extern TestVector GROESTL512_testvector[];
extern TestVectorBitwise GROESTL512_testvector_bitwise[];

extern TestVector JH224_testvector[];
extern TestVectorBitwise JH224_testvector_bitwise[];
extern TestVector JH256_testvector[];
extern TestVectorBitwise JH256_testvector_bitwise[];
extern TestVector JH384_testvector[];
extern TestVectorBitwise JH384_testvector_bitwise[];
extern TestVector JH512_testvector[];
extern TestVectorBitwise JH512_testvector_bitwise[];

extern TestVector KECCAK224_testvector[];
extern TestVectorBitwise KECCAK224_testvector_bitwise[];
extern TestVector KECCAK256_testvector[];
extern TestVectorBitwise KECCAK256_testvector_bitwise[];
extern TestVector KECCAK384_testvector[];
extern TestVectorBitwise KECCAK384_testvector_bitwise[];
extern TestVector KECCAK512_testvector[];
extern TestVectorBitwise KECCAK512_testvector_bitwise[];

extern TestVector SKEIN224_testvector[];
extern TestVectorBitwise SKEIN224_testvector_bitwise[];
extern TestVector SKEIN256_testvector[];
extern TestVectorBitwise SKEIN256_testvector_bitwise[];
extern TestVector SKEIN384_testvector[];
extern TestVectorBitwise SKEIN384_testvector_bitwise[];
extern TestVector SKEIN512_testvector[];
extern TestVectorBitwise SKEIN512_testvector_bitwise[];
extern TestVector SKEIN1024_testvector[];
extern TestVectorBitwise SKEIN1024_testvector_bitwise[];

extern HMACTestVector SHA1_HMACtestvector[];
extern HMACTestVector SHA224_HMACtestvector[];
extern HMACTestVector SHA256_HMACtestvector[];
extern HMACTestVector SHA384_HMACtestvector[];
extern HMACTestVector SHA512_HMACtestvector[];

extern HMACTestVector MD5_HMACtestvector[];

extern HMACTestVector RIPEMD128_HMACtestvector[];
extern HMACTestVector RIPEMD160_HMACtestvector[];

extern void    hash_error (HashReturn retval);

/* buffer size for reading and processing files */
#define	LARGEBUFSIZ	(8*BUFSIZ)
extern char    filebuffer[LARGEBUFSIZ];    // file read buffer, big

/* buffer size for hashes (like shake128 with 4096 bits) */
/* Solaris uses a BUFSIZ of 1024 */
/* we put HASHBUFSIZ to 4800 for xofshake128, xofshake256 - hvf 22.02.2016 */
#if BUFSIZ >= 4800
#define HASHBUFSIZ BUFSIZ
#else
#define HASHBUFSIZ 4800
#endif

extern	struct hash_algo HashTable[];

void DigestBitStringGillogly (struct hash_algo *a, char *bitstringgillogly);
void do_BitStringGillogly (struct hash_algo *a, void *context,
        char *bitstringgillogly);
void do_HexString (struct hash_algo *a, void *context, char *hexstring,
    uint64 bitcount, int bitwise_OK);
void maketokens (char *buf);
struct token *getnexttoken ();

void ReadDigest (char *listfilename);
int  TestSuite (struct use_algo *ua, struct test_results *t);
int  TestSuiteBitwise (struct use_algo *ua, struct test_results *t);
int  TestSuiteHMAC (struct use_algo *ua, struct test_results *t);
void DigestString (struct use_algo *ua, char *string);
void    TimeTrial();
void DigestHexString (struct use_algo *ua, char *hexstring,
    int bitflag, uint64 bitcount);
int hextobin (int c);		// convert a hex char into its binary value
// returns number of nibbles that have been copied
int copyhextobin (BYTE out[], int outlen, char *hexstring, int hexlen);

// hash one file, multiple hashes, in parallel
void    hash_one_file (const char *filename, struct use_algo *ua);

// print base64 output
void    print_b64 (const unsigned char *out, size_t outlen);

/* compare (binary) hash in hash_out[] with the ASCII digest in digest */
/* digest may contain white space */

int verify_hash (BYTE hash_out[], char *digest, int len);

// global variables for HMAC operation, we can then use macros to
// simplify quality assurance

extern int     hmacflag;       // HMAC request: key and algo required
extern int     kmacflag;       // KMAC request: key and algo required
extern int     keyflag;        // HMAC key supplied as ascii string:
                            	// -K, --K=, --key=
extern int     hexkeyflag;     // HMAC key supplied as hex string:
                            	// --hexkey=
extern char    *keystring;      // ASCII key string (for HMAC)
extern char    *hexkeystring;   // key string in hex (for HMAC)

extern int     HashTableSize;	// number of entries in HashTable
#endif
