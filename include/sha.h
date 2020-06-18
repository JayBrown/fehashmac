/*
 * Generic Hash and HMAC Program
 *
 * Copyright (C) 2009 2011 Harald von Fellenberg <hvf@hvf.ch>
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

/* sha.h - header file for SHA algorithms:
 * sha-1 sha-224 sha-256 sha-384 sha-512 sha-512-224 sha-512-256
 *
 * see FIPS PUB 180-1, 1993 May 11
 * see FIPS PUB 180-2, 2002 August 1, + Change Notice to include SHA-224
 * see FIPS PUB 180-3
 * http://www.itl.nist.gov/fipspubs/fip180-1.htm
 * http://csrc.nist.gov/encryption/shs/sha256-384-512.pdf
 * http://csrc.nist.gov/publications/fips/fips180-2/fips180-2withchangenotice.pdf
 * http://csrc.nist.gov/publications/fips/fips180-3/fips180-3_final.pdf
 *
 * hvf 23.1.2000 10.8.2001 31.01.2007 
 * hvf 31.01.2009 aligh with SHA3-C-API
 *
 * hvf 29.03.2011 add sha-512-224, sha-512-256, see
 * http://csrc.nist.gov/publications/drafts/fips180-4/Draft-FIPS180-4_Feb2011.pdf
 * http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/SHA512_224.pdf
 * http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/SHA512_256.pdf
 * http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/SHA2_Additional.pdf
 */
#ifndef _SHA_H_
#define _SHA_H_

#define DEBUG
#undef DEBUG

#include	"generic.h"
#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>

/* hash output length in bytes */
#define HASH_LENGTH_SHA_1	20
#define HASH_LENGTH_SHA_224	28
#define HASH_LENGTH_SHA_256	32
#define HASH_LENGTH_SHA_384	48
#define HASH_LENGTH_SHA_512	64
#define HASH_LENGTH_SHA_512_224 HASH_LENGTH_SHA_224
#define HASH_LENGTH_SHA_512_256 HASH_LENGTH_SHA_256

/* hash output length in bits */
#define HASH_BITLENGTH_SHA_1	160
#define HASH_BITLENGTH_SHA_224	224
#define HASH_BITLENGTH_SHA_256	256
#define HASH_BITLENGTH_SHA_384	384
#define HASH_BITLENGTH_SHA_512	512
#define HASH_BITLENGTH_SHA_512_224 HASH_BITLENGTH_SHA_224
#define HASH_BITLENGTH_SHA_512_256 HASH_BITLENGTH_SHA_256

/* hash input buffer length in bytes */
#define	HASH_INPUTBUFFER_SHA_1		64
#define	HASH_INPUTBUFFER_SHA_224	64
#define	HASH_INPUTBUFFER_SHA_256	64
#define	HASH_INPUTBUFFER_SHA_384	128
#define	HASH_INPUTBUFFER_SHA_512	128
#define	HASH_INPUTBUFFER_SHA_512_224 HASH_INPUTBUFFER_SHA_512
#define	HASH_INPUTBUFFER_SHA_512_256 HASH_INPUTBUFFER_SHA_512

/* hash input buffer length in bits */
#define	HASH_INPUTBUFFER_BITS_SHA_1		512
#define	HASH_INPUTBUFFER_BITS_SHA_224	512
#define	HASH_INPUTBUFFER_BITS_SHA_256	512
#define	HASH_INPUTBUFFER_BITS_SHA_384	1024
#define	HASH_INPUTBUFFER_BITS_SHA_512	1024
#define	HASH_INPUTBUFFER_BITS_SHA_512_224 HASH_INPUTBUFFER_BITS_SHA_512
#define	HASH_INPUTBUFFER_BITS_SHA_512_256 HASH_INPUTBUFFER_BITS_SHA_512

/* hash input buffer length in 32 or 64 bit words as implemented */
#define	HASH_INPUTBUFFER_W_SHA_1	16
#define	HASH_INPUTBUFFER_W_SHA_224	16
#define	HASH_INPUTBUFFER_W_SHA_256	16
#define	HASH_INPUTBUFFER_W_SHA_384	16
#define	HASH_INPUTBUFFER_W_SHA_512	16
#define	HASH_INPUTBUFFER_W_SHA_512_224 HASH_INPUTBUFFER_W_SHA_512
#define	HASH_INPUTBUFFER_W_SHA_512_256 HASH_INPUTBUFFER_W_SHA_512

/* hash magic values - SHA1 etc in little endian notation */
#define	HASH_MAGIC_SHA_1	0x31414853ULL             /* SHA1     */
#define	HASH_MAGIC_SHA_224	0x343232414853ULL         /* SHA224   */
#define	HASH_MAGIC_SHA_256	0x363532414853ULL         /* SHA256   */
#define	HASH_MAGIC_SHA_384	0x343833414853ULL         /* SHA384   */
#define	HASH_MAGIC_SHA_512	0x323135414853ULL         /* SHA512   */
#define	HASH_MAGIC_SHA_512_224	0x3432323135414853LL  /* SHA51224 */
#define	HASH_MAGIC_SHA_512_256	0x3635323135414853LL  /* SHA51256 */


typedef struct {
	/* required field: hashbitlen	*/
	/* must be HASH_BITLENGTH_SHA_1 */
	unsigned int	hashbitlen;
	/* magic token - SHA1 in LSB notation	*/
	DataLength		magic;
	/* internal state	*/
	unsigned int	H0, H1, H2, H3, H4;
	/* input buffer for 64 characters */
	unsigned int	m_buffer [HASH_INPUTBUFFER_W_SHA_1];
	/* bit count in m_buffer, mod 512, MSB is bit 0 */
	unsigned int	bitcount;
	/* total message length in bits */
	DataLength		total_count;
	/* output buffer of hash, 160 bits	*/
	BitSequence		out[HASH_LENGTH_SHA_1];
} SHA1_CTX;

unsigned int CLS (unsigned int x, int n);	/* circular left shift */

typedef struct {
	/* required field: hashbitlen	*/
	/* must be HASH_BITLENGTH_SHA_224 */
	unsigned int	hashbitlen;
	/* magic token - SHA224 in LSB notation	*/
	DataLength		magic;
	/* internal state	*/
	unsigned int	H1, H2, H3, H4, H5, H6, H7, H8;
	/* input buffer for 64 characters */
	unsigned int	m_buffer [HASH_INPUTBUFFER_W_SHA_224];
	/* bit count in m_buffer, mod 512, MSB is bit 0 */
	unsigned int	bitcount;
	/* total message length in bits */
	DataLength		total_count;
	/* output buffer of hash, 224 bits	*/
	BitSequence		out[HASH_LENGTH_SHA_224];
} SHA224_CTX;

typedef struct {
	/* required field: hashbitlen	*/
	/* must be HASH_BITLENGTH_SHA_256 */
	unsigned int	hashbitlen;
	/* magic token - SHA256 in LSB notation	*/
	DataLength		magic;
	/* internal state	*/
	unsigned int	H1, H2, H3, H4, H5, H6, H7, H8;
	/* input buffer for 64 characters */
	unsigned int	m_buffer [HASH_INPUTBUFFER_W_SHA_256];
	/* bit count in m_buffer, mod 512, MSB is bit 0 */
	unsigned int	bitcount;
	/* total message length in bits */
	DataLength		total_count;
	/* output buffer of hash, 256 bits	*/
	BitSequence		out[HASH_LENGTH_SHA_256];
} SHA256_CTX;

unsigned int Rint (unsigned int x, int n);	/* right shift by n bits */
unsigned int Sint (unsigned int x, int n);	/* right rotation by n bits */

typedef struct {
	/* required field: hashbitlen	*/
	/* must be HASH_BITLENGTH_SHA_384 */
	unsigned int	hashbitlen;
	/* magic token - SHA384 in LSB notation	*/
	DataLength		magic;
	/* internal state	*/
	uint64	H1, H2, H3, H4, H5, H6, H7, H8;
	/* input buffer 128 chars (1024 bits) */
	uint64	m_buffer [HASH_INPUTBUFFER_W_SHA_384];
	/* bit count in m_buffer, mod 1024, MSB is bit 0 */
	unsigned int	bitcount;
	/* total message length in bits */
	DataLength		total_count;
	/* output buffer of hash, 384 bits	*/
	BitSequence		out[HASH_LENGTH_SHA_384];
} SHA384_CTX;

uint64	 Rlong (uint64 x, int n);	/* right shift by n bits */
uint64	 Slong (uint64 x, int n);	/* right rotation by n bits */


typedef struct {
	/* required field: hashbitlen	*/
	/* must be HASH_BITLENGTH_SHA_512 */
	unsigned int	hashbitlen;
	/* magic token - SHA512 in LSB notation	*/
	DataLength		magic;
	/* internal state	*/
	uint64	H1, H2, H3, H4, H5, H6, H7, H8;
	/* input buffer 128 chars (1024 bits) */
	uint64	m_buffer [HASH_INPUTBUFFER_W_SHA_512];
	/* bit count in m_buffer, mod 1024, MSB is bit 0 */
	unsigned int	bitcount;
	/* total message length in bits */
	DataLength		total_count;
	/* output buffer of hash, 512 bits	*/
	BitSequence		out[HASH_LENGTH_SHA_512];
} SHA512_CTX;


typedef struct {
	/* required field: hashbitlen	*/
	/* must be HASH_BITLENGTH_SHA_512_224 */
	unsigned int	hashbitlen;
	/* magic token - SHA51224 in LSB notation	*/
	DataLength		magic;
	/* internal state	*/
	uint64	H1, H2, H3, H4, H5, H6, H7, H8;
	/* input buffer 128 chars (1024 bits) */
	uint64	m_buffer [HASH_INPUTBUFFER_W_SHA_512_224];
	/* bit count in m_buffer, mod 1024, MSB is bit 0 */
	unsigned int	bitcount;
	/* total message length in bits */
	DataLength		total_count;
	/* output buffer of hash, 224 bits	*/
	BitSequence		out[HASH_LENGTH_SHA_512_224];
} SHA512_224_CTX;


typedef struct {
	/* required field: hashbitlen	*/
	/* must be HASH_BITLENGTH_SHA_512_256 */
	unsigned int	hashbitlen;
	/* magic token - SHA51256 in LSB notation	*/
	DataLength		magic;
	/* internal state	*/
	uint64	H1, H2, H3, H4, H5, H6, H7, H8;
	/* input buffer 128 chars (1024 bits) */
	uint64	m_buffer [HASH_INPUTBUFFER_W_SHA_512_256];
	/* bit count in m_buffer, mod 1024, MSB is bit 0 */
	unsigned int	bitcount;
	/* total message length in bits */
	DataLength		total_count;
	/* output buffer of hash, 256 bits	*/
	BitSequence		out[HASH_LENGTH_SHA_512_256];
} SHA512_256_CTX;

/*********** SHA1 definitions *********/
/* initialize context */
extern HashReturn SHA1_init (hashState  *state, int hashbitlen);
/* update context, may be called many times */
extern HashReturn  SHA1_update (
    hashState state,          /* previously initialized context */
    const BitSequence *buffer,  /* bit buffer, first bit is MSB in [0] */
    DataLength databitlen);      /* number of bits to process from buffer */
/* produce hash and return in hashval */
extern HashReturn  SHA1_final (hashState state, BitSequence *hashval);
/* calculate hash all-in-one */
HashReturn SHA1_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval);

extern HashReturn SHA1_File (hashState state, FILE *in);
extern void SHA1_Print (SHA1_CTX *context);
extern HashReturn SHA1_HashToByte (hashState state, BYTE *out);

/*********** SHA224 definitions *********/
/* initialize context */
extern HashReturn SHA224_init (hashState  *state, int hashbitlen);
/* update context, may be called many times */
extern HashReturn  SHA224_update (
    hashState state,          /* previously initialized context */
    const BitSequence *buffer,  /* bit buffer, first bit is MSB in [0] */
    DataLength databitlen);      /* number of bits to process from buffer */
/* produce hash and return in hashval */
extern HashReturn  SHA224_final (hashState state, BitSequence *hashval);
/* calculate hash all-in-one */
HashReturn SHA224_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval);

extern HashReturn SHA224_File (hashState state, FILE *in);
extern void SHA224_Print (SHA224_CTX *context);
extern HashReturn SHA224_HashToByte (hashState state, BYTE *out);

/*********** SHA256 definitions *********/
/* initialize context */
extern HashReturn SHA256_init (hashState  *state, int hashbitlen);
/* update context, may be called many times */
extern HashReturn  SHA256_update (
    hashState state,          /* previously initialized context */
    const BitSequence *buffer,  /* bit buffer, first bit is MSB in [0] */
    DataLength databitlen);      /* number of bits to process from buffer */
/* produce hash and return in hashval */
extern HashReturn  SHA256_final (hashState state, BitSequence *hashval);
/* calculate hash all-in-one */
HashReturn SHA256_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval);

extern HashReturn SHA256_File (hashState state, FILE *in);
extern void SHA256_Print (SHA256_CTX *context);
extern HashReturn SHA256_HashToByte (hashState state, BYTE *out);

/*********** SHA384 definitions *********/
/* initialize context */
extern HashReturn SHA384_init (hashState  *state, int hashbitlen);
/* update context, may be called many times */
extern HashReturn  SHA384_update (
    hashState state,          /* previously initialized context */
    const BitSequence *buffer,  /* bit buffer, first bit is MSB in [0] */
    DataLength databitlen);      /* number of bits to process from buffer */
/* produce hash and return in hashval */
extern HashReturn  SHA384_final (hashState state, BitSequence *hashval);
/* calculate hash all-in-one */
HashReturn SHA384_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval);

extern HashReturn SHA384_File (hashState state, FILE *in);
extern void SHA384_Print (SHA384_CTX *context);
extern HashReturn SHA384_HashToByte (hashState state, BYTE *out);

/*********** SHA512 definitions *********/
/* initialize context */
extern HashReturn SHA512_init (hashState  *state, int hashbitlen);
/* update context, may be called many times */
extern HashReturn  SHA512_update (
    hashState state,          /* previously initialized context */
    const BitSequence *buffer,  /* bit buffer, first bit is MSB in [0] */
    DataLength databitlen);      /* number of bits to process from buffer */
/* produce hash and return in hashval */
extern HashReturn  SHA512_final (hashState state, BitSequence *hashval);
/* calculate hash all-in-one */
HashReturn SHA512_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval);
extern HashReturn SHA512_File (hashState state, FILE *in);
extern void SHA512_Print (SHA512_CTX *context);
extern HashReturn SHA512_HashToByte (hashState state, BYTE *out);

/*********** SHA512-224 definitions *********/
/* initialize context */
extern HashReturn SHA512_224_init (hashState  *state, int hashbitlen);
/* update context, may be called many times */
extern HashReturn  SHA512_224_update (
    hashState state,          /* previously initialized context */
    const BitSequence *buffer,  /* bit buffer, first bit is MSB in [0] */
    DataLength databitlen);      /* number of bits to process from buffer */
/* produce hash and return in hashval */
extern HashReturn  SHA512_224_final (hashState state, BitSequence *hashval);
/* calculate hash all-in-one */
HashReturn SHA512_224_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval);
extern HashReturn SHA512_224_File (hashState state, FILE *in);
extern void SHA512_224_Print (SHA512_224_CTX *context);
extern HashReturn SHA512_224_HashToByte (hashState state, BYTE *out);

/*********** SHA512-256 definitions *********/
/* initialize context */
extern HashReturn SHA512_256_init (hashState  *state, int hashbitlen);
/* update context, may be called many times */
extern HashReturn  SHA512_256_update (
    hashState state,          /* previously initialized context */
    const BitSequence *buffer,  /* bit buffer, first bit is MSB in [0] */
    DataLength databitlen);      /* number of bits to process from buffer */
/* produce hash and return in hashval */
extern HashReturn  SHA512_256_final (hashState state, BitSequence *hashval);
/* calculate hash all-in-one */
HashReturn SHA512_256_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval);
extern HashReturn SHA512_256_File (hashState state, FILE *in);
extern void SHA512_256_Print (SHA512_256_CTX *context);
extern HashReturn SHA512_256_HashToByte (hashState state, BYTE *out);

#endif
