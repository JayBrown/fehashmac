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

/*	rmdx.h	header file for RIPEMD family of hash functions
 *	hvf	13.08.01
 *	hvf 11.02.07 RIPEMD-256, 320 added
 *	hvf 09.02.2009 aligned with SHA3-C-API
 */

#ifndef _RMDX_H_
#define _RMDX_H_

#include	"generic.h"
#include    <stdio.h>
#include    <stdlib.h>

/* hash output length in bytes */
#define HASH_LENGTH_RIPEMD128  16
#define HASH_LENGTH_RIPEMD160  20
#define HASH_LENGTH_RIPEMD256  32
#define HASH_LENGTH_RIPEMD320  40

/* hash output length in bits */
#define HASH_BITLENGTH_RIPEMD128	128
#define HASH_BITLENGTH_RIPEMD160	160
#define HASH_BITLENGTH_RIPEMD256	256
#define HASH_BITLENGTH_RIPEMD320	320

/* hash input buffer length in bytes */
#define	HASH_INPUTBUFFER_RIPEMD128	64
#define	HASH_INPUTBUFFER_RIPEMD160	64
#define	HASH_INPUTBUFFER_RIPEMD256	64
#define	HASH_INPUTBUFFER_RIPEMD320	64

/* hash input buffer length in 32 bit words */
#define	HASH_INPUTBUFFER_W_RIPEMD128	16
#define	HASH_INPUTBUFFER_W_RIPEMD160	16
#define	HASH_INPUTBUFFER_W_RIPEMD256	16
#define	HASH_INPUTBUFFER_W_RIPEMD320	16

/* hash magic values - RMD128 etc in little endian notation */
#define HASH_MAGIC_RIPEMD128	0x383231444d52ULL
#define HASH_MAGIC_RIPEMD160	0x303631444d52ULL
#define HASH_MAGIC_RIPEMD256	0x363532444d52ULL
#define HASH_MAGIC_RIPEMD320	0x303233444d52ULL

typedef struct {
	/* required field: hashbitlen	*/
	/* must be HASH_BITLENGTH_RIPEMD128 */
	unsigned int	hashbitlen;
	/* magic token - RMD128 in LSB notation	*/
	DataLength		magic;
	/* internal state	*/
	unsigned int	MDbuf[4];		/* the state */
	unsigned int	m_buffer[16];	/* input buffer for 64 characters */
	unsigned int	count;			/* char count in m_buffer, mod 64 */
	uint64		total_count;	/* total message length in bits */
	unsigned char	out[16];		/* output buffer of hash, 128 bits */
} RIPEMD128_CTX;
	
typedef struct {
	/* required field: hashbitlen	*/
	/* must be HASH_BITLENGTH_RMD160 */
	unsigned int	hashbitlen;
	/* magic token - RMD160 in LSB notation	*/
	DataLength		magic;
	/* internal state	*/
	unsigned int	MDbuf[5];		/* the state */
	unsigned int	m_buffer[16];	/* input buffer for 64 characters */
	unsigned int	count;			/* char count in m_buffer, mod 64 */
	uint64	total_count;	/* total message length in bits */
	unsigned char	out[20];		/* output buffer of hash, 160 bits */
} RIPEMD160_CTX;
	
typedef struct {
	/* required field: hashbitlen	*/
	/* must be HASH_BITLENGTH_RMD256 */
	unsigned int	hashbitlen;
	/* magic token - RMD256 in LSB notation	*/
	DataLength		magic;
	/* internal state	*/
	unsigned int	MDbuf[8];		/* the state */
	unsigned int	m_buffer[16];	/* input buffer for 64 characters */
	unsigned int	count;			/* char count in m_buffer, mod 64 */
	uint64	total_count;	/* total message length in bits */
	unsigned char	out[32];		/* output buffer of hash, 256 bits */
} RIPEMD256_CTX;
	
typedef struct {
	/* required field: hashbitlen	*/
	/* must be HASH_BITLENGTH_RMD320 */
	unsigned int	hashbitlen;
	/* magic token - RMD320 in LSB notation	*/
	DataLength		magic;
	/* internal state	*/
	unsigned int	MDbuf[10];		/* the state */
	unsigned int	m_buffer[16];	/* input buffer for 64 characters */
	unsigned int	count;			/* char count in m_buffer, mod 64 */
	uint64	total_count;	/* total message length in bits */
	unsigned char	out[40];		/* output buffer of hash, 320 bits */
} RIPEMD320_CTX;

HashReturn RIPEMD128_init (hashState  *state, int hashbitlen);
HashReturn  RIPEMD128_update (
    hashState state,            /* previously initialized context */
    const BitSequence *buffer,  /* bit buffer, first bit is MSB in [0] */
    DataLength databitlen);     /* number of bits to process from buffer */
HashReturn  RIPEMD128_final (hashState state, BitSequence *hashval);
/* calculate hash all-in-one */
HashReturn RIPEMD128_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval);

extern HashReturn RIPEMD128_File (hashState state, FILE *in);
extern void RIPEMD128_Print (RIPEMD128_CTX *context);
extern HashReturn RIPEMD128_HashToByte (hashState state, BYTE *out);

HashReturn RIPEMD160_init (hashState  *state, int hashbitlen);
HashReturn  RIPEMD160_update (
    hashState state,            /* previously initialized context */
    const BitSequence *buffer,  /* bit buffer, first bit is MSB in [0] */
    DataLength databitlen);     /* number of bits to process from buffer */
HashReturn  RIPEMD160_final (hashState state, BitSequence *hashval);
/* calculate hash all-in-one */
HashReturn RIPEMD160_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval);

extern HashReturn RIPEMD160_File (hashState state, FILE *in);
extern void RIPEMD160_Print (RIPEMD160_CTX *context);
extern HashReturn RIPEMD160_HashToByte (hashState state, BYTE *out);

HashReturn RIPEMD256_init (hashState  *state, int hashbitlen);
HashReturn  RIPEMD256_update (
    hashState state,            /* previously initialized context */
    const BitSequence *buffer,  /* bit buffer, first bit is MSB in [0] */
    DataLength databitlen);     /* number of bits to process from buffer */
HashReturn  RIPEMD256_final (hashState state, BitSequence *hashval);
/* calculate hash all-in-one */
HashReturn RIPEMD256_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval);

extern HashReturn RIPEMD256_File (hashState state, FILE *in);
extern void RIPEMD256_Print (RIPEMD256_CTX *context);
extern HashReturn RIPEMD256_HashToByte (hashState state, BYTE *out);

HashReturn RIPEMD320_init (hashState  *state, int hashbitlen);
HashReturn  RIPEMD320_update (
    hashState state,            /* previously initialized context */
    const BitSequence *buffer,  /* bit buffer, first bit is MSB in [0] */
    DataLength databitlen);     /* number of bits to process from buffer */
HashReturn  RIPEMD320_final (hashState state, BitSequence *hashval);
/* calculate hash all-in-one */
HashReturn RIPEMD320_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval);

extern HashReturn RIPEMD320_File (hashState state, FILE *in);
extern void RIPEMD320_Print (RIPEMD320_CTX *context);
extern HashReturn RIPEMD320_HashToByte (hashState state, BYTE *out);

#endif
