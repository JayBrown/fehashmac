/* mdx.h - header file for md2, md4, md5
 */

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

/* Copyright (C) 1990-2, RSA Data Security, Inc. Created 1990. All
   rights reserved.

   License to copy and use this software is granted for
   non-commercial Internet Privacy-Enhanced Mail provided that it is
   identified as the "RSA Data Security, Inc. MD2 Message Digest
   Algorithm" in all material mentioning or referencing this software
   or this function.

   RSA Data Security, Inc. makes no representations concerning either
   the merchantability of this software or the suitability of this
   software for any particular purpose. It is provided "as is"
   without express or implied warranty of any kind.

   These notices must be retained in any copies of any part of this
   documentation and/or software.
 */

/* integrated in fehashmac - hvf 12.08.01	
 * hvf 09.02.2009 aligned with SHA3-C-API
 * 
 */

#ifndef _MDX_H_
#define _MDX_H_

#include	"generic.h"
#include	<stdio.h>

#define DEBUG
#undef DEBUG

/* hash output length in bytes */
#define HASH_LENGTH_MD2	16
#define HASH_LENGTH_MD4	16
#define HASH_LENGTH_MD5	16

/* hash output length in bits */
#define HASH_BITLENGTH_MD2	128
#define HASH_BITLENGTH_MD4	128
#define HASH_BITLENGTH_MD5	128

/* hash input buffer length in bytes */
#define	HASH_INPUTBUFFER_MD2	16
#define	HASH_INPUTBUFFER_MD4	64
#define	HASH_INPUTBUFFER_MD5	64

/* hash input buffer length in bits */
#define	HASH_INPUTBUFFER_BITS_MD4	512
#define	HASH_INPUTBUFFER_BITS_MD5	512

/* hash input buffer length in 32 bit words */
#define	HASH_INPUTBUFFER_W_MD4	16
#define	HASH_INPUTBUFFER_W_MD5	16

/* hash magic values - MD2 etc in little endian notation */
#define HASH_MAGIC_MD2	0x32444DULL
#define HASH_MAGIC_MD4	0x34444DULL
#define HASH_MAGIC_MD5	0x35444DULL

/* MD2 context
 * only bytewise hash supported
 */

typedef struct {
	/* required field: hashbitlen	*/
	/* must be HASH_BITLENGTH_MD2 */
	unsigned int	hashbitlen;
	/* magic token - MD2 in LSB notation	*/
	DataLength		magic;
	/* internal state	*/
	BYTE	 state[16];				/* state */
	BYTE	 checksum[16];          /* checksum */
	unsigned int count;             /* number of bytes, modulo 16 */
	BYTE	 buffer[HASH_INPUTBUFFER_MD2];  /* input buffer */
	BYTE	out[HASH_LENGTH_MD2];	/* output, 128 bits */
} MD2_CTX;

/* MD4 context
 * only bytewise hash supported
 */
typedef struct {
	/* required field: hashbitlen	*/
	/* must be HASH_BITLENGTH_MD4 */
	unsigned int	hashbitlen;
	/* magic token - MD4 in LSB notation	*/
	DataLength		magic;
	/* internal state	*/
	unsigned int state[4];          /* state (ABCD) */
	/* input buffer for 64 characters */
	BYTE	 buffer[64];            /* input buffer */
	/* number of bits, modulo 2^64 (lsb first) */
	unsigned int count[2];
	/* total message length in bits */
	DataLength		total_count;
	BYTE	out[HASH_LENGTH_MD4];	/* output, 128 bits */
} MD4_CTX;

/* MD5 context
 * only bytewise hash supported
 */
typedef struct {
	/* required field: hashbitlen	*/
	/* must be HASH_BITLENGTH_MD5 */
	unsigned int	hashbitlen;
	/* magic token - MD5 in LSB notation	*/
	DataLength		magic;
	/* internal state	*/
	unsigned int state[4];          /* state (ABCD) */
	/* input buffer for 64 characters */
	BYTE	 buffer[64];            /* input buffer */
	/* number of bits, modulo 2^64 (lsb first) */
	unsigned int count[2];
	/* total message length in bits */
	DataLength		total_count;
	BYTE	out[HASH_LENGTH_MD5];	/* output, 128 bits */
} MD5_CTX;

HashReturn MD2_init (hashState  *state, int hashbitlen);
HashReturn  MD2_update (
    hashState state,            /* previously initialized context */
    const BitSequence *buffer,  /* bit buffer, first bit is MSB in [0] */
    DataLength databitlen);     /* number of bits to process from buffer */
HashReturn  MD2_final (hashState state, BitSequence *hashval);
/* calculate hash all-in-one */
HashReturn MD2_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval);

extern HashReturn MD2_File (hashState state, FILE *in);
extern void MD2_Print (MD2_CTX *context);
extern HashReturn MD2_HashToByte (hashState state, BYTE *out);

HashReturn MD4_init (hashState  *state, int hashbitlen);
HashReturn  MD4_update (
    hashState state,            /* previously initialized context */
    const BitSequence *buffer,  /* bit buffer, first bit is MSB in [0] */
    DataLength databitlen);     /* number of bits to process from buffer */
HashReturn  MD4_final (hashState state, BitSequence *hashval);
/* calculate hash all-in-one */
HashReturn MD4_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval);

extern HashReturn MD4_File (hashState state, FILE *in);
extern void MD4_Print (MD4_CTX *context);
extern HashReturn MD4_HashToByte (hashState state, BYTE *out);

HashReturn MD5_init (hashState  *state, int hashbitlen);
HashReturn  MD5_update (
    hashState state,            /* previously initialized context */
    const BitSequence *buffer,  /* bit buffer, first bit is MSB in [0] */
    DataLength databitlen);     /* number of bits to process from buffer */
HashReturn  MD5_final (hashState state, BitSequence *hashval);
/* calculate hash all-in-one */
HashReturn MD5_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval);

extern HashReturn MD5_File (hashState state, FILE *in);
extern void MD5_Print (MD5_CTX *context);
extern HashReturn MD5_HashToByte (hashState state, BYTE *out);

#endif
