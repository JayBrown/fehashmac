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

/*
 *  gosthash.h 
 *  21 Apr 1998  Markku-Juhani Saarinen <mjos@ssh.fi>
 * 
 *  GOST R 34.11-94, Russian Standard Hash Function 
 *  header with function prototypes.
 *
 *  Copyright (c) 1998 SSH Communications Security, Finland
 *  All rights reserved.                    
 */

/* 
 * integrated in fehashmac
 * hvf 04.02.2007
 * hvf 16.02.2009 aligned with SHA3-C-API
 */


#ifndef _GOSTHASH_H_
#define _GOSTHASH_H_

#include "generic.h"
#include <stdlib.h>

/* the reference implementation assues that long is 32 bits
 * this is of course a sin on 64 bit machines
 * all ''unsigned long'' are replaced by GOSTLONG, which is
 * typedef'ed here
 * hvf 19.02.2007
 */

typedef unsigned int GOSTLONG;

/* hash output length in bytes */
#define HASH_LENGTH_GOST	32

/* hash output length in bits */
#define HASH_BITLENGTH_GOST	256

/* hash input buffer length in bytes */
#define HASH_INPUTBUFFER_GOST    32

/* hash magic values - GOST in little endian notation */
#define HASH_MAGIC_GOST	0x54534f47ULL


/* State structure */

typedef struct 
{
	/* required field: hashbitlen	*/
	/* must be HASH_BITLENGTH_GOST */
	unsigned int	hashbitlen;
	/* magic token - GOST in LSB notation	*/
	DataLength		magic;
	/* internal state	*/
  GOSTLONG sum[8];
  GOSTLONG hash[8];
  GOSTLONG len[8];
  unsigned char partial[32];
  size_t partial_bytes;  
  unsigned char out[32];	/* output, 256 bits */
} GostHashCtx;

typedef GostHashCtx GOST_CTX;
  
/* Compute some lookup-tables that are needed by all other functions. */

void gosthash_init();     

/* Clear the state of the given context structure. */

void gosthash_reset(GostHashCtx *ctx);  

/* Mix in len bytes of data for the given buffer. */

void gosthash_update(GostHashCtx *ctx, const unsigned char *buf, size_t len);

/* Compute and save the 32-byte digest. */

void gosthash_final(GostHashCtx *ctx, unsigned char *digest);

HashReturn GOST_init (hashState  *state, int hashbitlen);
HashReturn  GOST_update (
    hashState state,            /* previously initialized context */
    const BitSequence *buffer,  /* bit buffer, first bit is MSB in [0] */
    DataLength databitlen);     /* number of bits to process from buffer */
HashReturn  GOST_final (hashState state, BitSequence *hashval);
/* calculate hash all-in-one */
HashReturn GOST_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval);

extern HashReturn GOST_File (hashState state, FILE *in);
extern void GOST_Print (GOST_CTX *context);
extern HashReturn GOST_HashToByte (hashState state, BYTE *out);

#endif /* GOSTHASH_H */
