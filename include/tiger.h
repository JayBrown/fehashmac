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

/* tiger.h - header file for tiger
 * hvf	10.11.2008
 * hvf 09.02.2009 aligned with SHA3-C-API
 */

#ifndef _TIGER_H_
#define _TIGER_H_

#include "generic.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* hash output length in bytes */
#define HASH_LENGTH_TIGER 24

/* hash output length in bits */
#define HASH_BITLENGTH_TIGER	192

/* hash input buffer length in bytes */
#define HASH_INPUTBUFFER_TIGER    64

/* hash magic values - TIGER in little endian notation */
#define HASH_MAGIC_TIGER	0x5245474954ULL

typedef struct {
	/* required field: hashbitlen	*/
	/* must be HASH_BITLENGTH_TIGER */
	unsigned int	hashbitlen;
	/* magic token - TIGER in LSB notation	*/
	DataLength		magic;
	/* internal state	*/
	uint64			state[3];		/* state, 3 x 64 bits	*/
	unsigned int	count;			/* number of bytes */
	BYTE			buffer[64];		/* input buffer */
	BYTE			out[24];		/* output, 192 bits */
} TIGER_CTX;

/* TIGER SBoxes */

extern uint64 TIGER_Table[4*256];

HashReturn TIGER_init (hashState  *state, int hashbitlen);
HashReturn  TIGER_update (
    hashState state,            /* previously initialized context */
    const BitSequence *buffer,  /* bit buffer, first bit is MSB in [0] */
    DataLength databitlen);     /* number of bits to process from buffer */
HashReturn  TIGER_final (hashState state, BitSequence *hashval);
/* calculate hash all-in-one */
HashReturn TIGER_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval);

extern HashReturn TIGER_File (hashState state, FILE *in);
extern void TIGER_Print (TIGER_CTX *context);
extern HashReturn TIGER_HashToByte (hashState state, BYTE *out);


#endif




