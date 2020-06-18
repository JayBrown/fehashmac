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

// lash.h
// architecture-dependent types
// hvf 16.10.2008
/*
 * hvf 16.02.2009 aligned with SHA3-C-API
 */ 

#ifndef LASH_H
#define LASH_H

#include "generic.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// hash output length in bytes
#define HASH_LENGTH_LASH160	20
#define HASH_LENGTH_LASH256	32
#define HASH_LENGTH_LASH384	48
#define HASH_LENGTH_LASH512	64 

/* hash output length in bits */
#define HASH_BITLENGTH_LASH160	160
#define HASH_BITLENGTH_LASH256	256
#define HASH_BITLENGTH_LASH384	384
#define HASH_BITLENGTH_LASH512	512

// hash input buffer length in bytes
#define HASH_INPUTBUFFER_LASH160	40
#define HASH_INPUTBUFFER_LASH256	64
#define HASH_INPUTBUFFER_LASH384	96
#define HASH_INPUTBUFFER_LASH512	128

// bit vector length in compression function
#define HASH_BITVECTORLENGTH_LASH160	640
#define HASH_BITVECTORLENGTH_LASH256	1024
#define HASH_BITVECTORLENGTH_LASH384	1536
#define HASH_BITVECTORLENGTH_LASH512	2048

/* hash magic values - LASH160 etc in little endian notation */
#define HASH_MAGIC_LASH160	0x3036314853414cULL
#define HASH_MAGIC_LASH256	0x3635324853414cULL
#define HASH_MAGIC_LASH384	0x3438334853414cULL
#define HASH_MAGIC_LASH512	0x3231354853414cULL

// contexts
// LASH160 context
typedef struct {

	/* required field: hashbitlen	*/
	/* must be HASH_BITLENGTH_LASH160 */
	unsigned int	hashbitlen;
	/* magic token - LASH160 in LSB notation	*/
	DataLength		magic;
	/* internal state	*/
	BYTE	r[HASH_INPUTBUFFER_LASH160];	// state
	BYTE	s[HASH_INPUTBUFFER_LASH160];	// input
	int 	count;	// byte count in s buffer
	uint64	bitcount;	// bitcount in whole message
	BYTE	tcomp[HASH_INPUTBUFFER_LASH160];	// output of compression fct
	BYTE	t[HASH_LENGTH_LASH160];	// output hash
} LASH160_CTX;

// LASH256 context
typedef struct {
	/* required field: hashbitlen	*/
	/* must be HASH_BITLENGTH_LASH256 */
	unsigned int	hashbitlen;
	/* magic token - LASH256 in LSB notation	*/
	DataLength		magic;
	/* internal state	*/
	BYTE	r[HASH_INPUTBUFFER_LASH256];	// state
	BYTE	s[HASH_INPUTBUFFER_LASH256];	// input
	int 	count;	// byte count in s buffer
	uint64	bitcount;	// bitcount in whole message
	BYTE	tcomp[HASH_INPUTBUFFER_LASH256];	// output of compression fct
	BYTE	t[HASH_LENGTH_LASH256];	// output hash
} LASH256_CTX;

// LASH384 context
typedef struct {
	/* required field: hashbitlen	*/
	/* must be HASH_BITLENGTH_LASH384 */
	unsigned int	hashbitlen;
	/* magic token - LASH384 in LSB notation	*/
	DataLength		magic;
	/* internal state	*/
	BYTE	r[HASH_INPUTBUFFER_LASH384];	// state
	BYTE	s[HASH_INPUTBUFFER_LASH384];	// input
	int 	count;	// byte count in s buffer
	uint64	bitcount;	// bitcount in whole message
	BYTE	tcomp[HASH_INPUTBUFFER_LASH384];	// output of compression fct
	BYTE	t[HASH_LENGTH_LASH384];	// output hash
} LASH384_CTX;

// LASH512 context
typedef struct {
	/* required field: hashbitlen	*/
	/* must be HASH_BITLENGTH_LASH512 */
	unsigned int	hashbitlen;
	/* magic token - LASH512 in LSB notation	*/
	DataLength		magic;
	/* internal state	*/
	BYTE	r[HASH_INPUTBUFFER_LASH512];	// state
	BYTE	s[HASH_INPUTBUFFER_LASH512];	// input
	int 	count;	// byte count in s buffer
	uint64	bitcount;	// bitcount in whole message
	BYTE	tcomp[HASH_INPUTBUFFER_LASH512];	// output of compression fct
	BYTE	t[HASH_LENGTH_LASH512];	// output hash
} LASH512_CTX;

// macros for multidim array addressing
// it is unfortunately not possible in C to create multidim. arrays
// dynamically, we therefore do the index calculation by hand

#define addr2(i,j,jmax)	((i)*(jmax)+(j))
#define addr3(i,j,jmax,k,kmax)	((((i)*(jmax)+(j))*(kmax))+(k))

// function prototypes for array generation
void	mk_avector (int len1, BYTE *Arr1);
void	mk_hvector (int len1, int len2, BYTE *Arr1, BYTE *Arr2);
void	mk_gvector (int len1, int len2, BYTE *Arr2, BYTE *Arr3);

// thresholds for the array generation (H, G)
// currently we generate them right at the beginning
#define THRESHOLD_1_160	0
#define THRESHOLD_2_160	0
#define THRESHOLD_1_256	0
#define THRESHOLD_2_256	0
#define THRESHOLD_1_384	0
#define THRESHOLD_2_384	0
#define THRESHOLD_1_512	0
#define THRESHOLD_2_512	0

// LASH tables
// the tables are now generated dynamically, but we keep the static
// declarations for documentation purposes

#if 0
extern BYTE LASH_A_160[640];		// HASH_BITVECTORLENGTH_LASH160
extern BYTE LASH_H_160[640][40];
extern BYTE LASH_G_160[80][256][40];

extern BYTE LASH_A_256[1024];
extern BYTE LASH_H_256[1024][64];
extern BYTE LASH_G_256[128][256][64];

extern BYTE LASH_A_384[1536];
extern BYTE LASH_H_384[1536][96];
extern BYTE LASH_G_384[192][256][96];

extern BYTE LASH_A_512[2048];
extern BYTE LASH_H_512[2048][128];
extern BYTE LASH_G_512[256][256][128];
#endif

// exported LASH functions

HashReturn LASH160_init (hashState  *state, int hashbitlen);
HashReturn  LASH160_update (
    hashState state,            /* previously initialized context */
    const BitSequence *buffer,  /* bit buffer, first bit is MSB in [0] */
    DataLength databitlen);     /* number of bits to process from buffer */
HashReturn  LASH160_final (hashState state, BitSequence *hashval);
/* calculate hash all-in-one */
HashReturn LASH160_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval);

extern HashReturn LASH160_File (hashState state, FILE *in);
extern void LASH160_Print (LASH160_CTX *context);
extern HashReturn LASH160_HashToByte (hashState state, BYTE *out);

HashReturn LASH256_init (hashState  *state, int hashbitlen);
HashReturn  LASH256_update (
    hashState state,            /* previously initialized context */
    const BitSequence *buffer,  /* bit buffer, first bit is MSB in [0] */
    DataLength databitlen);     /* number of bits to process from buffer */
HashReturn  LASH256_final (hashState state, BitSequence *hashval);
/* calculate hash all-in-one */
HashReturn LASH256_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval);

extern HashReturn LASH256_File (hashState state, FILE *in);
extern void LASH256_Print (LASH256_CTX *context);
extern HashReturn LASH256_HashToByte (hashState state, BYTE *out);

HashReturn LASH384_init (hashState  *state, int hashbitlen);
HashReturn  LASH384_update (
    hashState state,            /* previously initialized context */
    const BitSequence *buffer,  /* bit buffer, first bit is MSB in [0] */
    DataLength databitlen);     /* number of bits to process from buffer */
HashReturn  LASH384_final (hashState state, BitSequence *hashval);
/* calculate hash all-in-one */
HashReturn LASH384_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval);

extern HashReturn LASH384_File (hashState state, FILE *in);
extern void LASH384_Print (LASH384_CTX *context);
extern HashReturn LASH384_HashToByte (hashState state, BYTE *out);

HashReturn LASH512_init (hashState  *state, int hashbitlen);
HashReturn  LASH512_update (
    hashState state,            /* previously initialized context */
    const BitSequence *buffer,  /* bit buffer, first bit is MSB in [0] */
    DataLength databitlen);     /* number of bits to process from buffer */
HashReturn  LASH512_final (hashState state, BitSequence *hashval);
/* calculate hash all-in-one */
HashReturn LASH512_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval);

extern HashReturn LASH512_File (hashState state, FILE *in);
extern void LASH512_Print (LASH512_CTX *context);
extern HashReturn LASH512_HashToByte (hashState state, BYTE *out);

#endif
