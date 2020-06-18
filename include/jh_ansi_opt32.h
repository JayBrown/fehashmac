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

/*
 * The files jh_ansi_opt32.h and jh_ansi_opt32.c have been taken from the final
 * JH submission to the SHA3 contest, see
 * http://csrc.nist.gov/groups/ST/hash/sha-3/Round3/submissions_rnd3.html
 * The JH homepage is http://www3.ntu.edu.sg/home/wuhj/research/jh/
 * The author of JH is
 * Hongjun Wu (Nanyang Technological University, Singapore)
 *
 * integration into fehashmac by hvf 10.04.2011
 */

#ifndef _JH_ANSI_OPT_32_H_
#define _JH_ANSI_OPT_32_H_

#include    "generic.h"
#include    <stdio.h>
#include    <stdlib.h>
#include <string.h>

/*define data alignment for different C compilers*/
#if defined(__GNUC__)
      #define DATA_ALIGN16(x) x __attribute__ ((aligned(16)))
#else
      #define DATA_ALIGN16(x) __declspec(align(16)) x
#endif

/* hash output length in bytes */
#define HASH_LENGTH_JH_224 28
#define HASH_LENGTH_JH_256 32
#define HASH_LENGTH_JH_384 48
#define HASH_LENGTH_JH_512 64

/* hash output length in bits */
#define HASH_BITLENGTH_JH_224  224
#define HASH_BITLENGTH_JH_256  256
#define HASH_BITLENGTH_JH_384  384
#define HASH_BITLENGTH_JH_512  512

/* hash input buffer length in bytes */
#define HASH_INPUTBUFFER_JH_224    64
#define HASH_INPUTBUFFER_JH_256    64
#define HASH_INPUTBUFFER_JH_384    64
#define HASH_INPUTBUFFER_JH_512    64

/* hash input buffer length in bits */
#define HASH_INPUTBUFFER_BITS_JH_224   512
#define HASH_INPUTBUFFER_BITS_JH_256   512
#define HASH_INPUTBUFFER_BITS_JH_384   512
#define HASH_INPUTBUFFER_BITS_JH_512   512

/* hash magic values - JHxxx etc in little endian notation */
#define HASH_MAGIC_JH_224  0x343232484aULL         /* JH224   */
#define HASH_MAGIC_JH_256  0x363532484aULL         /* JH256   */
#define HASH_MAGIC_JH_384  0x343833484aULL         /* JH384   */
#define HASH_MAGIC_JH_512  0x323135484aULL         /* JH512   */


typedef struct {
	int hashbitlen;	   	              /*the message digest size*/
  	/* magic token - must be HASH_MAGIC_JH_xxx */
  	DataLength      magic;
	unsigned long long datasize_in_buffer;           /*the size of the message remained in buffer; assumed to be multiple of 8bits except for the last partial block at the end of the message*/
	unsigned long long databitlen;    /*the message size in bits*/
	DATA_ALIGN16(uint32 x[8][4]);     /*the 1024-bit state, ( x[i][0] || x[i][1] || x[i][2] || x[i][3] ) is the ith row of the state in the pseudocode*/
	unsigned char buffer[64];         /*the 512-bit message block to be hashed;*/
	/* output buffer of hash, 512 bits  */
	BitSequence     out[HASH_LENGTH_JH_512];
} JH_CTX;


/* 
 * parameter safe wrappers for JH routines for each hash length
 */

/*********** JH224 definitions *********/
/* initialize context */
extern HashReturn JH224_init (hashState  *state, int hashbitlen);
/* update context, may be called many times */
extern HashReturn  JH224_update (
    hashState state,          /* previously initialized context */
    const BitSequence *buffer,  /* bit buffer, first bit is MSB in [0] */
    DataLength databitlen);      /* number of bits to process from buffer */
/* produce hash and return in hashval */
extern HashReturn  JH224_final (hashState state, BitSequence *hashval);
/* calculate hash all-in-one */
HashReturn JH224_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval);

extern HashReturn JH224_File (hashState state, FILE *in);
extern void JH224_Print (JH_CTX *context);
extern HashReturn JH224_HashToByte (hashState state, BYTE *out);

/*********** JH256 definitions *********/
/* initialize context */
extern HashReturn JH256_init (hashState  *state, int hashbitlen);
/* update context, may be called many times */
extern HashReturn  JH256_update (
    hashState state,          /* previously initialized context */
    const BitSequence *buffer,  /* bit buffer, first bit is MSB in [0] */
    DataLength databitlen);      /* number of bits to process from buffer */
/* produce hash and return in hashval */
extern HashReturn  JH256_final (hashState state, BitSequence *hashval);
/* calculate hash all-in-one */
HashReturn JH256_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval);

extern HashReturn JH256_File (hashState state, FILE *in);
extern void JH256_Print (JH_CTX *context);
extern HashReturn JH256_HashToByte (hashState state, BYTE *out);

/*********** JH384 definitions *********/
/* initialize context */
extern HashReturn JH384_init (hashState  *state, int hashbitlen);
/* update context, may be called many times */
extern HashReturn  JH384_update (
    hashState state,          /* previously initialized context */
    const BitSequence *buffer,  /* bit buffer, first bit is MSB in [0] */
    DataLength databitlen);      /* number of bits to process from buffer */
/* produce hash and return in hashval */
extern HashReturn  JH384_final (hashState state, BitSequence *hashval);
/* calculate hash all-in-one */
HashReturn JH384_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval);

extern HashReturn JH384_File (hashState state, FILE *in);
extern void JH384_Print (JH_CTX *context);
extern HashReturn JH384_HashToByte (hashState state, BYTE *out);

/*********** JH512 definitions *********/
/* initialize context */
extern HashReturn JH512_init (hashState  *state, int hashbitlen);
/* update context, may be called many times */
extern HashReturn  JH512_update (
    hashState state,          /* previously initialized context */
    const BitSequence *buffer,  /* bit buffer, first bit is MSB in [0] */
    DataLength databitlen);      /* number of bits to process from buffer */
/* produce hash and return in hashval */
extern HashReturn  JH512_final (hashState state, BitSequence *hashval);
/* calculate hash all-in-one */
HashReturn JH512_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval);

extern HashReturn JH512_File (hashState state, FILE *in);
extern void JH512_Print (JH_CTX *context);
extern HashReturn JH512_HashToByte (hashState state, BYTE *out);


#endif
