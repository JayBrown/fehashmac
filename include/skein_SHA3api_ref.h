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
 * The files 
 * skein_block.c  skein.c  skein_SHA3api_ref.c 
 * skein.h  skein_iv.h  skein_port.h  skein_SHA3api_ref.h
 * have been taken from the Skein submission to the SHA3 contest, see
 * http://csrc.nist.gov/groups/ST/hash/sha-3/Round3/submissions_rnd3.html
 * The Skein homepage is http://www.skein-hash.info/
 * The authors of Skein are
 * Niels Ferguson (Microsoft Corp.)
 * Stefan Lucks (Bauhaus-Universität Weimar)
 * Bruce Schneier (BT Group plc)
 * Doug Whiting (Hifn, Inc.)
 * Mihir Bellare (University of California San Diego)
 * Tadayoshi Kohno (University of Washington)
 * Jon Callas (PGP Corp.)
 * Jesse Walker (Intel Corp.)
 *
 * integration into fehashmac by hvf 11.04.2011
 * align CTX with standard - hvf 19.04.2015
 */

#ifndef _AHS_API_H_
#define _AHS_API_H_

/***********************************************************************
**
** Interface declarations of the AHS API using the Skein hash function.
**
** Source code author: Doug Whiting, 2008.
**
** This algorithm and source code is released to the public domain.
** 
************************************************************************/

#include "generic.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "skein.h"

/* hash output length in bytes */
#define HASH_LENGTH_SKEIN_224 28
#define HASH_LENGTH_SKEIN_256 32
#define HASH_LENGTH_SKEIN_384 48
#define HASH_LENGTH_SKEIN_512 64
#define HASH_LENGTH_SKEIN_1024 128

/* hash output length in bits */
#define HASH_BITLENGTH_SKEIN_224   224
#define HASH_BITLENGTH_SKEIN_256   256
#define HASH_BITLENGTH_SKEIN_384   384
#define HASH_BITLENGTH_SKEIN_512   512
#define HASH_BITLENGTH_SKEIN_1024 1024

/* hash input buffer length in bytes */
#define HASH_INPUTBUFFER_SKEIN_224    32
#define HASH_INPUTBUFFER_SKEIN_256    32
#define HASH_INPUTBUFFER_SKEIN_384    64
#define HASH_INPUTBUFFER_SKEIN_512    64
#define HASH_INPUTBUFFER_SKEIN_1024  128

/* hash input buffer length in bits */
#define HASH_INPUTBUFFER_BITS_SKEIN_224   256
#define HASH_INPUTBUFFER_BITS_SKEIN_256   256
#define HASH_INPUTBUFFER_BITS_SKEIN_384   512
#define HASH_INPUTBUFFER_BITS_SKEIN_512   512
#define HASH_INPUTBUFFER_BITS_SKEIN_1024 1024

/* hash magic values - SKEIxxx etc in little endian notation */
#define HASH_MAGIC_SKEIN_224  0x34323249454b53ULL         /* SKEI224   */
#define HASH_MAGIC_SKEIN_256  0x36353249454b53ULL         /* SKEI256   */
#define HASH_MAGIC_SKEIN_384  0x34383349454b53ULL         /* SKEI384   */
#define HASH_MAGIC_SKEIN_512  0x32313549454b53ULL         /* SKEI512   */
#define HASH_MAGIC_SKEIN_1024  0x3432303149454b53ULL        /* SKEI1024   */

typedef struct
{
    int hashbitlen;                         /* the message digest size */
    /* magic token - must be HASH_MAGIC_SKEIN_xxx */
    DataLength      magic;
    uint_t  statebits;                      /* 256, 512, or 1024 */
    union
        {
        Skein_Ctxt_Hdr_t h;                 /* common header "overlay" */
        Skein_256_Ctxt_t ctx_256;
        Skein_512_Ctxt_t ctx_512;
        Skein1024_Ctxt_t ctx1024;
        } u;
    /* output buffer of hash, 512 bits  */
    BitSequence     out[HASH_LENGTH_SKEIN_1024];
}
    SKEIN_CTX;

/* "incremental" hashing API */
HashReturn SKEIN_Init  (SKEIN_CTX *state, int hashbitlen);
HashReturn SKEIN_Update(SKEIN_CTX *state, const BitSequence *data, DataLength databitlen);
HashReturn SKEIN_Final (SKEIN_CTX *state,       BitSequence *hashval);

/* "all-in-one" call */
HashReturn SKEIN_Hash  (int hashbitlen,   const BitSequence *data, 
                  DataLength databitlen,  BitSequence *hashval);


/*
** Re-define the compile-time constants below to change the selection
** of the Skein state size in the Init() function in SHA3api_ref.c.
**
** That is, the NIST API does not allow for explicit selection of the
** Skein block size, so it must be done implicitly in the Init() function.
** The selection is controlled by these constants.
*/
#ifndef SKEIN_256_NIST_MAX_HASHBITS
#define SKEIN_256_NIST_MAX_HASHBITS (0)
#endif

#ifndef SKEIN_512_NIST_MAX_HASHBITS
#define SKEIN_512_NIST_MAX_HASHBITS (512)
#endif

/* 
 * parameter safe wrappers for JH routines for each hash length
 */

/*********** SKEIN224 definitions *********/
/* initialize context */
extern HashReturn SKEIN224_init (hashState  *state, int hashbitlen);
/* update context, may be called many times */
extern HashReturn  SKEIN224_update (
    hashState state,          /* previously initialized context */
    const BitSequence *buffer,  /* bit buffer, first bit is MSB in [0] */
    DataLength databitlen);      /* number of bits to process from buffer */
/* produce hash and return in hashval */
extern HashReturn  SKEIN224_final (hashState state, BitSequence *hashval);
/* calculate hash all-in-one */
HashReturn SKEIN224_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval);

extern HashReturn SKEIN224_File (hashState state, FILE *in);
extern void SKEIN224_Print (SKEIN_CTX *context);
extern HashReturn SKEIN224_HashToByte (hashState state, BYTE *out);

/*********** SKEIN256 definitions *********/
/* initialize context */
extern HashReturn SKEIN256_init (hashState  *state, int hashbitlen);
/* update context, may be called many times */
extern HashReturn  SKEIN256_update (
    hashState state,          /* previously initialized context */
    const BitSequence *buffer,  /* bit buffer, first bit is MSB in [0] */
    DataLength databitlen);      /* number of bits to process from buffer */
/* produce hash and return in hashval */
extern HashReturn  SKEIN256_final (hashState state, BitSequence *hashval);
/* calculate hash all-in-one */
HashReturn SKEIN256_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval);

extern HashReturn SKEIN256_File (hashState state, FILE *in);
extern void SKEIN256_Print (SKEIN_CTX *context);
extern HashReturn SKEIN256_HashToByte (hashState state, BYTE *out);

/*********** SKEIN384 definitions *********/
/* initialize context */
extern HashReturn SKEIN384_init (hashState  *state, int hashbitlen);
/* update context, may be called many times */
extern HashReturn  SKEIN384_update (
    hashState state,          /* previously initialized context */
    const BitSequence *buffer,  /* bit buffer, first bit is MSB in [0] */
    DataLength databitlen);      /* number of bits to process from buffer */
/* produce hash and return in hashval */
extern HashReturn  SKEIN384_final (hashState state, BitSequence *hashval);
/* calculate hash all-in-one */
HashReturn SKEIN384_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval);

extern HashReturn SKEIN384_File (hashState state, FILE *in);
extern void SKEIN384_Print (SKEIN_CTX *context);
extern HashReturn SKEIN384_HashToByte (hashState state, BYTE *out);

/*********** SKEIN512 definitions *********/
/* initialize context */
extern HashReturn SKEIN512_init (hashState  *state, int hashbitlen);
/* update context, may be called many times */
extern HashReturn  SKEIN512_update (
    hashState state,          /* previously initialized context */
    const BitSequence *buffer,  /* bit buffer, first bit is MSB in [0] */
    DataLength databitlen);      /* number of bits to process from buffer */
/* produce hash and return in hashval */
extern HashReturn  SKEIN512_final (hashState state, BitSequence *hashval);
/* calculate hash all-in-one */
HashReturn SKEIN512_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval);

extern HashReturn SKEIN512_File (hashState state, FILE *in);
extern void SKEIN512_Print (SKEIN_CTX *context);
extern HashReturn SKEIN512_HashToByte (hashState state, BYTE *out);

/*********** SKEIN1024 definitions *********/
/* initialize context */
extern HashReturn SKEIN1024_init (hashState  *state, int hashbitlen);
/* update context, may be called many times */
extern HashReturn  SKEIN1024_update (
    hashState state,          /* previously initialized context */
    const BitSequence *buffer,  /* bit buffer, first bit is MSB in [0] */
    DataLength databitlen);      /* number of bits to process from buffer */
/* produce hash and return in hashval */
extern HashReturn  SKEIN1024_final (hashState state, BitSequence *hashval);
/* calculate hash all-in-one */
HashReturn SKEIN1024_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval);

extern HashReturn SKEIN1024_File (hashState state, FILE *in);
extern void SKEIN1024_Print (SKEIN_CTX *context);
extern HashReturn SKEIN1024_HashToByte (hashState state, BYTE *out);


#endif  /* ifdef _AHS_API_H_ */
