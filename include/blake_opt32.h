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
 * The files blake_opt32.h and blake_opt32.c have been taken from the final
 * BLAKE submission to the SHA3 contest, see
 * http://csrc.nist.gov/groups/ST/hash/sha-3/Round3/submissions_rnd3.html
 * The BLAKE homepage is http://www.131002.net/blake/
 * The authors of BLAKE are    
 * Jean-Philippe Aumasson (Nagravision SA, Cheseaux, Switzerland)
 * Luca Henzen (ETHZ, Zürich, Switzerland)
 * Willi Meier (FHNW, Windisch, Switzerland)
 * Raphael C.-W. Phan (Loughborough University, UK)
 *
 * integration into fehashmac by hvf 04.04.2011
 */

#ifndef _BLAKE_OPT32_H_
#define _BLAKE_OPT32_H_

#define DEBUG
#undef DEBUG

#include    "generic.h"
#include    <stdio.h>
#include    <stdlib.h>
#include    <string.h>

#define NB_ROUNDS32 14
#define NB_ROUNDS64 16


/*
  byte-to-word conversion and vice-versa (little endian)  
*/
#define U8TO32_BE(p) \
  (((u32)((p)[0]) << 24) | \
   ((u32)((p)[1]) << 16) | \
   ((u32)((p)[2]) <<  8) | \
   ((u32)((p)[3])      ))

#define U8TO64_BE(p) \
  (((u64)U8TO32_BE(p) << 32) | (u64)U8TO32_BE((p) + 4))

#define U32TO8_BE(p, v) \
  do { \
    (p)[0] = (BitSequence)((v) >> 24);  \
    (p)[1] = (BitSequence)((v) >> 16); \
    (p)[2] = (BitSequence)((v) >>  8); \
    (p)[3] = (BitSequence)((v)      ); \
  } while (0)

#define U64TO8_BE(p, v) \
  do { \
    U32TO8_BE((p),     (u32)((v) >> 32));	\
    U32TO8_BE((p) + 4, (u32)((v)      ));	\
  } while (0)


/* hash output length in bytes */
#define HASH_LENGTH_BLAKE_224 28
#define HASH_LENGTH_BLAKE_256 32
#define HASH_LENGTH_BLAKE_384 48
#define HASH_LENGTH_BLAKE_512 64

/* hash output length in bits */
#define HASH_BITLENGTH_BLAKE_224  224
#define HASH_BITLENGTH_BLAKE_256  256
#define HASH_BITLENGTH_BLAKE_384  384
#define HASH_BITLENGTH_BLAKE_512  512

/* hash input buffer length in bytes */
#define HASH_INPUTBUFFER_BLAKE_224    64
#define HASH_INPUTBUFFER_BLAKE_256    64
#define HASH_INPUTBUFFER_BLAKE_384    128
#define HASH_INPUTBUFFER_BLAKE_512    128

/* hash input buffer length in bits */
#define HASH_INPUTBUFFER_BITS_BLAKE_224   512
#define HASH_INPUTBUFFER_BITS_BLAKE_256   512
#define HASH_INPUTBUFFER_BITS_BLAKE_384   1024
#define HASH_INPUTBUFFER_BITS_BLAKE_512   1024

/* hash input buffer length in 32 or 64 bit words as implemented */
#define HASH_INPUTBUFFER_W_BLAKE_224  16
#define HASH_INPUTBUFFER_W_BLAKE_256  16
#define HASH_INPUTBUFFER_W_BLAKE_384  16
#define HASH_INPUTBUFFER_W_BLAKE_512  16

/* hash magic values - BLAKExxx etc in little endian notation */
#define HASH_MAGIC_BLAKE_224  0x343232454b414c42ULL         /* BLAKE224   */
#define HASH_MAGIC_BLAKE_256  0x363532454b414c42ULL         /* BLAKE256   */
#define HASH_MAGIC_BLAKE_384  0x343833454b414c42ULL         /* BLAKE384   */
#define HASH_MAGIC_BLAKE_512  0x323135454b414c42ULL         /* BLAKE512   */

/* 
   hash structure
   BLAKE has one common hash structure for all hash sizes
*/
typedef struct  { 
  int hashbitlen;  /* length of the hash value (bits) */
  /* magic token - must be HASH_MAGIC_BLAKE_xxx	*/
  DataLength      magic;
  int datalen;     /* amount of remaining data to hash (bits) */
  int init;        /* set to 1 when initialized */
  int nullt;       /* Boolean value for special case \ell_i=0 */
  /*
    variables for the 32-bit version  
  */
  u32 h32[8];         /* current chain value (initialized to the IV) */
  u32 t32[2];         /* number of bits hashed so far */
  BitSequence data32[64];     /* remaining data to hash (less than a block) */
  u32 salt32[4];      /* salt (null by default) */
  /*
    variables for the 64-bit version  
  */
  u64 h64[8];      /* current chain value (initialized to the IV) */
  u64 t64[2];      /* number of bits hashed so far */
  BitSequence data64[128];  /* remaining data to hash (less than a block) */
  u64 salt64[4];   /* salt (null by default) */
  /* output buffer of hash, 512 bits  */
  BitSequence     out[HASH_LENGTH_BLAKE_512];
} BLAKE_CTX;

/*
  the 10 permutations of {0,...15}
*/
static const unsigned char sigma[][16] = {
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 } ,
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 } ,
    { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 } ,
    {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 } ,
    {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 } ,
    {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 } ,
    { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 } ,
    { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 } ,
    {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 } ,
    { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13 , 0 }, 
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 } ,
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 } ,
    { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 } ,
    {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 } ,
    {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 } ,
    {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 } ,
    { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 } ,
    { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 } ,
    {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 } ,
    { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13 , 0 }  
  };

/*
  constants for BLAKE-32 and BLAKE-28
*/
static const u32 c32[16] = {
    0x243F6A88, 0x85A308D3,
    0x13198A2E, 0x03707344,
    0xA4093822, 0x299F31D0,
    0x082EFA98, 0xEC4E6C89,
    0x452821E6, 0x38D01377,
    0xBE5466CF, 0x34E90C6C,
    0xC0AC29B7, 0xC97C50DD,
    0x3F84D5B5, 0xB5470917 
};

/*
  constants for BLAKE-64 and BLAKE-48
*/
static const u64 c64[16] = {
  0x243F6A8885A308D3ULL,0x13198A2E03707344ULL,
  0xA4093822299F31D0ULL,0x082EFA98EC4E6C89ULL,
  0x452821E638D01377ULL,0xBE5466CF34E90C6CULL,
  0xC0AC29B7C97C50DDULL,0x3F84D5B5B5470917ULL,
  0x9216D5D98979FB1BULL,0xD1310BA698DFB5ACULL,
  0x2FFD72DBD01ADFB7ULL,0xB8E1AFED6A267E96ULL,
  0xBA7C9045F12C7F99ULL,0x24A19947B3916CF7ULL,
  0x0801F2E2858EFC16ULL,0x636920D871574E69ULL
};

/*
  padding data
*/
static const BitSequence padding[129] =
  {
    0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/*
  initial values ( IVx for BLAKE-x)
*/
static const u32 IV256[8]={
  0x6A09E667, 0xBB67AE85,
  0x3C6EF372, 0xA54FF53A,
  0x510E527F, 0x9B05688C,
  0x1F83D9AB, 0x5BE0CD19
};
static const u32 IV224[8]={
  0xC1059ED8, 0x367CD507,
  0x3070DD17, 0xF70E5939,
  0xFFC00B31, 0x68581511,
  0x64F98FA7, 0xBEFA4FA4
};
static const u64 IV384[8]={
  0xCBBB9D5DC1059ED8ULL, 0x629A292A367CD507ULL,
  0x9159015A3070DD17ULL, 0x152FECD8F70E5939ULL,
  0x67332667FFC00B31ULL, 0x8EB44A8768581511ULL,
  0xDB0C2E0D64F98FA7ULL, 0x47B5481DBEFA4FA4ULL
};
static const u64 IV512[8]={
  0x6A09E667F3BCC908ULL, 0xBB67AE8584CAA73BULL,
  0x3C6EF372FE94F82BULL, 0xA54FF53A5F1D36F1ULL,
  0x510E527FADE682D1ULL, 0x9B05688C2B3E6C1FULL,
  0x1F83D9ABFB41BD6BULL, 0x5BE0CD19137E2179ULL
};

/* 
 * parameter safe wrappers for BLAKE routines for each hash length
 */

/*********** BLAKE224 definitions *********/
/* initialize context */
extern HashReturn BLAKE224_init (hashState  *state, int hashbitlen);
/* update context, may be called many times */
extern HashReturn  BLAKE224_update (
    hashState state,          /* previously initialized context */
    const BitSequence *buffer,  /* bit buffer, first bit is MSB in [0] */
    DataLength databitlen);      /* number of bits to process from buffer */
/* produce hash and return in hashval */
extern HashReturn  BLAKE224_final (hashState state, BitSequence *hashval);
/* calculate hash all-in-one */
HashReturn BLAKE224_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval);

extern HashReturn BLAKE224_File (hashState state, FILE *in);
extern void BLAKE224_Print (BLAKE_CTX *context);
extern HashReturn BLAKE224_HashToByte (hashState state, BYTE *out);

/*********** BLAKE256 definitions *********/
/* initialize context */
extern HashReturn BLAKE256_init (hashState  *state, int hashbitlen);
/* update context, may be called many times */
extern HashReturn  BLAKE256_update (
    hashState state,          /* previously initialized context */
    const BitSequence *buffer,  /* bit buffer, first bit is MSB in [0] */
    DataLength databitlen);      /* number of bits to process from buffer */
/* produce hash and return in hashval */
extern HashReturn  BLAKE256_final (hashState state, BitSequence *hashval);
/* calculate hash all-in-one */
HashReturn BLAKE256_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval);

extern HashReturn BLAKE256_File (hashState state, FILE *in);
extern void BLAKE256_Print (BLAKE_CTX *context);
extern HashReturn BLAKE256_HashToByte (hashState state, BYTE *out);

/*********** BLAKE384 definitions *********/
/* initialize context */
extern HashReturn BLAKE384_init (hashState  *state, int hashbitlen);
/* update context, may be called many times */
extern HashReturn  BLAKE384_update (
    hashState state,          /* previously initialized context */
    const BitSequence *buffer,  /* bit buffer, first bit is MSB in [0] */
    DataLength databitlen);      /* number of bits to process from buffer */
/* produce hash and return in hashval */
extern HashReturn  BLAKE384_final (hashState state, BitSequence *hashval);
/* calculate hash all-in-one */
HashReturn BLAKE384_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval);

extern HashReturn BLAKE384_File (hashState state, FILE *in);
extern void BLAKE384_Print (BLAKE_CTX *context);
extern HashReturn BLAKE384_HashToByte (hashState state, BYTE *out);

/*********** BLAKE512 definitions *********/
/* initialize context */
extern HashReturn BLAKE512_init (hashState  *state, int hashbitlen);
/* update context, may be called many times */
extern HashReturn  BLAKE512_update (
    hashState state,          /* previously initialized context */
    const BitSequence *buffer,  /* bit buffer, first bit is MSB in [0] */
    DataLength databitlen);      /* number of bits to process from buffer */
/* produce hash and return in hashval */
extern HashReturn  BLAKE512_final (hashState state, BitSequence *hashval);
/* calculate hash all-in-one */
HashReturn BLAKE512_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval);

extern HashReturn BLAKE512_File (hashState state, FILE *in);
extern void BLAKE512_Print (BLAKE_CTX *context);
extern HashReturn BLAKE512_HashToByte (hashState state, BYTE *out);


#endif
