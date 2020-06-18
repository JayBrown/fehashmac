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
 * The files groestl-opt.c, groestl-opt.h, groestl-tables.h, brg_endian.h,
 * brg_types.h have been taken from the final
 * GROESTL submission to the SHA3 contest, see
 * http://csrc.nist.gov/groups/ST/hash/sha-3/Round3/submissions_rnd3.html
 * The GROESTL homepage is http://www.groestl.info/index.html
 * The authors of GROESTL are    
 * Praveen Gauravaram, Lars R. Knudsen, Soren S. Thomsen
 * (Technical University of Denmark, Lyngby, Denmark)
 * Krystian Matusiewicz (Intel Technology Poland, Gdansk, Poland)
 * Florian Mendel, Martin Schlaeffer 
 * (IAIK, Graz University of Technology, Graz, Austria)
 * Christian Rechberger 
 * (ESAT/COSIC, Katholieke Universiteit Leuven, Heverlee, Belgium)
 *  
 * integration into fehashmac by hvf 09.04.2011
 * align GROESTL_CTX with standard layout - hvf 19.04.2015
 */ 



#ifndef __groestl_opt_h
#define __groestl_opt_h

#include "generic.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "brg_endian.h"
#include "brg_types.h"

/* some sizes (number of bytes) */
#define ROWS 8
#define LENGTHFIELDLEN ROWS
#define COLS512 8
#define COLS1024 16

#define SIZE512 (ROWS*COLS512)
#define SIZE1024 (ROWS*COLS1024)

#define ROUNDS512 10
#define ROUNDS1024 14

#ifndef ROTL32
#define ROTL32(v, n) ((((v)<<(n))|((v)>>(32-(n))))&li_32(ffffffff))
#endif

#if (PLATFORM_BYTE_ORDER == IS_BIG_ENDIAN)
#define EXT_BYTE(var,n) ((u8)((u32)(var) >> (8*(3-(n)))))
#define U32BIG(a) (a)
#endif /* IS_BIG_ENDIAN */

#if (PLATFORM_BYTE_ORDER == IS_LITTLE_ENDIAN)
#define EXT_BYTE(var,n) ((u8)((u32)(var) >> (8*n)))
#define U32BIG(a)				\
  ((ROTL32(a,8) & li_32(00FF00FF)) |		\
   (ROTL32(a,24) & li_32(FF00FF00)))
#endif /* IS_LITTLE_ENDIAN */

typedef enum { LONG, SHORT } Var;

/* hash output length in bytes */
#define HASH_LENGTH_GROESTL_224 28
#define HASH_LENGTH_GROESTL_256 32
#define HASH_LENGTH_GROESTL_384 48
#define HASH_LENGTH_GROESTL_512 64

/* hash output length in bits */
#define HASH_BITLENGTH_GROESTL_224  224
#define HASH_BITLENGTH_GROESTL_256  256
#define HASH_BITLENGTH_GROESTL_384  384
#define HASH_BITLENGTH_GROESTL_512  512

/* hash input buffer length in bytes */
#define HASH_INPUTBUFFER_GROESTL_224    SIZE512
#define HASH_INPUTBUFFER_GROESTL_256    SIZE512
#define HASH_INPUTBUFFER_GROESTL_384    SIZE1024
#define HASH_INPUTBUFFER_GROESTL_512    SIZE1024

/* hash input buffer length in bits */
#define HASH_INPUTBUFFER_BITS_GROESTL_224   (8*SIZE512)
#define HASH_INPUTBUFFER_BITS_GROESTL_256   (8*SIZE512)
#define HASH_INPUTBUFFER_BITS_GROESTL_384   (8*SIZE1024)
#define HASH_INPUTBUFFER_BITS_GROESTL_512   (8*SIZE1024)

/* hash magic values - GROESTxxx etc in little endian notation */
#define HASH_MAGIC_GROESTL_224  0x32325453454f5247ULL         /* GROEST224   */
#define HASH_MAGIC_GROESTL_256  0x35325453454f5247ULL         /* GROEST256   */
#define HASH_MAGIC_GROESTL_384  0x38335453454f5247ULL         /* GROEST384   */
#define HASH_MAGIC_GROESTL_512  0x31355453454f5247ULL         /* GROEST512   */

/*
 *	hashstructure
 *	GROESTL has one common structure for all hash sizes
 */
typedef struct {
  unsigned int hashbitlen;           /* output length in bits */
  DataLength      magic;
  u32 *chaining;            /* actual state */
  u32 block_counter1,
    block_counter2;         /* message block counter(s) */
  BitSequence *buffer;      /* data buffer */
  int buf_ptr;              /* data buffer pointer */
  int bits_in_last_byte;    /* no. of message bits in last byte of
			       data buffer */
  int columns;              /* no. of columns in state */
  int statesize;            /* total no. of bytes in state */
  Var v;                    /* LONG or SHORT */
  BitSequence     out[HASH_LENGTH_GROESTL_512];
} GROESTL_CTX;


/*
 *	hashstructure
 *	GROESTL has one common structure for all hash sizes
 */


/*********** GROESTL224 definitions *********/
/* initialize context */
extern HashReturn GROESTL224_init (hashState  *state, int hashbitlen);
/* update context, may be called many times */
extern HashReturn  GROESTL224_update (
    hashState state,          /* previously initialized context */
    const BitSequence *buffer,  /* bit buffer, first bit is MSB in [0] */
    DataLength databitlen);      /* number of bits to process from buffer */
/* produce hash and return in hashval */
extern HashReturn  GROESTL224_final (hashState state, BitSequence *hashval);
/* calculate hash all-in-one */
HashReturn GROESTL224_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval);

extern HashReturn GROESTL224_File (hashState state, FILE *in);
extern void GROESTL224_Print (GROESTL_CTX *context);
extern HashReturn GROESTL224_HashToByte (hashState state, BYTE *out);

/*********** GROESTL256 definitions *********/
/* initialize context */
extern HashReturn GROESTL256_init (hashState  *state, int hashbitlen);
/* update context, may be called many times */
extern HashReturn  GROESTL256_update (
    hashState state,          /* previously initialized context */
    const BitSequence *buffer,  /* bit buffer, first bit is MSB in [0] */
    DataLength databitlen);      /* number of bits to process from buffer */
/* produce hash and return in hashval */
extern HashReturn  GROESTL256_final (hashState state, BitSequence *hashval);
/* calculate hash all-in-one */
HashReturn GROESTL256_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval);

extern HashReturn GROESTL256_File (hashState state, FILE *in);
extern void GROESTL256_Print (GROESTL_CTX *context);
extern HashReturn GROESTL256_HashToByte (hashState state, BYTE *out);

/*********** GROESTL384 definitions *********/
/* initialize context */
extern HashReturn GROESTL384_init (hashState  *state, int hashbitlen);
/* update context, may be called many times */
extern HashReturn  GROESTL384_update (
    hashState state,          /* previously initialized context */
    const BitSequence *buffer,  /* bit buffer, first bit is MSB in [0] */
    DataLength databitlen);      /* number of bits to process from buffer */
/* produce hash and return in hashval */
extern HashReturn  GROESTL384_final (hashState state, BitSequence *hashval);
/* calculate hash all-in-one */
HashReturn GROESTL384_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval);

extern HashReturn GROESTL384_File (hashState state, FILE *in);
extern void GROESTL384_Print (GROESTL_CTX *context);
extern HashReturn GROESTL384_HashToByte (hashState state, BYTE *out);

/*********** GROESTL512 definitions *********/
/* initialize context */
extern HashReturn GROESTL512_init (hashState  *state, int hashbitlen);
/* update context, may be called many times */
extern HashReturn  GROESTL512_update (
    hashState state,          /* previously initialized context */
    const BitSequence *buffer,  /* bit buffer, first bit is MSB in [0] */
    DataLength databitlen);      /* number of bits to process from buffer */
/* produce hash and return in hashval */
extern HashReturn  GROESTL512_final (hashState state, BitSequence *hashval);
/* calculate hash all-in-one */
HashReturn GROESTL512_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval);

extern HashReturn GROESTL512_File (hashState state, FILE *in);
extern void GROESTL512_Print (GROESTL_CTX *context);
extern HashReturn GROESTL512_HashToByte (hashState state, BYTE *out);


#endif /* __groestl_opt_h */
