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

#ifndef _WHIRL_H_
#define _WHIRL_H_

#include <limits.h>
#include "generic.h"

/* Definition of minimum-width integer types
 * 
 * u8   -> unsigned integer type, at least 8 bits, equivalent to unsigned char
 * u16  -> unsigned integer type, at least 16 bits
 * u32  -> unsigned integer type, at least 32 bits
 *
 * s8, s16, s32  -> signed counterparts of u8, u16, u32
 *
 * Always use macro's T8(), T16() or T32() to obtain exact-width results,
 * i.e., to specify the size of the result of each expression.
 */

typedef signed char s8;
typedef unsigned char u8;

#if UINT_MAX >= 4294967295UL

typedef signed short s16;
typedef signed int s32;
typedef unsigned short u16;

#define ONE32   0xffffffffU

#else

typedef signed int s16;
typedef signed long s32;
typedef unsigned int u16;
typedef unsigned long u32;

#define ONE32   0xffffffffUL

#endif

#define ONE8    0xffU
#define ONE16   0xffffU

#define T8(x)   ((x) & ONE8)
#define T16(x)  ((x) & ONE16)
#define T32(x)  ((x) & ONE32)

#ifdef _MSC_VER
typedef unsigned __int64 u64;
typedef signed __int64 s64;
#define LL(v)   (v##i64)
#define ONE64   LL(0xffffffffffffffff)
#else  /* !_MSC_VER */
typedef signed long long s64;
#define LL(v)   (v##ULL)
#define ONE64   LL(0xffffffffffffffff)
#endif /* ?_MSC_VER */
#define T64(x)  ((x) & ONE64)
#define ROTR64(v, n)   (((v) >> (n)) | T64((v) << (64 - (n))))
/*
 * Note: the test is used to detect native 64-bit architectures;
 * if the unsigned long is strictly greater than 32-bit, it is
 * assumed to be at least 64-bit. This will not work correctly
 * on (old) 36-bit architectures (PDP-11 for instance).
 *
 * On non-64-bit architectures, "long long" is used.
 */

/*
 * U8TO32_BIG(c) returns the 32-bit value stored in big-endian convention
 * in the unsigned char array pointed to by c.
 */
#define U8TO32_BIG(c)  (((u32)T8(*(c)) << 24) | ((u32)T8(*((c) + 1)) << 16) | ((u32)T8(*((c) + 2)) << 8) | ((u32)T8(*((c) + 3))))

/*
 * U8TO32_LITTLE(c) returns the 32-bit value stored in little-endian convention
 * in the unsigned char array pointed to by c.
 */
#define U8TO32_LITTLE(c)  (((u32)T8(*(c))) | ((u32)T8(*((c) + 1)) << 8) | (u32)T8(*((c) + 2)) << 16) | ((u32)T8(*((c) + 3)) << 24))

/*
 * U8TO32_BIG(c, v) stores the 32-bit-value v in big-endian convention
 * into the unsigned char array pointed to by c.
 */
#define U32TO8_BIG(c, v)    do { u32 x = (v); u8 *d = (c); d[0] = T8(x >> 24); d[1] = T8(x >> 16); d[2] = T8(x >> 8); d[3] = T8(x); } while (0)

/*
 * U8TO32_LITTLE(c, v) stores the 32-bit-value v in little-endian convention
 * into the unsigned char array pointed to by c.
 */
#define U32TO8_LITTLE(c, v)    do { u32 x = (v); u8 *d = (c); d[0] = T8(x); d[1] = T8(x >> 8); d[2] = T8(x >> 16); d[3] = T8(x >> 24); } while (0)

/*
 * ROTL32(v, n) returns the value of the 32-bit unsigned value v after
 * a rotation of n bits to the left. It might be replaced by the appropriate
 * architecture-specific macro.
 *
 * It evaluates v and n twice.
 *
 * The compiler might emit a warning if n is the constant 0. The result
 * is undefined if n is greater than 31.
 */
#ifndef ROTL32
#define ROTL32(v, n)   (T32((v) << (n)) | ((v) >> (32 - (n))))
#endif

/*
 * Whirlpool-specific definitions.
 */


#define DIGESTBYTES 64
#define DIGESTBITS  (8*DIGESTBYTES) /* 512 */
/* hash output length in bits */
#define HASH_BITLENGTH_WHIRL	DIGESTBITS

#define WBLOCKBYTES 64
#define WBLOCKBITS  (8*WBLOCKBYTES) /* 512 */

#define LENGTHBYTES 32
#define LENGTHBITS  (8*LENGTHBYTES) /* 256 */

/* hash magic values - WHIRL in little endian notation */
#define HASH_MAGIC_WHIRL	0x4c52494857ULL

typedef struct NESSIEstruct {
	/* required field: hashbitlen	*/
	/* must be HASH_BITLENGTH_WHIRL */
	unsigned int	hashbitlen;
	/* magic token - WHIRL in LSB notation	*/
	DataLength		magic;
	/* internal state	*/
	u8  bitLength[LENGTHBYTES]; /* global number of hashed bits (256-bit counter) */
	u8  buffer[WBLOCKBYTES];	/* buffer of data to hash */
	int bufferBits;		        /* current number of bits on the buffer */
	int bufferPos;		        /* current (possibly incomplete) byte slot on the buffer */
	u64 hash[DIGESTBYTES/8];    /* the hashing state */
	u8  out[DIGESTBYTES];       /* output, 512 bits */
} NESSIEstruct;

typedef NESSIEstruct WHIRL_CTX;

#define HASH_LENGTH_WHIRL 64
#define HASH_INPUTBUFFER_WHIRL 64

/* initialize context */
extern HashReturn WHIRL_init (hashState  *state, int hashbitlen);
/* update context, may be called many times */
extern HashReturn  WHIRL_update (
    hashState state,          /* previously initialized context */
    const BitSequence *buffer,  /* bit buffer, first bit is MSB in [0] */
    DataLength databitlen);      /* number of bits to process from buffer */
/* produce hash and return in hashval */
extern HashReturn  WHIRL_final (hashState state, BitSequence *hashval);
/* calculate hash all-in-one */
HashReturn WHIRL_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval);

extern HashReturn WHIRL_File (hashState state, FILE *in);
extern void WHIRL_Print (WHIRL_CTX *context);
extern HashReturn WHIRL_HashToByte (hashState state, BYTE *out);

#endif   /* _WHIRL_H_ */

