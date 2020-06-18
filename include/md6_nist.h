/*
 * Generic Hash and HMAC Program
 *
 * Copyright (C) 2009 2016 Harald von Fellenberg <hvf@hvf.ch>
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

/* File:    md6_nist.h
** Author:  Ronald L. Rivest
** Address: Room 32G-692 Stata Center 
**          32 Vassar Street 
**          Cambridge, MA 02139
** Email:   rivest@mit.edu
** Date:    9/25/2008
**
** (The following license is known as "The MIT License")
** 
** Copyright (c) 2008 Ronald L. Rivest
** 
** Permission is hereby granted, free of charge, to any person obtaining a copy
** of this software and associated documentation files (the "Software"), to deal
** in the Software without restriction, including without limitation the rights
** to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
** copies of the Software, and to permit persons to whom the Software is
** furnished to do so, subject to the following conditions:
** 
** The above copyright notice and this permission notice shall be included in
** all copies or substantial portions of the Software.
** 
** THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
** IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
** FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
** AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
** LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
** OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
** THE SOFTWARE.
**
** (end of license)
**
** This is part of the MD6 hash function package.
** The files defining the MD6 hash function are:
**    md6.h
**    md6_compress.c
**    md6_mode.c
** The files defining the interface between MD6 and the NIST SHA-3
** API are:
**    md6_nist.h
**    md6_nist.c
** The NIST SHA-3 API is defined in:
**    http://www.csrc.nist.gov/groups/ST/hash/documents/SHA3-C-API.pdf
**
** See  http://groups.csail.mit.edu/cis/md6  for more information.
*/

/* 07.03.2016 hvf integrated into FEHASHMAC
*/

/* Multiple inclusion protection (through end of file)
*/
#ifndef MD6_NIST_H_INCLUDED
#define MD6_NIST_H_INCLUDED

#include    "generic.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include    "md6.h"

/* hash output length in bytes */
#define HASH_LENGTH_MD6_224 28
#define HASH_LENGTH_MD6_256 32
#define HASH_LENGTH_MD6_384 48
#define HASH_LENGTH_MD6_512 64

/* hash output length in bits */
#define HASH_BITLENGTH_MD6_224  224
#define HASH_BITLENGTH_MD6_256  256
#define HASH_BITLENGTH_MD6_384  384
#define HASH_BITLENGTH_MD6_512  512

/* hash input buffer length in bytes */ 
#define HASH_INPUTBUFFER_MD6_224    512
#define HASH_INPUTBUFFER_MD6_256    512
#define HASH_INPUTBUFFER_MD6_384    512
#define HASH_INPUTBUFFER_MD6_512    512

/* hash input buffer length in bits */
#define HASH_INPUTBUFFER_BITS_MD6_224   4096
#define HASH_INPUTBUFFER_BITS_MD6_256   4096
#define HASH_INPUTBUFFER_BITS_MD6_384   4096
#define HASH_INPUTBUFFER_BITS_MD6_512   4096

/* hash magic value - MD6_xxx in little endian notation    */
#define HASH_MAGIC_MD6_224 0x3432325f36444dULL
#define HASH_MAGIC_MD6_256 0x3635325f36444dULL
#define HASH_MAGIC_MD6_384 0x3438335f36444dULL
#define HASH_MAGIC_MD6_512 0x3231355f36444dULL


/*********** MD6-224 definitions *********/
/* initialize context */
extern HashReturn MD6_224_init (hashState  *state, int hashbitlen);
/* update context, may be called many times */
extern HashReturn  MD6_224_update (
    hashState state,          /* previously initialized context */
    const BitSequence *buffer,  /* bit buffer, first bit is MSB in [0] */
    DataLength databitlen);      /* number of bits to process from buffer */
/* produce hash and return in hashval */
extern HashReturn  MD6_224_final (hashState state, BitSequence *hashval);
/* calculate hash all-in-one */
HashReturn MD6_224_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval);

extern HashReturn MD6_224_File (hashState state, FILE *in);
extern void MD6_224_Print (MD6_CTX *context);
extern HashReturn MD6_224_HashToByte (hashState state, BYTE *out);


/*********** MD6-256 definitions *********/
/* initialize context */
extern HashReturn MD6_256_init (hashState  *state, int hashbitlen);
/* update context, may be called many times */
extern HashReturn  MD6_256_update (
    hashState state,          /* previously initialized context */
    const BitSequence *buffer,  /* bit buffer, first bit is MSB in [0] */
    DataLength databitlen);      /* number of bits to process from buffer */
/* produce hash and return in hashval */
extern HashReturn  MD6_256_final (hashState state, BitSequence *hashval);
/* calculate hash all-in-one */
HashReturn MD6_256_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval);

extern HashReturn MD6_256_File (hashState state, FILE *in);
extern void MD6_256_Print (MD6_CTX *context);
extern HashReturn MD6_256_HashToByte (hashState state, BYTE *out);


/*********** MD6-384 definitions *********/
/* initialize context */
extern HashReturn MD6_384_init (hashState  *state, int hashbitlen);
/* update context, may be called many times */
extern HashReturn  MD6_384_update (
    hashState state,          /* previously initialized context */
    const BitSequence *buffer,  /* bit buffer, first bit is MSB in [0] */
    DataLength databitlen);      /* number of bits to process from buffer */
/* produce hash and return in hashval */
extern HashReturn  MD6_384_final (hashState state, BitSequence *hashval);
/* calculate hash all-in-one */
HashReturn MD6_384_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval);

extern HashReturn MD6_384_File (hashState state, FILE *in);
extern void MD6_384_Print (MD6_CTX *context);
extern HashReturn MD6_384_HashToByte (hashState state, BYTE *out);

/*********** MD6-512 definitions *********/
/* initialize context */
extern HashReturn MD6_512_init (hashState  *state, int hashbitlen);
/* update context, may be called many times */
extern HashReturn  MD6_512_update (
    hashState state,          /* previously initialized context */
    const BitSequence *buffer,  /* bit buffer, first bit is MSB in [0] */
    DataLength databitlen);      /* number of bits to process from buffer */
/* produce hash and return in hashval */
extern HashReturn  MD6_512_final (hashState state, BitSequence *hashval);
/* calculate hash all-in-one */
HashReturn MD6_512_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval);

extern HashReturn MD6_512_File (hashState state, FILE *in);
extern void MD6_512_Print (MD6_CTX *context);
extern HashReturn MD6_512_HashToByte (hashState state, BYTE *out);

/*****************************************/

/* end of multiple inclusion protection
*/
#endif

/*
** end of nist.h
*/
