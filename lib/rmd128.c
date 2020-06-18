/* rmd160.c     RIPEMD-160 hash algorithm
 * integrated into fehashmac
 * hvf 13.08.01
 * hvf 15.02.2009	align with SHA3-C-API
 * disabled RIPEMD128_Print - hvf 19.04.2015
 *
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

#include	"rmdx.h"
#include	<string.h>
#include	<stdlib.h>
#include	<stdio.h>

#define DEBUG
#undef  DEBUG

/********************************************************************\
 *
 *      FILE:     rmd128.h
 *
 *      CONTENTS: Header file for a sample C-implementation of the
 *                RIPEMD-128 hash-function. This function is a
 *                plug-in substitute for RIPEMD. A 160-bit hash
 *                result is obtained using RIPEMD-160.
 *      TARGET:   any computer with an ANSI C compiler
 *
 *      AUTHOR:   Antoon Bosselaers, ESAT-COSIC
 *      DATE:     1 March 1996
 *      VERSION:  1.0
 *
 *      Copyright (c) Katholieke Universiteit Leuven
 *      1996, All Rights Reserved
 *
 *  Conditions for use of the RIPEMD-160 Software
 *
 *  The RIPEMD-160 software is freely available for use under the terms and
 *  conditions described hereunder, which shall be deemed to be accepted by
 *  any user of the software and applicable on any use of the software:
 * 
 *  1. K.U.Leuven Department of Electrical Engineering-ESAT/COSIC shall for
 *     all purposes be considered the owner of the RIPEMD-160 software and of
 *     all copyright, trade secret, patent or other intellectual property
 *     rights therein.
 *  2. The RIPEMD-160 software is provided on an "as is" basis without
 *     warranty of any sort, express or implied. K.U.Leuven makes no
 *     representation that the use of the software will not infringe any
 *     patent or proprietary right of third parties. User will indemnify
 *     K.U.Leuven and hold K.U.Leuven harmless from any claims or liabilities
 *     which may arise as a result of its use of the software. In no
 *     circumstances K.U.Leuven R&D will be held liable for any deficiency,
 *     fault or other mishappening with regard to the use or performance of
 *     the software.
 *  3. User agrees to give due credit to K.U.Leuven in scientific publications 
 *     or communications in relation with the use of the RIPEMD-160 software 
 *     as follows: RIPEMD-160 software written by Antoon Bosselaers, 
 *     available at http://www.esat.kuleuven.ac.be/~cosicart/ps/AB-9601/.
 *
\********************************************************************/

/* macro definitions */

/* collect four bytes into one word: */
#define BYTES_TO_unsigned int(strptr)                    \
            (((unsigned int) *((strptr)+3) << 24) | \
             ((unsigned int) *((strptr)+2) << 16) | \
             ((unsigned int) *((strptr)+1) <<  8) | \
             ((unsigned int) *(strptr)))

/* ROL(x, n) cyclically rotates x over n bits to the left */
/* x must be of an unsigned 32 bits type and 0 <= n < 32. */
#define ROL(x, n)        (((x) << (n)) | ((x) >> (32-(n))))

/* the four basic functions F(), G() and H() */
#define F(x, y, z)        ((x) ^ (y) ^ (z)) 
#define G(x, y, z)        (((x) & (y)) | (~(x) & (z))) 
#define H(x, y, z)        (((x) | ~(y)) ^ (z))
#define I(x, y, z)        (((x) & (z)) | ((y) & ~(z))) 
  
/* the eight basic operations FF() through III() */
#define FF(a, b, c, d, x, s)        {\
      (a) += F((b), (c), (d)) + (x);\
      (a) = ROL((a), (s));\
   }
#define GG(a, b, c, d, x, s)        {\
      (a) += G((b), (c), (d)) + (x) + 0x5a827999UL;\
      (a) = ROL((a), (s));\
   }
#define HH(a, b, c, d, x, s)        {\
      (a) += H((b), (c), (d)) + (x) + 0x6ed9eba1UL;\
      (a) = ROL((a), (s));\
   }
#define II(a, b, c, d, x, s)        {\
      (a) += I((b), (c), (d)) + (x) + 0x8f1bbcdcUL;\
      (a) = ROL((a), (s));\
   }
#define FFF(a, b, c, d, x, s)        {\
      (a) += F((b), (c), (d)) + (x);\
      (a) = ROL((a), (s));\
   }
#define GGG(a, b, c, d, x, s)        {\
      (a) += G((b), (c), (d)) + (x) + 0x6d703ef3UL;\
      (a) = ROL((a), (s));\
   }
#define HHH(a, b, c, d, x, s)        {\
      (a) += H((b), (c), (d)) + (x) + 0x5c4dd124UL;\
      (a) = ROL((a), (s));\
   }
#define III(a, b, c, d, x, s)        {\
      (a) += I((b), (c), (d)) + (x) + 0x50a28be6UL;\
      (a) = ROL((a), (s));\
   }

/********************************************************************/

HashReturn RIPEMD128_init (hashState  *state, int hashbitlen)
{
	/* verify correct hash length	*/
	if (hashbitlen != HASH_BITLENGTH_RIPEMD128)
		return BAD_HASHBITLEN;

	/* allocate context and fill it	*/
	RIPEMD128_CTX *context = (RIPEMD128_CTX *)malloc (sizeof (RIPEMD128_CTX));
	memset (context, 0, sizeof (RIPEMD128_CTX));
	context->hashbitlen = HASH_BITLENGTH_RIPEMD128;
	context->magic = HASH_MAGIC_RIPEMD128;

	context->MDbuf[0] = 0x67452301UL;
	context->MDbuf[1] = 0xefcdab89UL;
	context->MDbuf[2] = 0x98badcfeUL;
	context->MDbuf[3] = 0x10325476UL;

	*state = (hashState *) context;
	return SUCCESS;
}

/********************************************************************/

static void RIPEMD128_transform(RIPEMD128_CTX *context)
{
   unsigned int aa = context->MDbuf[0],  bb = context->MDbuf[1],  
	cc = context->MDbuf[2],  dd = context->MDbuf[3];
   unsigned int aaa = context->MDbuf[0], bbb = context->MDbuf[1], 
	ccc = context->MDbuf[2], ddd = context->MDbuf[3];

#ifdef DEBUG
	int i;
	for (i=0; i<HASH_INPUTBUFFER_W_RIPEMD128; i++)
		printf ("W[%2d] = %8.8x\n", i, context->m_buffer[i]);
#endif

   /* round 1 */
   FF(aa, bb, cc, dd, context->m_buffer[ 0], 11);
   FF(dd, aa, bb, cc, context->m_buffer[ 1], 14);
   FF(cc, dd, aa, bb, context->m_buffer[ 2], 15);
   FF(bb, cc, dd, aa, context->m_buffer[ 3], 12);
   FF(aa, bb, cc, dd, context->m_buffer[ 4],  5);
   FF(dd, aa, bb, cc, context->m_buffer[ 5],  8);
   FF(cc, dd, aa, bb, context->m_buffer[ 6],  7);
   FF(bb, cc, dd, aa, context->m_buffer[ 7],  9);
   FF(aa, bb, cc, dd, context->m_buffer[ 8], 11);
   FF(dd, aa, bb, cc, context->m_buffer[ 9], 13);
   FF(cc, dd, aa, bb, context->m_buffer[10], 14);
   FF(bb, cc, dd, aa, context->m_buffer[11], 15);
   FF(aa, bb, cc, dd, context->m_buffer[12],  6);
   FF(dd, aa, bb, cc, context->m_buffer[13],  7);
   FF(cc, dd, aa, bb, context->m_buffer[14],  9);
   FF(bb, cc, dd, aa, context->m_buffer[15],  8);
                             
   /* round 2 */
   GG(aa, bb, cc, dd, context->m_buffer[ 7],  7);
   GG(dd, aa, bb, cc, context->m_buffer[ 4],  6);
   GG(cc, dd, aa, bb, context->m_buffer[13],  8);
   GG(bb, cc, dd, aa, context->m_buffer[ 1], 13);
   GG(aa, bb, cc, dd, context->m_buffer[10], 11);
   GG(dd, aa, bb, cc, context->m_buffer[ 6],  9);
   GG(cc, dd, aa, bb, context->m_buffer[15],  7);
   GG(bb, cc, dd, aa, context->m_buffer[ 3], 15);
   GG(aa, bb, cc, dd, context->m_buffer[12],  7);
   GG(dd, aa, bb, cc, context->m_buffer[ 0], 12);
   GG(cc, dd, aa, bb, context->m_buffer[ 9], 15);
   GG(bb, cc, dd, aa, context->m_buffer[ 5],  9);
   GG(aa, bb, cc, dd, context->m_buffer[ 2], 11);
   GG(dd, aa, bb, cc, context->m_buffer[14],  7);
   GG(cc, dd, aa, bb, context->m_buffer[11], 13);
   GG(bb, cc, dd, aa, context->m_buffer[ 8], 12);

   /* round 3 */
   HH(aa, bb, cc, dd, context->m_buffer[ 3], 11);
   HH(dd, aa, bb, cc, context->m_buffer[10], 13);
   HH(cc, dd, aa, bb, context->m_buffer[14],  6);
   HH(bb, cc, dd, aa, context->m_buffer[ 4],  7);
   HH(aa, bb, cc, dd, context->m_buffer[ 9], 14);
   HH(dd, aa, bb, cc, context->m_buffer[15],  9);
   HH(cc, dd, aa, bb, context->m_buffer[ 8], 13);
   HH(bb, cc, dd, aa, context->m_buffer[ 1], 15);
   HH(aa, bb, cc, dd, context->m_buffer[ 2], 14);
   HH(dd, aa, bb, cc, context->m_buffer[ 7],  8);
   HH(cc, dd, aa, bb, context->m_buffer[ 0], 13);
   HH(bb, cc, dd, aa, context->m_buffer[ 6],  6);
   HH(aa, bb, cc, dd, context->m_buffer[13],  5);
   HH(dd, aa, bb, cc, context->m_buffer[11], 12);
   HH(cc, dd, aa, bb, context->m_buffer[ 5],  7);
   HH(bb, cc, dd, aa, context->m_buffer[12],  5);

   /* round 4 */
   II(aa, bb, cc, dd, context->m_buffer[ 1], 11);
   II(dd, aa, bb, cc, context->m_buffer[ 9], 12);
   II(cc, dd, aa, bb, context->m_buffer[11], 14);
   II(bb, cc, dd, aa, context->m_buffer[10], 15);
   II(aa, bb, cc, dd, context->m_buffer[ 0], 14);
   II(dd, aa, bb, cc, context->m_buffer[ 8], 15);
   II(cc, dd, aa, bb, context->m_buffer[12],  9);
   II(bb, cc, dd, aa, context->m_buffer[ 4],  8);
   II(aa, bb, cc, dd, context->m_buffer[13],  9);
   II(dd, aa, bb, cc, context->m_buffer[ 3], 14);
   II(cc, dd, aa, bb, context->m_buffer[ 7],  5);
   II(bb, cc, dd, aa, context->m_buffer[15],  6);
   II(aa, bb, cc, dd, context->m_buffer[14],  8);
   II(dd, aa, bb, cc, context->m_buffer[ 5],  6);
   II(cc, dd, aa, bb, context->m_buffer[ 6],  5);
   II(bb, cc, dd, aa, context->m_buffer[ 2], 12);

   /* parallel round 1 */
   III(aaa, bbb, ccc, ddd, context->m_buffer[ 5],  8); 
   III(ddd, aaa, bbb, ccc, context->m_buffer[14],  9);
   III(ccc, ddd, aaa, bbb, context->m_buffer[ 7],  9);
   III(bbb, ccc, ddd, aaa, context->m_buffer[ 0], 11);
   III(aaa, bbb, ccc, ddd, context->m_buffer[ 9], 13);
   III(ddd, aaa, bbb, ccc, context->m_buffer[ 2], 15);
   III(ccc, ddd, aaa, bbb, context->m_buffer[11], 15);
   III(bbb, ccc, ddd, aaa, context->m_buffer[ 4],  5);
   III(aaa, bbb, ccc, ddd, context->m_buffer[13],  7);
   III(ddd, aaa, bbb, ccc, context->m_buffer[ 6],  7);
   III(ccc, ddd, aaa, bbb, context->m_buffer[15],  8);
   III(bbb, ccc, ddd, aaa, context->m_buffer[ 8], 11);
   III(aaa, bbb, ccc, ddd, context->m_buffer[ 1], 14);
   III(ddd, aaa, bbb, ccc, context->m_buffer[10], 14);
   III(ccc, ddd, aaa, bbb, context->m_buffer[ 3], 12);
   III(bbb, ccc, ddd, aaa, context->m_buffer[12],  6);

   /* parallel round 2 */
   HHH(aaa, bbb, ccc, ddd, context->m_buffer[ 6],  9);
   HHH(ddd, aaa, bbb, ccc, context->m_buffer[11], 13);
   HHH(ccc, ddd, aaa, bbb, context->m_buffer[ 3], 15);
   HHH(bbb, ccc, ddd, aaa, context->m_buffer[ 7],  7);
   HHH(aaa, bbb, ccc, ddd, context->m_buffer[ 0], 12);
   HHH(ddd, aaa, bbb, ccc, context->m_buffer[13],  8);
   HHH(ccc, ddd, aaa, bbb, context->m_buffer[ 5],  9);
   HHH(bbb, ccc, ddd, aaa, context->m_buffer[10], 11);
   HHH(aaa, bbb, ccc, ddd, context->m_buffer[14],  7);
   HHH(ddd, aaa, bbb, ccc, context->m_buffer[15],  7);
   HHH(ccc, ddd, aaa, bbb, context->m_buffer[ 8], 12);
   HHH(bbb, ccc, ddd, aaa, context->m_buffer[12],  7);
   HHH(aaa, bbb, ccc, ddd, context->m_buffer[ 4],  6);
   HHH(ddd, aaa, bbb, ccc, context->m_buffer[ 9], 15);
   HHH(ccc, ddd, aaa, bbb, context->m_buffer[ 1], 13);
   HHH(bbb, ccc, ddd, aaa, context->m_buffer[ 2], 11);

   /* parallel round 3 */   
   GGG(aaa, bbb, ccc, ddd, context->m_buffer[15],  9);
   GGG(ddd, aaa, bbb, ccc, context->m_buffer[ 5],  7);
   GGG(ccc, ddd, aaa, bbb, context->m_buffer[ 1], 15);
   GGG(bbb, ccc, ddd, aaa, context->m_buffer[ 3], 11);
   GGG(aaa, bbb, ccc, ddd, context->m_buffer[ 7],  8);
   GGG(ddd, aaa, bbb, ccc, context->m_buffer[14],  6);
   GGG(ccc, ddd, aaa, bbb, context->m_buffer[ 6],  6);
   GGG(bbb, ccc, ddd, aaa, context->m_buffer[ 9], 14);
   GGG(aaa, bbb, ccc, ddd, context->m_buffer[11], 12);
   GGG(ddd, aaa, bbb, ccc, context->m_buffer[ 8], 13);
   GGG(ccc, ddd, aaa, bbb, context->m_buffer[12],  5);
   GGG(bbb, ccc, ddd, aaa, context->m_buffer[ 2], 14);
   GGG(aaa, bbb, ccc, ddd, context->m_buffer[10], 13);
   GGG(ddd, aaa, bbb, ccc, context->m_buffer[ 0], 13);
   GGG(ccc, ddd, aaa, bbb, context->m_buffer[ 4],  7);
   GGG(bbb, ccc, ddd, aaa, context->m_buffer[13],  5);

   /* parallel round 4 */
   FFF(aaa, bbb, ccc, ddd, context->m_buffer[ 8], 15);
   FFF(ddd, aaa, bbb, ccc, context->m_buffer[ 6],  5);
   FFF(ccc, ddd, aaa, bbb, context->m_buffer[ 4],  8);
   FFF(bbb, ccc, ddd, aaa, context->m_buffer[ 1], 11);
   FFF(aaa, bbb, ccc, ddd, context->m_buffer[ 3], 14);
   FFF(ddd, aaa, bbb, ccc, context->m_buffer[11], 14);
   FFF(ccc, ddd, aaa, bbb, context->m_buffer[15],  6);
   FFF(bbb, ccc, ddd, aaa, context->m_buffer[ 0], 14);
   FFF(aaa, bbb, ccc, ddd, context->m_buffer[ 5],  6);
   FFF(ddd, aaa, bbb, ccc, context->m_buffer[12],  9);
   FFF(ccc, ddd, aaa, bbb, context->m_buffer[ 2], 12);
   FFF(bbb, ccc, ddd, aaa, context->m_buffer[13],  9);
   FFF(aaa, bbb, ccc, ddd, context->m_buffer[ 9], 12);
   FFF(ddd, aaa, bbb, ccc, context->m_buffer[ 7],  5);
   FFF(ccc, ddd, aaa, bbb, context->m_buffer[10], 15);
   FFF(bbb, ccc, ddd, aaa, context->m_buffer[14],  8);

   /* combine results */
   ddd += cc + context->MDbuf[1];               /* final result for context->MDbuf[0] */
   context->MDbuf[1] = context->MDbuf[2] + dd + aaa;
   context->MDbuf[2] = context->MDbuf[3] + aa + bbb;
   context->MDbuf[3] = context->MDbuf[0] + bb + ccc;
   context->MDbuf[0] = ddd;

    context->count = 0;
    memset (context->m_buffer, 0, sizeof (context->m_buffer));

   return;
}

/********************************************************************/
void    RIPEMD128_update_old (RIPEMD128_CTX *context, const unsigned char *buffer,
unsigned int n)
{   /* can be called once or many times */
    unsigned int i;
    int c;
    for (i=0; i<n; i++){
        c = context->count++;
        /* filling is little-endian */
        context->m_buffer[c>>2] |= (unsigned int)buffer[i]<<((c&0x03)<<3);
        context->total_count += 8LL;    /* 8 bits per byte */
        if (c == 63)
            RIPEMD128_transform (context);
    }
}

void RIPEMD128_final_old (RIPEMD128_CTX *context)
{   /* does padding of last block, little endian    */
    int i;
    unsigned int c = context->count;
    context->m_buffer[c>>2] |= 0x80<<(((c&0x03)<<3));
    if (c > 55)
        RIPEMD128_transform (context);
    context->m_buffer[14] = (unsigned int) context->total_count;
    context->m_buffer[15] = (unsigned int) (context->total_count >> 32);
    RIPEMD128_transform (context);

    for (i=0; i<HASH_LENGTH_RIPEMD128; i++)
        context->out[i] = context->MDbuf[i>>2]>>(((i&0x03)<<3));

    return;
}

HashReturn 	RIPEMD128_update (
	hashState state, 			/* previously initialized context */
	const BitSequence *buffer, 	/* bit buffer, first bit is MSB in [0] */
	DataLength databitlen)		/* number of bits to process from buffer */
{	
	/* can be called once or many times */
	/* verify correct hashbitlen and magic	*/

	RIPEMD128_CTX *context = (RIPEMD128_CTX *) state;
	if (context->hashbitlen != HASH_BITLENGTH_RIPEMD128)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_RIPEMD128)
		return BAD_ALGORITHM;

	/* check for byte alignment */
	if ((databitlen & 0x7)) {
		return FAIL;
	}

	RIPEMD128_update_old (context, buffer, (unsigned int)(databitlen>>3));
	return SUCCESS;
}

HashReturn	RIPEMD128_final (hashState state, BitSequence *hashval)
{	/*	does padding of last block	*/
	RIPEMD128_CTX *context = (RIPEMD128_CTX *) state;
	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_RIPEMD128)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_RIPEMD128)
		return BAD_ALGORITHM;

	RIPEMD128_final_old (context);

	if (hashval)
		memcpy (hashval, context->out, HASH_LENGTH_RIPEMD128);
	return SUCCESS;
}

/* RIPEMD128 utility routines
 *
 * hvf 23.1.2000
 * hvf 13.2.01
 * hvf 10.8.01
 * hvf 15.02.2009
 */

/* Digests a file and prints the result.
 */

HashReturn RIPEMD128_File (hashState state, FILE *in)
{
	RIPEMD128_CTX *context = (RIPEMD128_CTX *) state;
	int len;
	unsigned char buffer[BUFFERSIZE];
	HashReturn retval;

	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_RIPEMD128)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_RIPEMD128)
		return BAD_ALGORITHM;

	while ((len = fread (buffer, 1, BUFFERSIZE, in))) {
		retval = RIPEMD128_update (context, buffer, (DataLength)len << 3);
		if (retval != SUCCESS) return retval;
	}
	retval = RIPEMD128_final (context, NULL);

	fclose (in);
	return retval;
}


HashReturn RIPEMD128_HashToByte (hashState state, BYTE *out) 
{
	RIPEMD128_CTX *context = (RIPEMD128_CTX *) state;

	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_RIPEMD128)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_RIPEMD128)
		return BAD_ALGORITHM;

	memcpy (out, context->out, HASH_LENGTH_RIPEMD128);
	return SUCCESS;
}

/* all-in-one hash function as required by SHA3-C-API */

HashReturn RIPEMD128_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval) 
{
	hashState	state;
	HashReturn	retval;
	
	retval = RIPEMD128_init (&state, HASH_BITLENGTH_RIPEMD128);
	if (retval != SUCCESS) {
		fprintf (stderr, "RIPEMD128_init failed, reason %d, hash length %d\n",
                 retval, HASH_BITLENGTH_RIPEMD128);
        exit (1);
    }

	retval = RIPEMD128_update (state, data, databitlen);
	if (retval != SUCCESS) {
		fprintf (stderr, "RIPEMD128_update failed, reason %d\n", retval);
        exit (1);
    }

	retval = RIPEMD128_final (state, hashval);
	if (retval != SUCCESS) {
		fprintf (stderr, "RIPEMD128_final failed, reason %d\n", retval);
        exit (1);
    }
	free (state);
 	return retval;
}

