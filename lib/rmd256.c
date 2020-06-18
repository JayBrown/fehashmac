/* rmd256.c     RIPEMD-256 hash algorithm
 * implemented
 * hvf 11.02.07
 * hvf 15.02.2009	align with SHA3-C-API
 * disabled RIPEMD256_Print - hvf 19.04.2015
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
 *      FILE:     rmd256.h
 *
 *      CONTENTS: Header file for a sample C-implementation of the
 *                RIPEMD-256 hash-function. This function is a
 *                plug-in substitute for RIPEMD. A 256-bit hash
 *                result is obtained using RIPEMD-256.
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
/* hvf: j=0 to 15 */
#define F(x, y, z)        ((x) ^ (y) ^ (z)) 
/* hvf: j=16 to 31 */
#define G(x, y, z)        (((x) & (y)) | (~(x) & (z))) 
/* hvf: j=32 to 47 */
#define H(x, y, z)        (((x) | ~(y)) ^ (z))
/* hvf: j=48 to 63 */
#define I(x, y, z)        (((x) & (z)) | ((y) & ~(z))) 
  
/* the eight basic operations FF() through III() */
/* hvf: j=0 to 15 */
#define FF(a, b, c, d, x, s)        {\
      (a) += F((b), (c), (d)) + (x);\
      (a) = ROL((a), (s));\
   }
/* hvf: j=16 to 31 */
#define GG(a, b, c, d, x, s)        {\
      (a) += G((b), (c), (d)) + (x) + 0x5a827999UL;\
      (a) = ROL((a), (s));\
   }
/* hvf: j=32 to 47 */
#define HH(a, b, c, d, x, s)        {\
      (a) += H((b), (c), (d)) + (x) + 0x6ed9eba1UL;\
      (a) = ROL((a), (s));\
   }
/* hvf: j=48 to 63 */
#define II(a, b, c, d, x, s)        {\
      (a) += I((b), (c), (d)) + (x) + 0x8f1bbcdcUL;\
      (a) = ROL((a), (s));\
   }
/* hvf: j=48 to 63 */
#define FFF(a, b, c, d, x, s)        {\
      (a) += F((b), (c), (d)) + (x);\
      (a) = ROL((a), (s));\
   }
/* hvf: j=32 to 47 */
#define GGG(a, b, c, d, x, s)        {\
      (a) += G((b), (c), (d)) + (x) + 0x6d703ef3UL;\
      (a) = ROL((a), (s));\
   }
/* hvf: j=16 to 31 */
#define HHH(a, b, c, d, x, s)        {\
      (a) += H((b), (c), (d)) + (x) + 0x5c4dd124UL;\
      (a) = ROL((a), (s));\
   }
/* hvf: j=0 to 15 */
#define III(a, b, c, d, x, s)        {\
      (a) += I((b), (c), (d)) + (x) + 0x50a28be6UL;\
      (a) = ROL((a), (s));\
   }

/********************************************************************/

HashReturn RIPEMD256_init (hashState  *state, int hashbitlen)
{
	/* verify correct hash length	*/
	if (hashbitlen != HASH_BITLENGTH_RIPEMD256)
		return BAD_HASHBITLEN;

	/* allocate context and fill it	*/
	RIPEMD256_CTX *context = (RIPEMD256_CTX *)malloc (sizeof (RIPEMD256_CTX));
	memset (context, 0, sizeof (RIPEMD256_CTX));
	context->hashbitlen = HASH_BITLENGTH_RIPEMD256;
	context->magic = HASH_MAGIC_RIPEMD256;


	context->MDbuf[0] = 0x67452301UL;
	context->MDbuf[1] = 0xefcdab89UL;
	context->MDbuf[2] = 0x98badcfeUL;
	context->MDbuf[3] = 0x10325476UL;
	context->MDbuf[4] = 0x76543210UL;
	context->MDbuf[5] = 0xfedcba98UL;
	context->MDbuf[6] = 0x89abcdefUL;
	context->MDbuf[7] = 0x01234567UL;

	*state = (hashState *) context;
	return SUCCESS;
}

/********************************************************************/

static void RIPEMD256_transform(RIPEMD256_CTX *context)
{
   unsigned int aa = context->MDbuf[0],  bb = context->MDbuf[1],  
	cc = context->MDbuf[2],  dd = context->MDbuf[3],
	aaprime = context->MDbuf[4], bbprime = context->MDbuf[5],
	ccprime = context->MDbuf[6], ddprime = context->MDbuf[7];
	unsigned int temp;

#ifdef DEBUG
	int i;
	for (i=0; i<HASH_INPUTBUFFER_W_RIPEMD256; i++)
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
                             
III(aaprime, bbprime, ccprime, ddprime, context->m_buffer[ 5], 8);
III(ddprime, aaprime, bbprime, ccprime, context->m_buffer[14], 9);
III(ccprime, ddprime, aaprime, bbprime, context->m_buffer[ 7], 9);
III(bbprime, ccprime, ddprime, aaprime, context->m_buffer[ 0],11);
III(aaprime, bbprime, ccprime, ddprime, context->m_buffer[ 9],13);
III(ddprime, aaprime, bbprime, ccprime, context->m_buffer[ 2],15);
III(ccprime, ddprime, aaprime, bbprime, context->m_buffer[11],15);
III(bbprime, ccprime, ddprime, aaprime, context->m_buffer[ 4], 5);
III(aaprime, bbprime, ccprime, ddprime, context->m_buffer[13], 7);
III(ddprime, aaprime, bbprime, ccprime, context->m_buffer[ 6], 7);
III(ccprime, ddprime, aaprime, bbprime, context->m_buffer[15], 8);
III(bbprime, ccprime, ddprime, aaprime, context->m_buffer[ 8],11);
III(aaprime, bbprime, ccprime, ddprime, context->m_buffer[ 1],14);
III(ddprime, aaprime, bbprime, ccprime, context->m_buffer[10],14);
III(ccprime, ddprime, aaprime, bbprime, context->m_buffer[ 3],12);
III(bbprime, ccprime, ddprime, aaprime, context->m_buffer[12], 6);

temp = aa; aa = aaprime; aaprime = temp;

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

HHH(aaprime, bbprime, ccprime, ddprime, context->m_buffer[ 6], 9);
HHH(ddprime, aaprime, bbprime, ccprime, context->m_buffer[11],13);
HHH(ccprime, ddprime, aaprime, bbprime, context->m_buffer[ 3],15);
HHH(bbprime, ccprime, ddprime, aaprime, context->m_buffer[ 7], 7);
HHH(aaprime, bbprime, ccprime, ddprime, context->m_buffer[ 0],12);
HHH(ddprime, aaprime, bbprime, ccprime, context->m_buffer[13], 8);
HHH(ccprime, ddprime, aaprime, bbprime, context->m_buffer[ 5], 9);
HHH(bbprime, ccprime, ddprime, aaprime, context->m_buffer[10],11);
HHH(aaprime, bbprime, ccprime, ddprime, context->m_buffer[14], 7);
HHH(ddprime, aaprime, bbprime, ccprime, context->m_buffer[15], 7);
HHH(ccprime, ddprime, aaprime, bbprime, context->m_buffer[ 8],12);
HHH(bbprime, ccprime, ddprime, aaprime, context->m_buffer[12], 7);
HHH(aaprime, bbprime, ccprime, ddprime, context->m_buffer[ 4], 6);
HHH(ddprime, aaprime, bbprime, ccprime, context->m_buffer[ 9],15);
HHH(ccprime, ddprime, aaprime, bbprime, context->m_buffer[ 1],13);
HHH(bbprime, ccprime, ddprime, aaprime, context->m_buffer[ 2],11);

temp = bb; bb = bbprime; bbprime = temp;

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

GGG(aaprime, bbprime, ccprime, ddprime, context->m_buffer[15], 9);
GGG(ddprime, aaprime, bbprime, ccprime, context->m_buffer[ 5], 7);
GGG(ccprime, ddprime, aaprime, bbprime, context->m_buffer[ 1],15);
GGG(bbprime, ccprime, ddprime, aaprime, context->m_buffer[ 3],11);
GGG(aaprime, bbprime, ccprime, ddprime, context->m_buffer[ 7], 8);
GGG(ddprime, aaprime, bbprime, ccprime, context->m_buffer[14], 6);
GGG(ccprime, ddprime, aaprime, bbprime, context->m_buffer[ 6], 6);
GGG(bbprime, ccprime, ddprime, aaprime, context->m_buffer[ 9],14);
GGG(aaprime, bbprime, ccprime, ddprime, context->m_buffer[11],12);
GGG(ddprime, aaprime, bbprime, ccprime, context->m_buffer[ 8],13);
GGG(ccprime, ddprime, aaprime, bbprime, context->m_buffer[12], 5);
GGG(bbprime, ccprime, ddprime, aaprime, context->m_buffer[ 2],14);
GGG(aaprime, bbprime, ccprime, ddprime, context->m_buffer[10],13);
GGG(ddprime, aaprime, bbprime, ccprime, context->m_buffer[ 0],13);
GGG(ccprime, ddprime, aaprime, bbprime, context->m_buffer[ 4], 7);
GGG(bbprime, ccprime, ddprime, aaprime, context->m_buffer[13], 5);

temp = cc; cc = ccprime; ccprime = temp;

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

FFF(aaprime, bbprime, ccprime, ddprime, context->m_buffer[ 8],15);
FFF(ddprime, aaprime, bbprime, ccprime, context->m_buffer[ 6], 5);
FFF(ccprime, ddprime, aaprime, bbprime, context->m_buffer[ 4], 8);
FFF(bbprime, ccprime, ddprime, aaprime, context->m_buffer[ 1],11);
FFF(aaprime, bbprime, ccprime, ddprime, context->m_buffer[ 3],14);
FFF(ddprime, aaprime, bbprime, ccprime, context->m_buffer[11],14);
FFF(ccprime, ddprime, aaprime, bbprime, context->m_buffer[15], 6);
FFF(bbprime, ccprime, ddprime, aaprime, context->m_buffer[ 0],14);
FFF(aaprime, bbprime, ccprime, ddprime, context->m_buffer[ 5], 6);
FFF(ddprime, aaprime, bbprime, ccprime, context->m_buffer[12], 9);
FFF(ccprime, ddprime, aaprime, bbprime, context->m_buffer[ 2],12);
FFF(bbprime, ccprime, ddprime, aaprime, context->m_buffer[13], 9);
FFF(aaprime, bbprime, ccprime, ddprime, context->m_buffer[ 9],12);
FFF(ddprime, aaprime, bbprime, ccprime, context->m_buffer[ 7], 5);
FFF(ccprime, ddprime, aaprime, bbprime, context->m_buffer[10],15);
FFF(bbprime, ccprime, ddprime, aaprime, context->m_buffer[14], 8);

temp = dd; dd = ddprime; ddprime = temp;

	context->MDbuf[0] += aa;
	context->MDbuf[1] += bb;
	context->MDbuf[2] += cc;
	context->MDbuf[3] += dd;
	context->MDbuf[4] += aaprime;
	context->MDbuf[5] += bbprime;
	context->MDbuf[6] += ccprime;
	context->MDbuf[7] += ddprime;
	

    context->count = 0;
    memset (context->m_buffer, 0, sizeof (context->m_buffer));

   return;
}

/********************************************************************/
void    RIPEMD256_update_old (RIPEMD256_CTX *context, const unsigned char *buffer,
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
            RIPEMD256_transform (context);
    }
}

void RIPEMD256_final_old (RIPEMD256_CTX *context)
{   /* does padding of last block, little endian    */
    int i;
    unsigned int c = context->count;
    context->m_buffer[c>>2] |= 0x80<<(((c&0x03)<<3));
    if (c > 55)
        RIPEMD256_transform (context);
    context->m_buffer[14] = (unsigned int) context->total_count;
    context->m_buffer[15] = (unsigned int) (context->total_count >> 32);
    RIPEMD256_transform (context);

    for (i=0; i<HASH_LENGTH_RIPEMD256; i++)
        context->out[i] = context->MDbuf[i>>2]>>(((i&0x03)<<3));

    return;
}

HashReturn 	RIPEMD256_update (
	hashState state, 			/* previously initialized context */
	const BitSequence *buffer, 	/* bit buffer, first bit is MSB in [0] */
	DataLength databitlen)		/* number of bits to process from buffer */
{	
	/* can be called once or many times */
	/* verify correct hashbitlen and magic	*/

	RIPEMD256_CTX *context = (RIPEMD256_CTX *) state;
	if (context->hashbitlen != HASH_BITLENGTH_RIPEMD256)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_RIPEMD256)
		return BAD_ALGORITHM;

	/* check for byte alignment */
	if ((databitlen & 0x7)) {
		return FAIL;
	}

	RIPEMD256_update_old (context, buffer, (unsigned int)(databitlen>>3));
	return SUCCESS;
}

HashReturn	RIPEMD256_final (hashState state, BitSequence *hashval)
{	/*	does padding of last block	*/
	RIPEMD256_CTX *context = (RIPEMD256_CTX *) state;
	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_RIPEMD256)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_RIPEMD256)
		return BAD_ALGORITHM;

	RIPEMD256_final_old (context);

	if (hashval)
		memcpy (hashval, context->out, HASH_LENGTH_RIPEMD256);
	return SUCCESS;
}

/* RIPEMD256 utility routines
 *
 * hvf 23.1.2000
 * hvf 13.2.01
 * hvf 10.8.01
 * hvf 15.02.2009
 */

/* Digests a file and prints the result.
 */

HashReturn RIPEMD256_File (hashState state, FILE *in)
{
	RIPEMD256_CTX *context = (RIPEMD256_CTX *) state;
	int len;
	unsigned char buffer[BUFFERSIZE];
	HashReturn retval;

	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_RIPEMD256)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_RIPEMD256)
		return BAD_ALGORITHM;

	while ((len = fread (buffer, 1, BUFFERSIZE, in))) {
		retval = RIPEMD256_update (context, buffer, (DataLength)len << 3);
		if (retval != SUCCESS) return retval;
	}
	retval = RIPEMD256_final (context, NULL);

	fclose (in);
	return retval;
}


HashReturn RIPEMD256_HashToByte (hashState state, BYTE *out) 
{
	RIPEMD256_CTX *context = (RIPEMD256_CTX *) state;

	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_RIPEMD256)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_RIPEMD256)
		return BAD_ALGORITHM;

	memcpy (out, context->out, HASH_LENGTH_RIPEMD256);
	return SUCCESS;
}

/* all-in-one hash function as required by SHA3-C-API */

HashReturn RIPEMD256_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval) 
{
	hashState	state;
	HashReturn	retval;
	
	retval = RIPEMD256_init (&state, HASH_BITLENGTH_RIPEMD256);
	if (retval != SUCCESS) {
		fprintf (stderr, "RIPEMD256_init failed, reason %d, hash length %d\n",
                 retval, HASH_BITLENGTH_RIPEMD256);
        exit (1);
    }

	retval = RIPEMD256_update (state, data, databitlen);
	if (retval != SUCCESS) {
		fprintf (stderr, "RIPEMD256_update failed, reason %d\n", retval);
        exit (1);
    }

	retval = RIPEMD256_final (state, hashval);
	if (retval != SUCCESS) {
		fprintf (stderr, "RIPEMD256_final failed, reason %d\n", retval);
        exit (1);
    }
	free (state);
 	return retval;
}

