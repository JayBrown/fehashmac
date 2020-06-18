/* rmd160.c		RIPEMD-160 hash algorithm
 * integrated into fehashmac
 * hvf 13.08.01
 * hvf 15.02.2009	align with SHA3-C-API
 * disabled RIPEMD160_Print - hvf 19.04.2015
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
 *      FILE:     rmd160.h
 *
 *      CONTENTS: Header file for a sample C-implementation of the
 *                RIPEMD-160 hash-function. 
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
#define BYTES_TO_DWORD(strptr)                    \
            (((dword) *((strptr)+3) << 24) | \
             ((dword) *((strptr)+2) << 16) | \
             ((dword) *((strptr)+1) <<  8) | \
             ((dword) *(strptr)))

/* ROL(x, n) cyclically rotates x over n bits to the left */
/* x must be of an unsigned 32 bits type and 0 <= n < 32. */
#define ROL(x, n)        (((x) << (n)) | ((x) >> (32-(n))))

/* the five basic functions F(), G() and H() */
#define F(x, y, z)        ((x) ^ (y) ^ (z)) 
#define G(x, y, z)        (((x) & (y)) | (~(x) & (z))) 
#define H(x, y, z)        (((x) | ~(y)) ^ (z))
#define I(x, y, z)        (((x) & (z)) | ((y) & ~(z))) 
#define J(x, y, z)        ((x) ^ ((y) | ~(z)))
  
/* the ten basic operations FF() through III() */
#define FF(a, b, c, d, e, x, s)        {\
      (a) += F((b), (c), (d)) + (x);\
      (a) = ROL((a), (s)) + (e);\
      (c) = ROL((c), 10);\
   }
#define GG(a, b, c, d, e, x, s)        {\
      (a) += G((b), (c), (d)) + (x) + 0x5a827999UL;\
      (a) = ROL((a), (s)) + (e);\
      (c) = ROL((c), 10);\
   }
#define HH(a, b, c, d, e, x, s)        {\
      (a) += H((b), (c), (d)) + (x) + 0x6ed9eba1UL;\
      (a) = ROL((a), (s)) + (e);\
      (c) = ROL((c), 10);\
   }
#define II(a, b, c, d, e, x, s)        {\
      (a) += I((b), (c), (d)) + (x) + 0x8f1bbcdcUL;\
      (a) = ROL((a), (s)) + (e);\
      (c) = ROL((c), 10);\
   }
#define JJ(a, b, c, d, e, x, s)        {\
      (a) += J((b), (c), (d)) + (x) + 0xa953fd4eUL;\
      (a) = ROL((a), (s)) + (e);\
      (c) = ROL((c), 10);\
   }
#define FFF(a, b, c, d, e, x, s)        {\
      (a) += F((b), (c), (d)) + (x);\
      (a) = ROL((a), (s)) + (e);\
      (c) = ROL((c), 10);\
   }
#define GGG(a, b, c, d, e, x, s)        {\
      (a) += G((b), (c), (d)) + (x) + 0x7a6d76e9UL;\
      (a) = ROL((a), (s)) + (e);\
      (c) = ROL((c), 10);\
   }
#define HHH(a, b, c, d, e, x, s)        {\
      (a) += H((b), (c), (d)) + (x) + 0x6d703ef3UL;\
      (a) = ROL((a), (s)) + (e);\
      (c) = ROL((c), 10);\
   }
#define III(a, b, c, d, e, x, s)        {\
      (a) += I((b), (c), (d)) + (x) + 0x5c4dd124UL;\
      (a) = ROL((a), (s)) + (e);\
      (c) = ROL((c), 10);\
   }
#define JJJ(a, b, c, d, e, x, s)        {\
      (a) += J((b), (c), (d)) + (x) + 0x50a28be6UL;\
      (a) = ROL((a), (s)) + (e);\
      (c) = ROL((c), 10);\
   }



/********************************************************************/

HashReturn RIPEMD160_init (hashState  *state, int hashbitlen)
{
	/* verify correct hash length	*/
	if (hashbitlen != HASH_BITLENGTH_RIPEMD160)
		return BAD_HASHBITLEN;

	/* allocate context and fill it	*/
	RIPEMD160_CTX *context = (RIPEMD160_CTX *)malloc (sizeof (RIPEMD160_CTX));
	memset (context, 0, sizeof (RIPEMD160_CTX));
	context->hashbitlen = HASH_BITLENGTH_RIPEMD160;
	context->magic = HASH_MAGIC_RIPEMD160;

   	context->MDbuf[0] = 0x67452301UL;
   	context->MDbuf[1] = 0xefcdab89UL;
   	context->MDbuf[2] = 0x98badcfeUL;
   	context->MDbuf[3] = 0x10325476UL;
   	context->MDbuf[4] = 0xc3d2e1f0UL;

	*state = (hashState *) context;
	return SUCCESS;
}

/********************************************************************/

static void RIPEMD160_transform(RIPEMD160_CTX *context)
{
	unsigned int aa = context->MDbuf[0],  bb = context->MDbuf[1],  
		cc = context->MDbuf[2], dd = context->MDbuf[3],  ee = context->MDbuf[4];
	unsigned int aaa = context->MDbuf[0], bbb = context->MDbuf[1], 
		ccc = context->MDbuf[2], ddd = context->MDbuf[3], 
		eee = context->MDbuf[4];

#ifdef DEBUG
	int i;
	for (i=0; i<HASH_INPUTBUFFER_W_RIPEMD160; i++)
		printf ("W[%2d] = %8.8x\n", i, context->m_buffer[i]);
#endif

   /* round 1 */
   FF(aa, bb, cc, dd, ee, context->m_buffer[ 0], 11);
   FF(ee, aa, bb, cc, dd, context->m_buffer[ 1], 14);
   FF(dd, ee, aa, bb, cc, context->m_buffer[ 2], 15);
   FF(cc, dd, ee, aa, bb, context->m_buffer[ 3], 12);
   FF(bb, cc, dd, ee, aa, context->m_buffer[ 4],  5);
   FF(aa, bb, cc, dd, ee, context->m_buffer[ 5],  8);
   FF(ee, aa, bb, cc, dd, context->m_buffer[ 6],  7);
   FF(dd, ee, aa, bb, cc, context->m_buffer[ 7],  9);
   FF(cc, dd, ee, aa, bb, context->m_buffer[ 8], 11);
   FF(bb, cc, dd, ee, aa, context->m_buffer[ 9], 13);
   FF(aa, bb, cc, dd, ee, context->m_buffer[10], 14);
   FF(ee, aa, bb, cc, dd, context->m_buffer[11], 15);
   FF(dd, ee, aa, bb, cc, context->m_buffer[12],  6);
   FF(cc, dd, ee, aa, bb, context->m_buffer[13],  7);
   FF(bb, cc, dd, ee, aa, context->m_buffer[14],  9);
   FF(aa, bb, cc, dd, ee, context->m_buffer[15],  8);
                             
   /* round 2 */
   GG(ee, aa, bb, cc, dd, context->m_buffer[ 7],  7);
   GG(dd, ee, aa, bb, cc, context->m_buffer[ 4],  6);
   GG(cc, dd, ee, aa, bb, context->m_buffer[13],  8);
   GG(bb, cc, dd, ee, aa, context->m_buffer[ 1], 13);
   GG(aa, bb, cc, dd, ee, context->m_buffer[10], 11);
   GG(ee, aa, bb, cc, dd, context->m_buffer[ 6],  9);
   GG(dd, ee, aa, bb, cc, context->m_buffer[15],  7);
   GG(cc, dd, ee, aa, bb, context->m_buffer[ 3], 15);
   GG(bb, cc, dd, ee, aa, context->m_buffer[12],  7);
   GG(aa, bb, cc, dd, ee, context->m_buffer[ 0], 12);
   GG(ee, aa, bb, cc, dd, context->m_buffer[ 9], 15);
   GG(dd, ee, aa, bb, cc, context->m_buffer[ 5],  9);
   GG(cc, dd, ee, aa, bb, context->m_buffer[ 2], 11);
   GG(bb, cc, dd, ee, aa, context->m_buffer[14],  7);
   GG(aa, bb, cc, dd, ee, context->m_buffer[11], 13);
   GG(ee, aa, bb, cc, dd, context->m_buffer[ 8], 12);

   /* round 3 */
   HH(dd, ee, aa, bb, cc, context->m_buffer[ 3], 11);
   HH(cc, dd, ee, aa, bb, context->m_buffer[10], 13);
   HH(bb, cc, dd, ee, aa, context->m_buffer[14],  6);
   HH(aa, bb, cc, dd, ee, context->m_buffer[ 4],  7);
   HH(ee, aa, bb, cc, dd, context->m_buffer[ 9], 14);
   HH(dd, ee, aa, bb, cc, context->m_buffer[15],  9);
   HH(cc, dd, ee, aa, bb, context->m_buffer[ 8], 13);
   HH(bb, cc, dd, ee, aa, context->m_buffer[ 1], 15);
   HH(aa, bb, cc, dd, ee, context->m_buffer[ 2], 14);
   HH(ee, aa, bb, cc, dd, context->m_buffer[ 7],  8);
   HH(dd, ee, aa, bb, cc, context->m_buffer[ 0], 13);
   HH(cc, dd, ee, aa, bb, context->m_buffer[ 6],  6);
   HH(bb, cc, dd, ee, aa, context->m_buffer[13],  5);
   HH(aa, bb, cc, dd, ee, context->m_buffer[11], 12);
   HH(ee, aa, bb, cc, dd, context->m_buffer[ 5],  7);
   HH(dd, ee, aa, bb, cc, context->m_buffer[12],  5);

   /* round 4 */
   II(cc, dd, ee, aa, bb, context->m_buffer[ 1], 11);
   II(bb, cc, dd, ee, aa, context->m_buffer[ 9], 12);
   II(aa, bb, cc, dd, ee, context->m_buffer[11], 14);
   II(ee, aa, bb, cc, dd, context->m_buffer[10], 15);
   II(dd, ee, aa, bb, cc, context->m_buffer[ 0], 14);
   II(cc, dd, ee, aa, bb, context->m_buffer[ 8], 15);
   II(bb, cc, dd, ee, aa, context->m_buffer[12],  9);
   II(aa, bb, cc, dd, ee, context->m_buffer[ 4],  8);
   II(ee, aa, bb, cc, dd, context->m_buffer[13],  9);
   II(dd, ee, aa, bb, cc, context->m_buffer[ 3], 14);
   II(cc, dd, ee, aa, bb, context->m_buffer[ 7],  5);
   II(bb, cc, dd, ee, aa, context->m_buffer[15],  6);
   II(aa, bb, cc, dd, ee, context->m_buffer[14],  8);
   II(ee, aa, bb, cc, dd, context->m_buffer[ 5],  6);
   II(dd, ee, aa, bb, cc, context->m_buffer[ 6],  5);
   II(cc, dd, ee, aa, bb, context->m_buffer[ 2], 12);

   /* round 5 */
   JJ(bb, cc, dd, ee, aa, context->m_buffer[ 4],  9);
   JJ(aa, bb, cc, dd, ee, context->m_buffer[ 0], 15);
   JJ(ee, aa, bb, cc, dd, context->m_buffer[ 5],  5);
   JJ(dd, ee, aa, bb, cc, context->m_buffer[ 9], 11);
   JJ(cc, dd, ee, aa, bb, context->m_buffer[ 7],  6);
   JJ(bb, cc, dd, ee, aa, context->m_buffer[12],  8);
   JJ(aa, bb, cc, dd, ee, context->m_buffer[ 2], 13);
   JJ(ee, aa, bb, cc, dd, context->m_buffer[10], 12);
   JJ(dd, ee, aa, bb, cc, context->m_buffer[14],  5);
   JJ(cc, dd, ee, aa, bb, context->m_buffer[ 1], 12);
   JJ(bb, cc, dd, ee, aa, context->m_buffer[ 3], 13);
   JJ(aa, bb, cc, dd, ee, context->m_buffer[ 8], 14);
   JJ(ee, aa, bb, cc, dd, context->m_buffer[11], 11);
   JJ(dd, ee, aa, bb, cc, context->m_buffer[ 6],  8);
   JJ(cc, dd, ee, aa, bb, context->m_buffer[15],  5);
   JJ(bb, cc, dd, ee, aa, context->m_buffer[13],  6);

   /* parallel round 1 */
   JJJ(aaa, bbb, ccc, ddd, eee, context->m_buffer[ 5],  8);
   JJJ(eee, aaa, bbb, ccc, ddd, context->m_buffer[14],  9);
   JJJ(ddd, eee, aaa, bbb, ccc, context->m_buffer[ 7],  9);
   JJJ(ccc, ddd, eee, aaa, bbb, context->m_buffer[ 0], 11);
   JJJ(bbb, ccc, ddd, eee, aaa, context->m_buffer[ 9], 13);
   JJJ(aaa, bbb, ccc, ddd, eee, context->m_buffer[ 2], 15);
   JJJ(eee, aaa, bbb, ccc, ddd, context->m_buffer[11], 15);
   JJJ(ddd, eee, aaa, bbb, ccc, context->m_buffer[ 4],  5);
   JJJ(ccc, ddd, eee, aaa, bbb, context->m_buffer[13],  7);
   JJJ(bbb, ccc, ddd, eee, aaa, context->m_buffer[ 6],  7);
   JJJ(aaa, bbb, ccc, ddd, eee, context->m_buffer[15],  8);
   JJJ(eee, aaa, bbb, ccc, ddd, context->m_buffer[ 8], 11);
   JJJ(ddd, eee, aaa, bbb, ccc, context->m_buffer[ 1], 14);
   JJJ(ccc, ddd, eee, aaa, bbb, context->m_buffer[10], 14);
   JJJ(bbb, ccc, ddd, eee, aaa, context->m_buffer[ 3], 12);
   JJJ(aaa, bbb, ccc, ddd, eee, context->m_buffer[12],  6);

   /* parallel round 2 */
   III(eee, aaa, bbb, ccc, ddd, context->m_buffer[ 6],  9); 
   III(ddd, eee, aaa, bbb, ccc, context->m_buffer[11], 13);
   III(ccc, ddd, eee, aaa, bbb, context->m_buffer[ 3], 15);
   III(bbb, ccc, ddd, eee, aaa, context->m_buffer[ 7],  7);
   III(aaa, bbb, ccc, ddd, eee, context->m_buffer[ 0], 12);
   III(eee, aaa, bbb, ccc, ddd, context->m_buffer[13],  8);
   III(ddd, eee, aaa, bbb, ccc, context->m_buffer[ 5],  9);
   III(ccc, ddd, eee, aaa, bbb, context->m_buffer[10], 11);
   III(bbb, ccc, ddd, eee, aaa, context->m_buffer[14],  7);
   III(aaa, bbb, ccc, ddd, eee, context->m_buffer[15],  7);
   III(eee, aaa, bbb, ccc, ddd, context->m_buffer[ 8], 12);
   III(ddd, eee, aaa, bbb, ccc, context->m_buffer[12],  7);
   III(ccc, ddd, eee, aaa, bbb, context->m_buffer[ 4],  6);
   III(bbb, ccc, ddd, eee, aaa, context->m_buffer[ 9], 15);
   III(aaa, bbb, ccc, ddd, eee, context->m_buffer[ 1], 13);
   III(eee, aaa, bbb, ccc, ddd, context->m_buffer[ 2], 11);

   /* parallel round 3 */
   HHH(ddd, eee, aaa, bbb, ccc, context->m_buffer[15],  9);
   HHH(ccc, ddd, eee, aaa, bbb, context->m_buffer[ 5],  7);
   HHH(bbb, ccc, ddd, eee, aaa, context->m_buffer[ 1], 15);
   HHH(aaa, bbb, ccc, ddd, eee, context->m_buffer[ 3], 11);
   HHH(eee, aaa, bbb, ccc, ddd, context->m_buffer[ 7],  8);
   HHH(ddd, eee, aaa, bbb, ccc, context->m_buffer[14],  6);
   HHH(ccc, ddd, eee, aaa, bbb, context->m_buffer[ 6],  6);
   HHH(bbb, ccc, ddd, eee, aaa, context->m_buffer[ 9], 14);
   HHH(aaa, bbb, ccc, ddd, eee, context->m_buffer[11], 12);
   HHH(eee, aaa, bbb, ccc, ddd, context->m_buffer[ 8], 13);
   HHH(ddd, eee, aaa, bbb, ccc, context->m_buffer[12],  5);
   HHH(ccc, ddd, eee, aaa, bbb, context->m_buffer[ 2], 14);
   HHH(bbb, ccc, ddd, eee, aaa, context->m_buffer[10], 13);
   HHH(aaa, bbb, ccc, ddd, eee, context->m_buffer[ 0], 13);
   HHH(eee, aaa, bbb, ccc, ddd, context->m_buffer[ 4],  7);
   HHH(ddd, eee, aaa, bbb, ccc, context->m_buffer[13],  5);

   /* parallel round 4 */   
   GGG(ccc, ddd, eee, aaa, bbb, context->m_buffer[ 8], 15);
   GGG(bbb, ccc, ddd, eee, aaa, context->m_buffer[ 6],  5);
   GGG(aaa, bbb, ccc, ddd, eee, context->m_buffer[ 4],  8);
   GGG(eee, aaa, bbb, ccc, ddd, context->m_buffer[ 1], 11);
   GGG(ddd, eee, aaa, bbb, ccc, context->m_buffer[ 3], 14);
   GGG(ccc, ddd, eee, aaa, bbb, context->m_buffer[11], 14);
   GGG(bbb, ccc, ddd, eee, aaa, context->m_buffer[15],  6);
   GGG(aaa, bbb, ccc, ddd, eee, context->m_buffer[ 0], 14);
   GGG(eee, aaa, bbb, ccc, ddd, context->m_buffer[ 5],  6);
   GGG(ddd, eee, aaa, bbb, ccc, context->m_buffer[12],  9);
   GGG(ccc, ddd, eee, aaa, bbb, context->m_buffer[ 2], 12);
   GGG(bbb, ccc, ddd, eee, aaa, context->m_buffer[13],  9);
   GGG(aaa, bbb, ccc, ddd, eee, context->m_buffer[ 9], 12);
   GGG(eee, aaa, bbb, ccc, ddd, context->m_buffer[ 7],  5);
   GGG(ddd, eee, aaa, bbb, ccc, context->m_buffer[10], 15);
   GGG(ccc, ddd, eee, aaa, bbb, context->m_buffer[14],  8);

   /* parallel round 5 */
   FFF(bbb, ccc, ddd, eee, aaa, context->m_buffer[12] ,  8);
   FFF(aaa, bbb, ccc, ddd, eee, context->m_buffer[15] ,  5);
   FFF(eee, aaa, bbb, ccc, ddd, context->m_buffer[10] , 12);
   FFF(ddd, eee, aaa, bbb, ccc, context->m_buffer[ 4] ,  9);
   FFF(ccc, ddd, eee, aaa, bbb, context->m_buffer[ 1] , 12);
   FFF(bbb, ccc, ddd, eee, aaa, context->m_buffer[ 5] ,  5);
   FFF(aaa, bbb, ccc, ddd, eee, context->m_buffer[ 8] , 14);
   FFF(eee, aaa, bbb, ccc, ddd, context->m_buffer[ 7] ,  6);
   FFF(ddd, eee, aaa, bbb, ccc, context->m_buffer[ 6] ,  8);
   FFF(ccc, ddd, eee, aaa, bbb, context->m_buffer[ 2] , 13);
   FFF(bbb, ccc, ddd, eee, aaa, context->m_buffer[13] ,  6);
   FFF(aaa, bbb, ccc, ddd, eee, context->m_buffer[14] ,  5);
   FFF(eee, aaa, bbb, ccc, ddd, context->m_buffer[ 0] , 15);
   FFF(ddd, eee, aaa, bbb, ccc, context->m_buffer[ 3] , 13);
   FFF(ccc, ddd, eee, aaa, bbb, context->m_buffer[ 9] , 11);
   FFF(bbb, ccc, ddd, eee, aaa, context->m_buffer[11] , 11);

   /* combine results */
   ddd += cc + context->MDbuf[1];               /* final result for MDbuf[0] */
   context->MDbuf[1] = context->MDbuf[2] + dd + eee;
   context->MDbuf[2] = context->MDbuf[3] + ee + aaa;
   context->MDbuf[3] = context->MDbuf[4] + aa + bbb;
   context->MDbuf[4] = context->MDbuf[0] + bb + ccc;
   context->MDbuf[0] = ddd;

	context->count = 0;
	memset (context->m_buffer, 0, sizeof (context->m_buffer));

   return;
}


void    RIPEMD160_update_old (RIPEMD160_CTX *context, const unsigned char *buffer, 
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
            RIPEMD160_transform (context);
    }
}

void RIPEMD160_final_old (RIPEMD160_CTX *context)
{	/* does padding of last block, little endian	*/
	int i;
	unsigned int c = context->count;
    context->m_buffer[c>>2] |= 0x80<<(((c&0x03)<<3));
    if (c > 55)
        RIPEMD160_transform (context);
    context->m_buffer[14] = (unsigned int) context->total_count;
    context->m_buffer[15] = (unsigned int) (context->total_count >> 32);
	RIPEMD160_transform (context);

	for (i=0; i<HASH_LENGTH_RIPEMD160; i++)
		context->out[i] = context->MDbuf[i>>2]>>(((i&0x03)<<3));

	return;
}

HashReturn 	RIPEMD160_update (
	hashState state, 			/* previously initialized context */
	const BitSequence *buffer, 	/* bit buffer, first bit is MSB in [0] */
	DataLength databitlen)		/* number of bits to process from buffer */
{	
	/* can be called once or many times */
	/* verify correct hashbitlen and magic	*/

	RIPEMD160_CTX *context = (RIPEMD160_CTX *) state;
	if (context->hashbitlen != HASH_BITLENGTH_RIPEMD160)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_RIPEMD160)
		return BAD_ALGORITHM;

	/* check for byte alignment */
	if ((databitlen & 0x7)) {
		return FAIL;
	}

	RIPEMD160_update_old (context, buffer, (unsigned int)(databitlen>>3));
	return SUCCESS;
}

HashReturn	RIPEMD160_final (hashState state, BitSequence *hashval)
{	/*	does padding of last block	*/
	RIPEMD160_CTX *context = (RIPEMD160_CTX *) state;
	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_RIPEMD160)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_RIPEMD160)
		return BAD_ALGORITHM;

	RIPEMD160_final_old (context);

	if (hashval)
		memcpy (hashval, context->out, HASH_LENGTH_RIPEMD160);
	return SUCCESS;
}

/* RIPEMD160 utility routines
 *
 * hvf 23.1.2000
 * hvf 13.2.01
 * hvf 10.8.01
 * hvf 15.02.2009
 */

/* Digests a file and prints the result.
 */

HashReturn RIPEMD160_File (hashState state, FILE *in)
{
	RIPEMD160_CTX *context = (RIPEMD160_CTX *) state;
	int len;
	unsigned char buffer[BUFFERSIZE];
	HashReturn retval;

	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_RIPEMD160)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_RIPEMD160)
		return BAD_ALGORITHM;

	while ((len = fread (buffer, 1, BUFFERSIZE, in))) {
		retval = RIPEMD160_update (context, buffer, (DataLength)len << 3);
		if (retval != SUCCESS) return retval;
	}
	retval = RIPEMD160_final (context, NULL);

	fclose (in);
	return retval;
}


HashReturn RIPEMD160_HashToByte (hashState state, BYTE *out) 
{
	RIPEMD160_CTX *context = (RIPEMD160_CTX *) state;

	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_RIPEMD160)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_RIPEMD160)
		return BAD_ALGORITHM;

	memcpy (out, context->out, HASH_LENGTH_RIPEMD160);
	return SUCCESS;
}

/* all-in-one hash function as required by SHA3-C-API */

HashReturn RIPEMD160_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval) 
{
	hashState	state;
	HashReturn	retval;
	
	retval = RIPEMD160_init (&state, HASH_BITLENGTH_RIPEMD160);
	if (retval != SUCCESS) {
		fprintf (stderr, "RIPEMD160_init failed, reason %d, hash length %d\n",
                 retval, HASH_BITLENGTH_RIPEMD160);
        exit (1);
    }

	retval = RIPEMD160_update (state, data, databitlen);
	if (retval != SUCCESS) {
		fprintf (stderr, "RIPEMD160_update failed, reason %d\n", retval);
        exit (1);
    }

	retval = RIPEMD160_final (state, hashval);
	if (retval != SUCCESS) {
		fprintf (stderr, "RIPEMD160_final failed, reason %d\n", retval);
        exit (1);
    }
	free (state);
 	return retval;
}

