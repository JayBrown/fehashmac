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

// tiger2 implementation
// streamlined a la MD5
// feh 10.11.2008
// hvf 09.02.2009 aligned with SHA3-C-API
// * disabled TIGER_Print - hvf 19.04.2015
//

#include "tiger.h"
#include <stdio.h>

/* Big endian:                                         */
#if !(defined(__alpha)||defined(__i386__)||defined(__x86_64)||defined(__vax__))
#define BIG_ENDIAN
#endif

/* The following macro denotes that an optimization    */
/* for Alpha is required. It is used only for          */
/* optimization of time. Otherwise it does nothing.    */
#ifdef __alpha
#define OPTIMIZE_FOR_ALPHA
#endif

/* NOTE that this code is NOT FULLY OPTIMIZED for any  */
/* machine. Assembly code might be much faster on some */
/* machines, especially if the code is compiled with   */
/* gcc.                                                */

/* The number of passes of the hash function.          */
/* Three passes are recommended.                       */
/* Use four passes when you need extra security.       */
/* Must be at least three.                             */
#define PASSES 3

extern uint64 table[4*256];

#define t1 (TIGER_Table)
#define t2 (TIGER_Table+256)
#define t3 (TIGER_Table+256*2)
#define t4 (TIGER_Table+256*3)

#define save_abc \
      aa = a; \
      bb = b; \
      cc = c;

#ifdef OPTIMIZE_FOR_ALPHA
/* This is the official definition of round */
#define round(a,b,c,x,mul) \
      c ^= x; \
      a -= t1[((c)>>(0*8))&0xFF] ^ t2[((c)>>(2*8))&0xFF] ^ \
	   t3[((c)>>(4*8))&0xFF] ^ t4[((c)>>(6*8))&0xFF] ; \
      b += t4[((c)>>(1*8))&0xFF] ^ t3[((c)>>(3*8))&0xFF] ^ \
	   t2[((c)>>(5*8))&0xFF] ^ t1[((c)>>(7*8))&0xFF] ; \
      b *= mul;
#else
/* This code works faster when compiled on 32-bit machines */
/* (but works slower on Alpha) */
#define round(a,b,c,x,mul) \
      c ^= x; \
      a -= t1[(BYTE)(c)] ^ \
           t2[(BYTE)(((uint32)(c))>>(2*8))] ^ \
	   t3[(BYTE)((c)>>(4*8))] ^ \
           t4[(BYTE)(((uint32)((c)>>(4*8)))>>(2*8))] ; \
      b += t4[(BYTE)(((uint32)(c))>>(1*8))] ^ \
           t3[(BYTE)(((uint32)(c))>>(3*8))] ^ \
	   t2[(BYTE)(((uint32)((c)>>(4*8)))>>(1*8))] ^ \
           t1[(BYTE)(((uint32)((c)>>(4*8)))>>(3*8))]; \
      b *= mul;
#endif

#define pass(a,b,c,mul) \
      round(a,b,c,x0,mul) \
      round(b,c,a,x1,mul) \
      round(c,a,b,x2,mul) \
      round(a,b,c,x3,mul) \
      round(b,c,a,x4,mul) \
      round(c,a,b,x5,mul) \
      round(a,b,c,x6,mul) \
      round(b,c,a,x7,mul)

#define key_schedule \
      x0 -= x7 ^ 0xA5A5A5A5A5A5A5A5LL; \
      x1 ^= x0; \
      x2 += x1; \
      x3 -= x2 ^ ((~x1)<<19); \
      x4 ^= x3; \
      x5 += x4; \
      x6 -= x5 ^ ((~x4)>>23); \
      x7 ^= x6; \
      x0 += x7; \
      x1 -= x0 ^ ((~x7)<<19); \
      x2 ^= x1; \
      x3 += x2; \
      x4 -= x3 ^ ((~x2)>>23); \
      x5 ^= x4; \
      x6 += x5; \
      x7 -= x6 ^ 0x0123456789ABCDEFLL;

#define feedforward \
      a ^= aa; \
      b -= bb; \
      c += cc;

#ifdef OPTIMIZE_FOR_ALPHA
/* The loop is unrolled: works better on Alpha */
#define compress \
      save_abc \
      pass(a,b,c,5) \
      key_schedule \
      pass(c,a,b,7) \
      key_schedule \
      pass(b,c,a,9) \
      for(pass_no=3; pass_no<PASSES; pass_no++) { \
        key_schedule \
	pass(a,b,c,9) \
	tmpa=a; a=c; c=b; b=tmpa;} \
      feedforward
#else
/* loop: works better on PC and Sun (smaller cache?) */
#define compress \
      save_abc \
      for(pass_no=0; pass_no<PASSES; pass_no++) { \
        if(pass_no != 0) {key_schedule} \
	pass(a,b,c,(pass_no==0?5:pass_no==1?7:9)); \
	tmpa=a; a=c; c=b; b=tmpa;} \
      feedforward
#endif

// MD5 padding is with 0x80, TIGER padding is with 0x01
static BYTE PADDING[64] = {
  0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

void TIGER_compress (uint64 *xarr, uint64 *state)
{
	register uint64 a, b, c, tmpa; 
	uint64 aa, bb, cc; 
	register uint64 x0, x1, x2, x3, x4, x5, x6, x7; 
	//register int i; 
	int pass_no; 
	
	a = state[0]; 
	b = state[1]; 
	c = state[2]; 
	
	x0=xarr[0]; x1=xarr[1]; x2=xarr[2]; x3=xarr[3]; 
	x4=xarr[4]; x5=xarr[5]; x6=xarr[6]; x7=xarr[7]; 
	
	compress; 
	
	state[0] = a; 
	state[1] = b; 
	state[2] = c; 
}

void TIGER_transform (TIGER_CTX *context)
{
	uint64	temp[8];
	int i, j;
	memset ((void *) temp, 0, sizeof (temp));
	for (i=0, j=0; i<64; i+=8, j++) {
		temp[j] = context->buffer[i];
		temp[j] |= (uint64) context->buffer[i+1] << 8;
		temp[j] |= (uint64) context->buffer[i+2] << 16;
		temp[j] |= (uint64) context->buffer[i+3] << 24;
		temp[j] |= (uint64) context->buffer[i+4] << 32;
		temp[j] |= (uint64) context->buffer[i+5] << 40;
		temp[j] |= (uint64) context->buffer[i+6] << 48;
		temp[j] |= (uint64) context->buffer[i+7] << 56;
	}
	TIGER_compress (temp, context->state);
	memset (context->buffer, 0, 64);	// clear buffer
}

HashReturn TIGER_init (hashState  *state, int hashbitlen)
{
	/* verify correct hash length	*/
	if (hashbitlen != HASH_BITLENGTH_TIGER)
		return BAD_HASHBITLEN;

	/* allocate context and fill it	*/
	TIGER_CTX *context = (TIGER_CTX *)malloc (sizeof (TIGER_CTX));
	memset (context, 0, sizeof (TIGER_CTX));
	context->hashbitlen = HASH_BITLENGTH_TIGER;
	context->magic = HASH_MAGIC_TIGER;

    /* Load magic initialization constants.
    */
	context->state[0]=0x0123456789ABCDEFLL;
	context->state[1]=0xFEDCBA9876543210LL;
	context->state[2]=0xF096A5B4C3B2E187LL;
	
	*state = (hashState *) context;
	return SUCCESS;
}

/* Tiger block update operation. Continues a Tiger message-digest
  operation, processing another message block, and updating the
  context.
 */
void TIGER_update_old (TIGER_CTX *context, const BYTE *input, unsigned int inputLen)
{
    unsigned int i = 0, index, partLen;

    /* Compute number of bytes mod 64 */
	index = context->count % 64;

	// update count
	context->count += inputLen;

	partLen = 64 - index;
	if (inputLen >= partLen) {	// several updates necesary
		memcpy (&context->buffer[index], input, partLen);
		TIGER_transform (context);

		// process full buffers
		for (i=partLen; i+63 < inputLen; i+=64) {
			memcpy (&context->buffer[0], &input[i], 64);
			TIGER_transform (context);
		}
		index = 0;
	}
	else
		i = 0;

	// last partial buffer: copy
	memcpy (&context->buffer[index], &input[i], inputLen-i);
}
	
/* TIGER finalization. Ends an TIGER message-digest operation, writing the
  the message digest and zeroizing the context.
 */
void TIGER_final_old (TIGER_CTX *context)
{
    unsigned int index, padLen;
	uint64	bitcount = context->count << 3;
    /* Compute number of bytes mod 64 */
	index = context->count % 64;

	// pad out to 56 mod 64
	padLen = (index < 56) ? (56 - index) : (120 - index);
	TIGER_update_old (context, PADDING, padLen);

	context->buffer[56] = (bitcount      ) & 0xff;
	context->buffer[57] = (bitcount >>  8) & 0xff;
	context->buffer[58] = (bitcount >> 16) & 0xff;
	context->buffer[59] = (bitcount >> 24) & 0xff;
	context->buffer[60] = (bitcount >> 32) & 0xff;
	context->buffer[61] = (bitcount >> 40) & 0xff;
	context->buffer[62] = (bitcount >> 48) & 0xff;
	context->buffer[63] = (bitcount >> 56) & 0xff;
//printf ("final after bitcount: ");
//for (i=0; i<64; i++) printf ("%02x", context->buffer[i]); printf ("\n");

	TIGER_transform (context);

	context->out[0] = (context->state[0]      ) & 0xff;
	context->out[1] = (context->state[0] >>  8) & 0xff;
	context->out[2] = (context->state[0] >> 16) & 0xff;
	context->out[3] = (context->state[0] >> 24) & 0xff;
	context->out[4] = (context->state[0] >> 32) & 0xff;
	context->out[5] = (context->state[0] >> 40) & 0xff;
	context->out[6] = (context->state[0] >> 48) & 0xff;
	context->out[7] = (context->state[0] >> 56) & 0xff;
	context->out[8] = (context->state[1]      ) & 0xff;
	context->out[9] = (context->state[1] >>  8) & 0xff;
	context->out[10] = (context->state[1] >> 16) & 0xff;
	context->out[11] = (context->state[1] >> 24) & 0xff;
	context->out[12] = (context->state[1] >> 32) & 0xff;
	context->out[13] = (context->state[1] >> 40) & 0xff;
	context->out[14] = (context->state[1] >> 48) & 0xff;
	context->out[15] = (context->state[1] >> 56) & 0xff;
	context->out[16] = (context->state[2]      ) & 0xff;
	context->out[17] = (context->state[2] >>  8) & 0xff;
	context->out[18] = (context->state[2] >> 16) & 0xff;
	context->out[19] = (context->state[2] >> 24) & 0xff;
	context->out[20] = (context->state[2] >> 32) & 0xff;
	context->out[21] = (context->state[2] >> 40) & 0xff;
	context->out[22] = (context->state[2] >> 48) & 0xff;
	context->out[23] = (context->state[2] >> 56) & 0xff;
}

HashReturn 	TIGER_update (
	hashState state, 			/* previously initialized context */
	const BitSequence *buffer, 	/* bit buffer, first bit is MSB in [0] */
	DataLength databitlen)		/* number of bits to process from buffer */
{	
	/* can be called once or many times */
	/* verify correct hashbitlen and magic	*/

	TIGER_CTX *context = (TIGER_CTX *) state;
	if (context->hashbitlen != HASH_BITLENGTH_TIGER)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_TIGER)
		return BAD_ALGORITHM;

	/* check for byte alignment */
	if ((databitlen & 0x7)) {
		return FAIL;
	}

	TIGER_update_old (context, buffer, (unsigned int)(databitlen>>3));
	return SUCCESS;
}

HashReturn	TIGER_final (hashState state, BitSequence *hashval)
{	/*	does padding of last block	*/
	TIGER_CTX *context = (TIGER_CTX *) state;
	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_TIGER)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_TIGER)
		return BAD_ALGORITHM;

	TIGER_final_old (context);

	if (hashval)
		memcpy (hashval, context->out, HASH_LENGTH_TIGER);
	return SUCCESS;
}

/* TIGER utility routines
 *
 * hvf 23.1.2000
 * hvf 13.2.01
 * hvf 10.8.01
 * hvf 15.02.2009
 */

/* Digests a file and prints the result.
 */

HashReturn TIGER_File (hashState state, FILE *in)
{
	TIGER_CTX *context = (TIGER_CTX *) state;
	int len;
	unsigned char buffer[BUFFERSIZE];
	HashReturn retval;

	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_TIGER)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_TIGER)
		return BAD_ALGORITHM;

	while ((len = fread (buffer, 1, BUFFERSIZE, in))) {
		retval = TIGER_update (context, buffer, (DataLength)len << 3);
		if (retval != SUCCESS) return retval;
	}
	retval = TIGER_final (context, NULL);

	fclose (in);
	return retval;
}


HashReturn TIGER_HashToByte (hashState state, BYTE *out) 
{
	TIGER_CTX *context = (TIGER_CTX *) state;

	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_TIGER)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_TIGER)
		return BAD_ALGORITHM;

	memcpy (out, context->out, HASH_LENGTH_TIGER);
	return SUCCESS;
}

/* all-in-one hash function as required by SHA3-C-API */

HashReturn TIGER_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval) 
{
	hashState	state;
	HashReturn	retval;
	
	retval = TIGER_init (&state, HASH_BITLENGTH_TIGER);
	if (retval != SUCCESS) {
		fprintf (stderr, "TIGER_init failed, reason %d, hash length %d\n",
                 retval, HASH_BITLENGTH_TIGER);
        exit (1);
    }

	retval = TIGER_update (state, data, databitlen);
	if (retval != SUCCESS) {
		fprintf (stderr, "TIGER_update failed, reason %d\n", retval);
        exit (1);
    }

	retval = TIGER_final (state, hashval);
	if (retval != SUCCESS) {
		fprintf (stderr, "TIGER_final failed, reason %d\n", retval);
        exit (1);
    }
	free (state);
 	return retval;
}

