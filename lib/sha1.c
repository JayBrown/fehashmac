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

/* sha1.c	 - implement the Secure Hash Algorithms:
 * sha1 
 *
 * see FIPS PUB 180-1, 1993 May 11
 * see FIPS PUB 180-3
 * http://www.itl.nist.gov/fipspubs/fip180-1.htm
 * http://csrc.nist.gov/encryption/shs/sha256-384-512.pdf
 * http://csrc.nist.gov/publications/fips/fips180-3/fips180-3_final.pdf
 *
 * hvf 23.1.2000 10.8.2001 15.9.01 18.12.2008
 * hvf 31.01.2009 alignment with SHA3-C-API
 * disabled SHA1_Print - hvf 19.04.2015
 */

#include	"sha.h"
#include	<stdlib.h>
#include	<stdio.h>
#include 	<string.h>

/* constants for sha1 */

unsigned int	K_1[80] = {
	0x5A827999, 0x5A827999, 0x5A827999, 0x5A827999, 0x5A827999, 
	0x5A827999, 0x5A827999, 0x5A827999, 0x5A827999, 0x5A827999, 
	0x5A827999, 0x5A827999, 0x5A827999, 0x5A827999, 0x5A827999, 
	0x5A827999, 0x5A827999, 0x5A827999, 0x5A827999, 0x5A827999, 
	0x6ED9EBA1, 0x6ED9EBA1, 0x6ED9EBA1, 0x6ED9EBA1, 0x6ED9EBA1, 
	0x6ED9EBA1, 0x6ED9EBA1, 0x6ED9EBA1, 0x6ED9EBA1, 0x6ED9EBA1, 
	0x6ED9EBA1, 0x6ED9EBA1, 0x6ED9EBA1, 0x6ED9EBA1, 0x6ED9EBA1, 
	0x6ED9EBA1, 0x6ED9EBA1, 0x6ED9EBA1, 0x6ED9EBA1, 0x6ED9EBA1, 
	0x8F1BBCDC, 0x8F1BBCDC, 0x8F1BBCDC, 0x8F1BBCDC, 0x8F1BBCDC, 
	0x8F1BBCDC, 0x8F1BBCDC, 0x8F1BBCDC, 0x8F1BBCDC, 0x8F1BBCDC, 
	0x8F1BBCDC, 0x8F1BBCDC, 0x8F1BBCDC, 0x8F1BBCDC, 0x8F1BBCDC, 
	0x8F1BBCDC, 0x8F1BBCDC, 0x8F1BBCDC, 0x8F1BBCDC, 0x8F1BBCDC, 
	0xCA62C1D6, 0xCA62C1D6, 0xCA62C1D6, 0xCA62C1D6, 0xCA62C1D6, 
	0xCA62C1D6, 0xCA62C1D6, 0xCA62C1D6, 0xCA62C1D6, 0xCA62C1D6, 
	0xCA62C1D6, 0xCA62C1D6, 0xCA62C1D6, 0xCA62C1D6, 0xCA62C1D6, 
	0xCA62C1D6, 0xCA62C1D6, 0xCA62C1D6, 0xCA62C1D6, 0xCA62C1D6, 
};

/* functions	*/

#define	F0(B,C,D)  (((B)&(C))|((~(B))&(D)))
#define F2(B,C,D)  ((B)^(C)^(D))
#define F4(B,C,D)  (((B)&(C))|((B)&(D))|((C)&(D)))
#define F6(B,C,D)  ((B)^(C)^(D))

static unsigned int F (int i, unsigned int B, unsigned int C, unsigned int D)
{
	if (i < 20) 
		return ((B&C)|(~B&D));
	else if (i < 40)
		return (B^C^D);
	else if (i < 60)
		return ((B&C)|(B&D)|(C&D));
	else
		return (B^C^D);
	
}

HashReturn SHA1_init (hashState  *state, int hashbitlen)
{
	/* verify correct hash length	*/
	if (hashbitlen != HASH_BITLENGTH_SHA_1)
		return BAD_HASHBITLEN;

	/* allocate context and fill it	*/
	SHA1_CTX *context = (SHA1_CTX *)malloc (sizeof (SHA1_CTX));
	memset (context, 0, sizeof (SHA1_CTX));
	context->hashbitlen = HASH_BITLENGTH_SHA_1;
	context->magic = HASH_MAGIC_SHA_1;
	context->H0 = 0x67452301;
	context->H1 = 0xEFCDAB89;
	context->H2 = 0x98BADCFE;
	context->H3 = 0x10325476;
	context->H4 = 0xC3D2E1F0;
	*state = (hashState *) context;
	return SUCCESS;
}

static void 	SHA1_transform (SHA1_CTX *context)
/*	processes one full m_buffer of 64 characters */
{
	unsigned int	A, B, C, D, E;
	unsigned int	W[80];
	int	i;
	unsigned int	TEMP;

	for (i=0; i<HASH_INPUTBUFFER_W_SHA_1; i++){
		W[i] = context->m_buffer[i];
#ifdef	DEBUG
		printf ("W[%d] = %08X\n", i, W[i]);
#endif
	}

	for (i=HASH_INPUTBUFFER_W_SHA_1; i<80; i++)
		W[i] = CLS (W[i-3]^W[i-8]^W[i-14]^W[i-16], 1);

	A = context->H0;
	B = context->H1;
	C = context->H2;
	D = context->H3;
	E = context->H4;

#ifdef	DEBUG_TRANSFORM
		printf ("i = %d: %08X %08X %08X %08X %08X\n", -1, A, B, C, D, E);
#endif

	for (i=0; i<80; i++){
		TEMP = CLS (A, 5) + F(i,B,C,D) + E + W[i] + K_1[i];
		E = D; D = C; C = CLS (B, 30); B = A, A = TEMP;
#ifdef	DEBUG_TRANSFORM
		printf ("i = %d: %08X %08X %08X %08X %08X\n", i, A, B, C, D, E);
#endif
	}

	context->H0 += A; 
	context->H1 += B;
	context->H2 += C;
	context->H3 += D;
	context->H4 += E;

#ifdef	DEBUG_TRANSFORM
		printf ("H0 - H4: %08X %08X %08X %08X %08X\n", context->H0, 
			context->H1, context->H2, context->H3, context->H4);
#endif

	context->bitcount = 0;
	for (i=0; i<HASH_INPUTBUFFER_W_SHA_1; i++)
		context->m_buffer[i] = 0;
}

HashReturn 	SHA1_update (
	hashState state, 			/* previously initialized context */
	const BitSequence *buffer, 	/* bit buffer, first bit is MSB in [0] */
	DataLength databitlen)		/* number of bits to process from buffer */
{	
	/* can be called once or many times */
	/* verify correct hashbitlen and magic	*/

	SHA1_CTX *context = (SHA1_CTX *) state;
	if (context->hashbitlen != HASH_BITLENGTH_SHA_1)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_SHA_1)
		return BAD_ALGORITHM;

	DataLength bitsprocessed = 0LL;
	DataLength ibits;

	/* check for byte alignment */
	if (((databitlen & 0x7) == 0) && ((context->total_count & 0x7) == 0)) {
		/* use fast method for byte copying */
		int i, c;
		int n = databitlen >> 3;
		for (i=0; i<n; i++){
			c = context->bitcount >> 3;
			context->m_buffer[c>>2] |= (unsigned int)buffer[i]<<(24-((c&0x03)<<3));
			context->total_count += 8LL;	/* 8 bits per byte */
			context->bitcount += 8LL;	/* 8 bits per byte */
			if (c == (HASH_INPUTBUFFER_SHA_1 - 1)) 
				SHA1_transform (context);
		}
	}
	else {	/* bitwise processing, slower */
		while (bitsprocessed < databitlen) {
			ibits = AddBitsToArrayOfInts (
					context->m_buffer,
					context->bitcount,
					buffer,
					databitlen,
					bitsprocessed);
			context->bitcount += ibits;
			context->total_count += ibits;
			bitsprocessed += ibits;
#ifdef DEBUG
			printf ("SHA1_update: databitlen = %lld, bitsprocessed = %lld, ibits = %lld, bitcount = %d, totalcount = %lld\n",
				databitlen, bitsprocessed, ibits, context->bitcount, context->total_count);
#endif
			if (context->bitcount == HASH_INPUTBUFFER_BITS_SHA_1)
				SHA1_transform (context);
		}
	}
	return SUCCESS;
}

HashReturn	SHA1_final (hashState state, BitSequence *hashval)
{	/*	does padding of last block	*/
	SHA1_CTX *context = (SHA1_CTX *) state;
	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_SHA_1)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_SHA_1)
		return BAD_ALGORITHM;

	BitSequence Paddy = 0x80;
	AddBitsToArrayOfInts (
		context->m_buffer, 
		context->bitcount,
		&Paddy,
		1ULL,
		0);
	if (context->bitcount >= (HASH_INPUTBUFFER_BITS_SHA_1 - 64))
		SHA1_transform (context);

	context->m_buffer[14] = (unsigned int) (context->total_count >> 32);
	context->m_buffer[15] = (unsigned int) context->total_count;
	SHA1_transform (context);
	context->out[ 0] = (context->H0>>24) & 0xff;
	context->out[ 1] = (context->H0>>16) & 0xff;
	context->out[ 2] = (context->H0>> 8) & 0xff;
	context->out[ 3] = (context->H0    ) & 0xff;
	context->out[ 4] = (context->H1>>24) & 0xff;
	context->out[ 5] = (context->H1>>16) & 0xff;
	context->out[ 6] = (context->H1>> 8) & 0xff;
	context->out[ 7] = (context->H1    ) & 0xff;
	context->out[ 8] = (context->H2>>24) & 0xff;
	context->out[ 9] = (context->H2>>16) & 0xff;
	context->out[10] = (context->H2>> 8) & 0xff;
	context->out[11] = (context->H2    ) & 0xff;
	context->out[12] = (context->H3>>24) & 0xff;
	context->out[13] = (context->H3>>16) & 0xff;
	context->out[14] = (context->H3>> 8) & 0xff;
	context->out[15] = (context->H3    ) & 0xff;
	context->out[16] = (context->H4>>24) & 0xff;
	context->out[17] = (context->H4>>16) & 0xff;
	context->out[18] = (context->H4>> 8) & 0xff;
	context->out[19] = (context->H4    ) & 0xff;

	if (hashval)
		memcpy (hashval, context->out, HASH_LENGTH_SHA_1);
	return SUCCESS;
}

unsigned int	CLS (unsigned int x, int n)	/* circular left shift */
{
#ifdef	DEBUG1
	unsigned int result;
	printf ("CLS (%08x, %d) = ", x, n);
	result = ((x<<n) | ((x>>(32-n)) & (0x7FFFFFFF>>(31-n))));
	printf ("%08x\n", result);
	return result;
#else
	return ((x<<n) | ((x>>(32-n)) & (0x7FFFFFFF>>(31-n))));
#endif
}

/* SHA utility routines
 *
 * hvf 23.1.2000
 * hvf 13.2.01
 * hvf 10.8.01
 */

/* Digests a file and prints the result.
 */
HashReturn SHA1_File (hashState state, FILE *in)
{
	SHA1_CTX *context = (SHA1_CTX *) state;
	int len;
	unsigned char buffer[BUFFERSIZE];
	HashReturn retval;

	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_SHA_1)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_SHA_1)
		return BAD_ALGORITHM;

	while ((len = fread (buffer, 1, BUFFERSIZE, in))) {
		retval = SHA1_update (context, buffer, (DataLength)len << 3);
		if (retval != SUCCESS) return retval;
	}
	retval = SHA1_final (context, NULL);

	fclose (in);
	return retval;
}

HashReturn SHA1_HashToByte (hashState state, BYTE *out) 
{
	SHA1_CTX *context = (SHA1_CTX *) state;

	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_SHA_1)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_SHA_1)
		return BAD_ALGORITHM;

	memcpy (out, context->out, HASH_LENGTH_SHA_1);
	return SUCCESS;
}

/* all-in-one hash function as required by SHA3-C-API */

HashReturn SHA1_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval) 
{
	hashState	state;
	HashReturn	retval;
	
	retval = SHA1_init (&state, HASH_BITLENGTH_SHA_1);
	//HashReturn SHA1_init (hashState  *state, int hashbitlen)
	if (retval != SUCCESS) {
		fprintf (stderr, "SHA1_init failed, reason %d, hash length %d\n",
                 retval, HASH_BITLENGTH_SHA_1);
        exit (1);
    }

	retval = SHA1_update (state, data, databitlen);
	if (retval != SUCCESS) {
		fprintf (stderr, "SHA1_update failed, reason %d\n", retval);
        exit (1);
    }

	retval = SHA1_final (state, hashval);
	if (retval != SUCCESS) {
		fprintf (stderr, "SHA1_final failed, reason %d\n", retval);
        exit (1);
    }
	free (state);
 	return retval;
}


/* addbits return the number of used bits in buf after adding (positive)
 * or (negative) the number of bits that could not be added and that have to
 * go to the next word
 */

int addbits (unsigned int *buf, int bitsinlastword, 
			unsigned int bits, int nbits)
{
	// clear unused bits (just to make sure)
	// bits &=  ~((~0)<<nbits);
#ifdef DEBUG
	printf ("addbits buf %#x usedbits %d bits %#x nbits %d\n",
		*buf, bitsinlastword, bits, nbits);
#endif

	int sumbits = bitsinlastword + nbits;
	if (sumbits <= 32) {
		int do_leftshifts = 32 - sumbits;
		*buf |= bits << do_leftshifts;
		return sumbits;
	}
	else {
		int do_rightshifts = sumbits - 32;
		*buf |= (bits >> do_rightshifts) & 
				(0x7FFFFFFF >> (do_rightshifts-1));
		return -do_rightshifts;
	}
}
