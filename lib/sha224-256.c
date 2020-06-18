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

/* sha224-256.c	 - implement the Secure Hash Algorithms:
 * sha 224, sha256 
 *
 * see FIPS PUB 180-1, 1993 May 11
 * see FIPS PUB 180-2, 2002 August 1 + Change Notice to include SHA-224
 * see FIPS PUB 180-3
 * http://www.itl.nist.gov/fipspubs/fip180-1.htm
 * http://csrc.nist.gov/encryption/shs/sha256-384-512.pdf
 * http://csrc.nist.gov/publications/fips/fips180-2/fips180-2withchangenotice.pdf
 *http://csrc.nist.gov/publications/fips/fips180-3/fips180-3_final.pdf
 *
 * hvf 23.1.2000 10.8.2001 15.9.01 31.01.2007
 * hvf 16.02.2007 add bitcount
 * hvf 07.02.2009 alignment with SHA3-C-API
 * disabled SHA224_Print SHA256_Print - hvf 19.04.2015
 */

#include	"sha.h"
#include	<stdlib.h>
#include	<stdio.h>
#include 	<string.h>


/* sha256	 - implement the Secure Hash Algorithm SHA256
 */

/* constants for sha256 */

unsigned int	K_256[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 
	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 
	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2

};

/* functions	*/

#define	Ch(B,C,D)  (((B)&(C))^((~(B))&(D)))
#define Maj(B,C,D)  (((B)&(C))^((B)&(D))^((C)&(D)))
#define SIGMA0(x)	(Sint((x),2)^Sint((x),13)^Sint((x),22))
#define SIGMA1(x)	(Sint((x),6)^Sint((x),11)^Sint((x),25))
#define sigma0(x)	(Sint((x),7)^Sint((x),18)^Rint((x),3))
#define sigma1(x)	(Sint((x),17)^Sint((x),19)^Rint((x),10))

/* SHA224 ******************************************************/

HashReturn SHA224_init (hashState  *state, int hashbitlen)
{
	/* verify correct hash length	*/
	if (hashbitlen != HASH_BITLENGTH_SHA_224)
		return BAD_HASHBITLEN;

	/* allocate context and fill it	*/
	SHA224_CTX *context = (SHA224_CTX *)malloc (sizeof (SHA224_CTX));
	memset (context, 0, sizeof (SHA224_CTX));
	context->hashbitlen = HASH_BITLENGTH_SHA_224;
	context->magic = HASH_MAGIC_SHA_224;
	context->H1 = 0xc1059ed8;
	context->H2 = 0x367cd507;
	context->H3 = 0x3070dd17;
	context->H4 = 0xf70e5939;
	context->H5 = 0xffc00b31;
	context->H6 = 0x68581511;
	context->H7 = 0x64f98fa7;
	context->H8 = 0xbefa4fa4;
	*state = (hashState *) context;
	return SUCCESS;
}

static void 	SHA224_transform (SHA224_CTX *context)
/*	processes one full m_buffer of 64 characters */
{
	unsigned int	a, b, c, d, e, f, g, h;
	unsigned int	W[64];
	int	i;
	unsigned int	T1, T2;

	for (i=0; i<HASH_INPUTBUFFER_W_SHA_224; i++){
		W[i] = context->m_buffer[i];
#ifdef	DEBUG
		printf ("W[%d] = %08X\n", i, W[i]);
#endif
	}

	for (i=HASH_INPUTBUFFER_W_SHA_224; i<64; i++)
		W[i] = sigma1(W[i-2])+W[i-7]+sigma0(W[i-15])+W[i-16];


	a = context->H1;
	b = context->H2;
	c = context->H3;
	d = context->H4;
	e = context->H5;
	f = context->H6;
	g = context->H7;
	h = context->H8;

#ifdef	DEBUG_TRANSFORM
		printf ("i = %d: %08X %08X %08X %08X %08X %08X %08X %08X\n", 
			-1, a, b, c, d, e, f, g, h);
#endif

	for (i=0; i<64; i++){
		T1 = h + SIGMA1(e) + Ch(e, f, g) + K_256[i] + W[i];
		T2 = SIGMA0(a) + Maj(a, b, c);
		h = g; g = f; f = e; e = d + T1;
		d = c; c = b; b = a; a = T1 + T2;
#ifdef	DEBUG_TRANSFORM
		printf ("i = %d: %08X %08X %08X %08X %08X %08X %08X %08X\n", 
			i, a, b, c, d, e, f, g, h);
#endif
	}

	context->H1 += a;
	context->H2 += b;
	context->H3 += c;
	context->H4 += d;
	context->H5 += e;
	context->H6 += f;
	context->H7 += g;
	context->H8 += h;

#ifdef	DEBUG_TRANSFORM
		printf ("H1 - H8: %08X %08X %08X %08X %08X %08X %08X %08X\n", 
			context->H1, context->H2, context->H3, context->H4,
			context->H5, context->H6, context->H7, context->H8);
#endif

	context->bitcount = 0;
	for (i=0; i<HASH_INPUTBUFFER_W_SHA_224; i++)
		context->m_buffer[i] = 0;
}

HashReturn 	SHA224_update (
	hashState state, 			/* previously initialized context */
	const BitSequence *buffer, 	/* bit buffer, first bit is MSB in [0] */
	DataLength databitlen)		/* number of bits to process from buffer */
{	
	/* can be called once or many times */
	/* verify correct hashbitlen and magic	*/

	SHA224_CTX *context = (SHA224_CTX *) state;
	if (context->hashbitlen != HASH_BITLENGTH_SHA_224)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_SHA_224)
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
			if (c == (HASH_INPUTBUFFER_SHA_224 - 1)) 
				SHA224_transform (context);
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
			printf ("SHA224_update: databitlen = %lld, bitsprocessed = %lld, ibits = %lld, bitcount = %d, totalcount = %lld\n",
				databitlen, bitsprocessed, ibits, context->bitcount, context->total_count);
#endif
			if (context->bitcount == HASH_INPUTBUFFER_BITS_SHA_224)
				SHA224_transform (context);
		}
	}
	return SUCCESS;
}

HashReturn	SHA224_final (hashState state, BitSequence *hashval)
{	/*	does padding of last block	*/
	SHA224_CTX *context = (SHA224_CTX *) state;
	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_SHA_224)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_SHA_224)
		return BAD_ALGORITHM;

	BitSequence Paddy = 0x80;
	AddBitsToArrayOfInts (
		context->m_buffer, 
		context->bitcount,
		&Paddy,
		1ULL,
		0);
	if (context->bitcount >= (HASH_INPUTBUFFER_BITS_SHA_224 - 64))
		SHA224_transform (context);

	context->m_buffer[14] = (unsigned int) (context->total_count >> 32);
	context->m_buffer[15] = (unsigned int) context->total_count;
	SHA224_transform (context);
	context->out[ 0] = (context->H1>>24) & 0xff;
	context->out[ 1] = (context->H1>>16) & 0xff;
	context->out[ 2] = (context->H1>> 8) & 0xff;
	context->out[ 3] = (context->H1    ) & 0xff;
	context->out[ 4] = (context->H2>>24) & 0xff;
	context->out[ 5] = (context->H2>>16) & 0xff;
	context->out[ 6] = (context->H2>> 8) & 0xff;
	context->out[ 7] = (context->H2    ) & 0xff;
	context->out[ 8] = (context->H3>>24) & 0xff;
	context->out[ 9] = (context->H3>>16) & 0xff;
	context->out[10] = (context->H3>> 8) & 0xff;
	context->out[11] = (context->H3    ) & 0xff;
	context->out[12] = (context->H4>>24) & 0xff;
	context->out[13] = (context->H4>>16) & 0xff;
	context->out[14] = (context->H4>> 8) & 0xff;
	context->out[15] = (context->H4    ) & 0xff;
	context->out[16] = (context->H5>>24) & 0xff;
	context->out[17] = (context->H5>>16) & 0xff;
	context->out[18] = (context->H5>> 8) & 0xff;
	context->out[19] = (context->H5    ) & 0xff;
	context->out[20] = (context->H6>>24) & 0xff;
	context->out[21] = (context->H6>>16) & 0xff;
	context->out[22] = (context->H6>> 8) & 0xff;
	context->out[23] = (context->H6    ) & 0xff;
	context->out[24] = (context->H7>>24) & 0xff;
	context->out[25] = (context->H7>>16) & 0xff;
	context->out[26] = (context->H7>> 8) & 0xff;
	context->out[27] = (context->H7    ) & 0xff;
	if (hashval)
		memcpy (hashval, context->out, HASH_LENGTH_SHA_224);
	return SUCCESS;
}

unsigned int	Rint (unsigned int x, int n)	/* right shift */
{
#ifdef	DEBUG1
	unsigned int result;
	printf ("R (%08x, %d) = ", x, n);
	result = (x>>n) & (0x7FFFFFFF>>(n-1));
	printf ("%08x\n", result);
	return result;
#else
	return ((x>>n) & (0x7FFFFFFF>>(n-1)));
#endif
}

unsigned int	Sint (unsigned int x, int n)	/* right rotation */
{
#ifdef	DEBUG1
	unsigned int result;
	printf ("S (%08x, %d) = ", x, n);
	result = (x<<(32-n)) | ((x>>n) & (0x7FFFFFFF>>(n-1)));
	printf ("%08x\n", result);
	return result;
#else
	return ((x<<(32-n)) | ((x>>n) & (0x7FFFFFFF>>(n-1))));
#endif
}

/* SHA224 utility routines
 *
 * hvf 23.1.2000
 * hvf 13.2.01
 * hvf 10.8.01
 * hvf 31.01.2007
 * hvf 07.02.2009
 */

/* Digests a file and prints the result.
 */
HashReturn SHA224_File (hashState state, FILE *in)
{
	SHA224_CTX *context = (SHA224_CTX *) state;
	int len;
	unsigned char buffer[BUFFERSIZE];
	HashReturn retval;

	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_SHA_224)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_SHA_224)
		return BAD_ALGORITHM;

	while ((len = fread (buffer, 1, BUFFERSIZE, in))) {
		retval = SHA224_update (context, buffer, (DataLength)len << 3);
		if (retval != SUCCESS) return retval;
	}
	retval = SHA224_final (context, NULL);

	fclose (in);
	return retval;
}

HashReturn SHA224_HashToByte (hashState state, BYTE *out) 
{
	SHA224_CTX *context = (SHA224_CTX *) state;

	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_SHA_224)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_SHA_224)
		return BAD_ALGORITHM;

	memcpy (out, context->out, HASH_LENGTH_SHA_224);
	return SUCCESS;
}

/* all-in-one hash function as required by SHA3-C-API */

HashReturn SHA224_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval) 
{
	hashState	state;
	HashReturn	retval;
	
	retval = SHA224_init (&state, HASH_BITLENGTH_SHA_224);
	if (retval != SUCCESS) {
		fprintf (stderr, "SHA224_init failed, reason %d, hash length %d\n",
                 retval, HASH_BITLENGTH_SHA_224);
        exit (1);
    }

	retval = SHA224_update (state, data, databitlen);
	if (retval != SUCCESS) {
		fprintf (stderr, "SHA224_update failed, reason %d\n", retval);
        exit (1);
    }

	retval = SHA224_final (state, hashval);
	if (retval != SUCCESS) {
		fprintf (stderr, "SHA224_final failed, reason %d\n", retval);
        exit (1);
    }
	free (state);
 	return retval;
}

/* SHA256 ******************************************************/

HashReturn SHA256_init (hashState  *state, int hashbitlen)
{
	/* verify correct hash length	*/
	if (hashbitlen != HASH_BITLENGTH_SHA_256)
		return BAD_HASHBITLEN;

	/* allocate context and fill it	*/
	SHA256_CTX *context = (SHA256_CTX *)malloc (sizeof (SHA256_CTX));
	memset (context, 0, sizeof (SHA256_CTX));
	context->hashbitlen = HASH_BITLENGTH_SHA_256;
	context->magic = HASH_MAGIC_SHA_256;
	context->H1 = 0x6a09e667;
	context->H2 = 0xbb67ae85;
	context->H3 = 0x3c6ef372;
	context->H4 = 0xa54ff53a;
	context->H5 = 0x510e527f;
	context->H6 = 0x9b05688c;
	context->H7 = 0x1f83d9ab;
	context->H8 = 0x5be0cd19;
	*state = (hashState *) context;
	return SUCCESS;
}

static void 	SHA256_transform (SHA256_CTX *context)
/*	processes one full m_buffer of 64 characters */
{
	unsigned int	a, b, c, d, e, f, g, h;
	unsigned int	W[64];
	int	i;
	unsigned int	T1, T2;

	for (i=0; i<HASH_INPUTBUFFER_W_SHA_256; i++){
		W[i] = context->m_buffer[i];
#ifdef	DEBUG
		printf ("W[%d] = %08X\n", i, W[i]);
#endif
	}

	for (i=HASH_INPUTBUFFER_W_SHA_256; i<64; i++)
		W[i] = sigma1(W[i-2])+W[i-7]+sigma0(W[i-15])+W[i-16];


	a = context->H1;
	b = context->H2;
	c = context->H3;
	d = context->H4;
	e = context->H5;
	f = context->H6;
	g = context->H7;
	h = context->H8;

#ifdef	DEBUG
		printf ("i = %d: %08X %08X %08X %08X %08X %08X %08X %08X\n", 
			-1, a, b, c, d, e, f, g, h);
#endif

	for (i=0; i<64; i++){
		T1 = h + SIGMA1(e) + Ch(e, f, g) + K_256[i] + W[i];
		T2 = SIGMA0(a) + Maj(a, b, c);
		h = g; g = f; f = e; e = d + T1;
		d = c; c = b; b = a; a = T1 + T2;
#ifdef	DEBUG
		printf ("i = %d: %08X %08X %08X %08X %08X %08X %08X %08X\n", 
			i, a, b, c, d, e, f, g, h);
#endif
	}

	context->H1 += a;
	context->H2 += b;
	context->H3 += c;
	context->H4 += d;
	context->H5 += e;
	context->H6 += f;
	context->H7 += g;
	context->H8 += h;

#ifdef	DEBUG
		printf ("H1 - H8: %08X %08X %08X %08X %08X %08X %08X %08X\n", 
			context->H1, context->H2, context->H3, context->H4,
			context->H5, context->H6, context->H7, context->H8);
#endif

	context->bitcount = 0;
	for (i=0; i<HASH_INPUTBUFFER_W_SHA_256; i++)
		context->m_buffer[i] = 0;
}

HashReturn 	SHA256_update (
	hashState state, 			/* previously initialized context */
	const BitSequence *buffer, 	/* bit buffer, first bit is MSB in [0] */
	DataLength databitlen)		/* number of bits to process from buffer */
{	
	/* can be called once or many times */
	/* verify correct hashbitlen and magic	*/

	SHA256_CTX *context = (SHA256_CTX *) state;
	if (context->hashbitlen != HASH_BITLENGTH_SHA_256)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_SHA_256)
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
			if (c == (HASH_INPUTBUFFER_SHA_256 - 1)) 
				SHA256_transform (context);
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
			printf ("SHA256_update: databitlen = %lld, bitsprocessed = %lld, ibits = %lld, bitcount = %d, totalcount = %lld\n",
				databitlen, bitsprocessed, ibits, context->bitcount, context->total_count);
#endif
			if (context->bitcount == HASH_INPUTBUFFER_BITS_SHA_256)
				SHA256_transform (context);
		}
	}
	return SUCCESS;
}

HashReturn	SHA256_final (hashState state, BitSequence *hashval)
{	/*	does padding of last block	*/
	SHA256_CTX *context = (SHA256_CTX *) state;
	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_SHA_256)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_SHA_256)
		return BAD_ALGORITHM;

	BitSequence Paddy = 0x80;
	AddBitsToArrayOfInts (
		context->m_buffer, 
		context->bitcount,
		&Paddy,
		1ULL,
		0);
	if (context->bitcount >= (HASH_INPUTBUFFER_BITS_SHA_256 - 64))
		SHA256_transform (context);

	context->m_buffer[14] = (unsigned int) (context->total_count >> 32);
	context->m_buffer[15] = (unsigned int) context->total_count;
	SHA256_transform (context);
	context->out[ 0] = (context->H1>>24) & 0xff;
	context->out[ 1] = (context->H1>>16) & 0xff;
	context->out[ 2] = (context->H1>> 8) & 0xff;
	context->out[ 3] = (context->H1    ) & 0xff;
	context->out[ 4] = (context->H2>>24) & 0xff;
	context->out[ 5] = (context->H2>>16) & 0xff;
	context->out[ 6] = (context->H2>> 8) & 0xff;
	context->out[ 7] = (context->H2    ) & 0xff;
	context->out[ 8] = (context->H3>>24) & 0xff;
	context->out[ 9] = (context->H3>>16) & 0xff;
	context->out[10] = (context->H3>> 8) & 0xff;
	context->out[11] = (context->H3    ) & 0xff;
	context->out[12] = (context->H4>>24) & 0xff;
	context->out[13] = (context->H4>>16) & 0xff;
	context->out[14] = (context->H4>> 8) & 0xff;
	context->out[15] = (context->H4    ) & 0xff;
	context->out[16] = (context->H5>>24) & 0xff;
	context->out[17] = (context->H5>>16) & 0xff;
	context->out[18] = (context->H5>> 8) & 0xff;
	context->out[19] = (context->H5    ) & 0xff;
	context->out[20] = (context->H6>>24) & 0xff;
	context->out[21] = (context->H6>>16) & 0xff;
	context->out[22] = (context->H6>> 8) & 0xff;
	context->out[23] = (context->H6    ) & 0xff;
	context->out[24] = (context->H7>>24) & 0xff;
	context->out[25] = (context->H7>>16) & 0xff;
	context->out[26] = (context->H7>> 8) & 0xff;
	context->out[27] = (context->H7    ) & 0xff;
	context->out[28] = (context->H8>>24) & 0xff;
	context->out[29] = (context->H8>>16) & 0xff;
	context->out[30] = (context->H8>> 8) & 0xff;
	context->out[31] = (context->H8    ) & 0xff;
	if (hashval)
		memcpy (hashval, context->out, HASH_LENGTH_SHA_256);
	return SUCCESS;
}

/* SHA utility routines
 *
 * hvf 23.1.2000
 * hvf 13.2.01
 * hvf 10.8.01
 */

/* Digests a file and prints the result.
 */
HashReturn SHA256_File (hashState state, FILE *in)
{
	SHA256_CTX *context = (SHA256_CTX *) state;
	int len;
	unsigned char buffer[BUFFERSIZE];
	HashReturn retval;

	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_SHA_256)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_SHA_256)
		return BAD_ALGORITHM;

	while ((len = fread (buffer, 1, BUFFERSIZE, in))) {
		retval = SHA256_update (context, buffer, (DataLength)len << 3);
		if (retval != SUCCESS) return retval;
	}
	retval = SHA256_final (context, NULL);

	fclose (in);
	return retval;
}

HashReturn SHA256_HashToByte (hashState state, BYTE *out) 
{
	SHA256_CTX *context = (SHA256_CTX *) state;

	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_SHA_256)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_SHA_256)
		return BAD_ALGORITHM;

	memcpy (out, context->out, HASH_LENGTH_SHA_256);
	return SUCCESS;
}

/* all-in-one hash function as required by SHA3-C-API */

HashReturn SHA256_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval) 
{
	hashState	state;
	HashReturn	retval;
	
	retval = SHA256_init (&state, HASH_BITLENGTH_SHA_256);
	if (retval != SUCCESS) {
		fprintf (stderr, "SHA256_init failed, reason %d, hash length %d\n",
                 retval, HASH_BITLENGTH_SHA_256);
        exit (1);
    }

	retval = SHA256_update (state, data, databitlen);
	if (retval != SUCCESS) {
		fprintf (stderr, "SHA256_update failed, reason %d\n", retval);
        exit (1);
    }

	retval = SHA256_final (state, hashval);
	if (retval != SUCCESS) {
		fprintf (stderr, "SHA256_final failed, reason %d\n", retval);
        exit (1);
    }
	free (state);
 	return retval;
}

