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

/* sha384-512.c	 - implement the Secure Hash Algorithms:
 * sha384 sha512 sha512-224 sha512-256
 *
 * see FIPS PUB 180-1, 1993 May 11
 * http://www.itl.nist.gov/fipspubs/fip180-1.htm
 * http://csrc.nist.gov/encryption/shs/sha256-384-512.pdf
 *
 * hvf 23.1.2000 10.8.2001 15.9.01
 * hvf 16.02.2007 add bitcount
 * hvf 08.02.2009 alignment with SHA3-C-API
 * hvf 17.08.2009 SHA384_final: copy context to hashval
 *
 * hvf 29.03.2011 add sha512-224 and sha512-256
 * see referfences in sha.h
 *
 * disabled SHA384_Print SHA512_Print SHA512_224_Print SHA512_256_Print - hvf 19.04.2015
 */

#include	"sha.h"
#include	<stdlib.h>
#include	<stdio.h>
#include 	<string.h>


/* sha384	 - implement the Secure Hash Algorithm SHA384
 */

/* constants for sha384 and sha512 */

uint64	K_384_512[80] = {
	0x428a2f98d728ae22LL, 0x7137449123ef65cdLL, 0xb5c0fbcfec4d3b2fLL, 0xe9b5dba58189dbbcLL,
	0x3956c25bf348b538LL, 0x59f111f1b605d019LL, 0x923f82a4af194f9bLL, 0xab1c5ed5da6d8118LL,
	0xd807aa98a3030242LL, 0x12835b0145706fbeLL, 0x243185be4ee4b28cLL, 0x550c7dc3d5ffb4e2LL,
	0x72be5d74f27b896fLL, 0x80deb1fe3b1696b1LL, 0x9bdc06a725c71235LL, 0xc19bf174cf692694LL,
	0xe49b69c19ef14ad2LL, 0xefbe4786384f25e3LL, 0x0fc19dc68b8cd5b5LL, 0x240ca1cc77ac9c65LL,
	0x2de92c6f592b0275LL, 0x4a7484aa6ea6e483LL, 0x5cb0a9dcbd41fbd4LL, 0x76f988da831153b5LL,
	0x983e5152ee66dfabLL, 0xa831c66d2db43210LL, 0xb00327c898fb213fLL, 0xbf597fc7beef0ee4LL,
	0xc6e00bf33da88fc2LL, 0xd5a79147930aa725LL, 0x06ca6351e003826fLL, 0x142929670a0e6e70LL,
	0x27b70a8546d22ffcLL, 0x2e1b21385c26c926LL, 0x4d2c6dfc5ac42aedLL, 0x53380d139d95b3dfLL,
	0x650a73548baf63deLL, 0x766a0abb3c77b2a8LL, 0x81c2c92e47edaee6LL, 0x92722c851482353bLL,
	0xa2bfe8a14cf10364LL, 0xa81a664bbc423001LL, 0xc24b8b70d0f89791LL, 0xc76c51a30654be30LL,
	0xd192e819d6ef5218LL, 0xd69906245565a910LL, 0xf40e35855771202aLL, 0x106aa07032bbd1b8LL,
	0x19a4c116b8d2d0c8LL, 0x1e376c085141ab53LL, 0x2748774cdf8eeb99LL, 0x34b0bcb5e19b48a8LL,
	0x391c0cb3c5c95a63LL, 0x4ed8aa4ae3418acbLL, 0x5b9cca4f7763e373LL, 0x682e6ff3d6b2b8a3LL,
	0x748f82ee5defb2fcLL, 0x78a5636f43172f60LL, 0x84c87814a1f0ab72LL, 0x8cc702081a6439ecLL,
	0x90befffa23631e28LL, 0xa4506cebde82bde9LL, 0xbef9a3f7b2c67915LL, 0xc67178f2e372532bLL,
	0xca273eceea26619cLL, 0xd186b8c721c0c207LL, 0xeada7dd6cde0eb1eLL, 0xf57d4f7fee6ed178LL,
	0x06f067aa72176fbaLL, 0x0a637dc5a2c898a6LL, 0x113f9804bef90daeLL, 0x1b710b35131c471bLL,
	0x28db77f523047d84LL, 0x32caab7b40c72493LL, 0x3c9ebe0a15c9bebcLL, 0x431d67c49c100d4cLL,
	0x4cc5d4becb3e42b6LL, 0x597f299cfc657e2aLL, 0x5fcb6fab3ad6faecLL, 0x6c44198c4a475817LL
};

/* functions for sha384 and sha512	*/

#define	Chlong(B,C,D)  (((B)&(C))^((~(B))&(D)))
#define Majlong(B,C,D)  (((B)&(C))^((B)&(D))^((C)&(D)))
#define SIGMA0long(x)	(Slong((x),28)^Slong((x),34)^Slong((x),39))
#define SIGMA1long(x)	(Slong((x),14)^Slong((x),18)^Slong((x),41))
#define sigma0long(x)	(Slong((x),1)^Slong((x),8)^Rlong((x),7))
#define sigma1long(x)	(Slong((x),19)^Slong((x),61)^Rlong((x),6))

HashReturn SHA384_init (hashState  *state, int hashbitlen)
{
	/* verify correct hash length	*/
	if (hashbitlen != HASH_BITLENGTH_SHA_384)
		return BAD_HASHBITLEN;

	/* allocate context and fill it	*/
	SHA384_CTX *context = (SHA384_CTX *)malloc (sizeof (SHA384_CTX));
	memset (context, 0, sizeof (SHA384_CTX));
	context->hashbitlen = HASH_BITLENGTH_SHA_384;
	context->magic = HASH_MAGIC_SHA_384;
	context->H1 = 0xcbbb9d5dc1059ed8LL;
	context->H2 = 0x629a292a367cd507LL;
	context->H3 = 0x9159015a3070dd17LL;
	context->H4 = 0x152fecd8f70e5939LL;
	context->H5 = 0x67332667ffc00b31LL;
	context->H6 = 0x8eb44a8768581511LL;
	context->H7 = 0xdb0c2e0d64f98fa7LL;
	context->H8 = 0x47b5481dbefa4fa4LL;
	*state = (hashState *) context;
	return SUCCESS;
}

static void 	SHA384_transform (SHA384_CTX *context)
/*	processes one full m_buffer of 128 characters */
{
	uint64	a, b, c, d, e, f, g, h;
	uint64	W[80];
	int	i;
	uint64	T1, T2;

	for (i=0; i<HASH_INPUTBUFFER_W_SHA_384; i++){
		W[i] = context->m_buffer[i];
#ifdef	DEBUG
		printf ("W[%d] = %016llX\n", i, W[i]);
#endif
	}

	for (i=HASH_INPUTBUFFER_W_SHA_384; i<80; i++)
		W[i] = sigma1long(W[i-2])+W[i-7]+sigma0long(W[i-15])+W[i-16];


	a = context->H1;
	b = context->H2;
	c = context->H3;
	d = context->H4;
	e = context->H5;
	f = context->H6;
	g = context->H7;
	h = context->H8;

#ifdef	DEBUG_TRANSFORM
		printf ("i = %d: %016llX %016llX %016llX %016llX %016llX %016llX %016llX %016llX\n", 
			-1, a, b, c, d, e, f, g, h);
#endif

	for (i=0; i<80; i++){
		T1 = h + SIGMA1long(e) + Chlong(e, f, g) + K_384_512[i] + W[i];
		T2 = SIGMA0long(a) + Majlong(a, b, c);
		h = g; g = f; f = e; e = d + T1;
		d = c; c = b; b = a; a = T1 + T2;
#ifdef	DEBUG_TRANSFORM
		printf ("i = %d: %016llX %016llX %016llX %016llX %016llX %016llX %016llX %016llX\n", 
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
		printf ("H1 - H8: %016llX %016llX %016llX %016llX %016llX %016llX %016llX %016llX\n", 
			context->H1, context->H2, context->H3, context->H4,
			context->H5, context->H6, context->H7, context->H8);
#endif

	context->bitcount = 0;
	for (i=0; i<HASH_INPUTBUFFER_W_SHA_384; i++)
		context->m_buffer[i] = 0LL;
}

HashReturn 	SHA384_update (
	hashState state, 			/* previously initialized context */
	const BitSequence *buffer, 	/* bit buffer, first bit is MSB in [0] */
	DataLength databitlen)		/* number of bits to process from buffer */
{	
	/* can be called once or many times */
	/* verify correct hashbitlen and magic	*/

	SHA384_CTX *context = (SHA384_CTX *) state;
	if (context->hashbitlen != HASH_BITLENGTH_SHA_384)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_SHA_384)
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
			context->m_buffer[c>>3] |= (uint64)buffer[i]<<(56-((c&0x07)<<3));
			context->total_count += 8LL;	/* 8 bits per byte */
			context->bitcount += 8LL;	/* 8 bits per byte */
			if (c == (HASH_INPUTBUFFER_SHA_384 - 1)) 
				SHA384_transform (context);
		}
	}
	else {	/* bitwise processing, slower */
		while (bitsprocessed < databitlen) {
			ibits = AddBitsToArrayOfLL (
					context->m_buffer,
					context->bitcount,
					buffer,
					databitlen,
					bitsprocessed);
			context->bitcount += ibits;
			context->total_count += ibits;
			bitsprocessed += ibits;
#ifdef DEBUG
			printf ("SHA384_update: databitlen = %lld, bitsprocessed = %lld, ibits = %lld, bitcount = %d, totalcount = %lld\n",
				databitlen, bitsprocessed, ibits, context->bitcount, context->total_count);
#endif
			if (context->bitcount == HASH_INPUTBUFFER_BITS_SHA_384)
				SHA384_transform (context);
		}
	}
	return SUCCESS;
}
	 
HashReturn	SHA384_final (hashState state, BitSequence *hashval)
{	/*	does padding of last block	*/
	SHA384_CTX *context = (SHA384_CTX *) state;
	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_SHA_384)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_SHA_384)
		return BAD_ALGORITHM;

	BitSequence Paddy = 0x80;
	AddBitsToArrayOfLL (
		context->m_buffer, 
		context->bitcount,
		&Paddy,
		1ULL,
		0);
	if (context->bitcount >= (HASH_INPUTBUFFER_BITS_SHA_384 - 128))
		SHA384_transform (context);

	context->m_buffer[15] = context->total_count;
	SHA384_transform (context);
	context->out[ 0] = (context->H1>>56) & 0xff;
	context->out[ 1] = (context->H1>>48) & 0xff;
	context->out[ 2] = (context->H1>>40) & 0xff;
	context->out[ 3] = (context->H1>>32) & 0xff;
	context->out[ 4] = (context->H1>>24) & 0xff;
	context->out[ 5] = (context->H1>>16) & 0xff;
	context->out[ 6] = (context->H1>> 8) & 0xff;
	context->out[ 7] = (context->H1    ) & 0xff;
	context->out[ 8] = (context->H2>>56) & 0xff;
	context->out[ 9] = (context->H2>>48) & 0xff;
	context->out[10] = (context->H2>>40) & 0xff;
	context->out[11] = (context->H2>>32) & 0xff;
	context->out[12] = (context->H2>>24) & 0xff;
	context->out[13] = (context->H2>>16) & 0xff;
	context->out[14] = (context->H2>> 8) & 0xff;
	context->out[15] = (context->H2    ) & 0xff;
	context->out[16] = (context->H3>>56) & 0xff;
	context->out[17] = (context->H3>>48) & 0xff;
	context->out[18] = (context->H3>>40) & 0xff;
	context->out[19] = (context->H3>>32) & 0xff;
	context->out[20] = (context->H3>>24) & 0xff;
	context->out[21] = (context->H3>>16) & 0xff;
	context->out[22] = (context->H3>> 8) & 0xff;
	context->out[23] = (context->H3    ) & 0xff;
	context->out[24] = (context->H4>>56) & 0xff;
	context->out[25] = (context->H4>>48) & 0xff;
	context->out[26] = (context->H4>>40) & 0xff;
	context->out[27] = (context->H4>>32) & 0xff;
	context->out[28] = (context->H4>>24) & 0xff;
	context->out[29] = (context->H4>>16) & 0xff;
	context->out[30] = (context->H4>> 8) & 0xff;
	context->out[31] = (context->H4    ) & 0xff;
	context->out[32] = (context->H5>>56) & 0xff;
	context->out[33] = (context->H5>>48) & 0xff;
	context->out[34] = (context->H5>>40) & 0xff;
	context->out[35] = (context->H5>>32) & 0xff;
	context->out[36] = (context->H5>>24) & 0xff;
	context->out[37] = (context->H5>>16) & 0xff;
	context->out[38] = (context->H5>> 8) & 0xff;
	context->out[39] = (context->H5    ) & 0xff;
	context->out[40] = (context->H6>>56) & 0xff;
	context->out[41] = (context->H6>>48) & 0xff;
	context->out[42] = (context->H6>>40) & 0xff;
	context->out[43] = (context->H6>>32) & 0xff;
	context->out[44] = (context->H6>>24) & 0xff;
	context->out[45] = (context->H6>>16) & 0xff;
	context->out[46] = (context->H6>> 8) & 0xff;
	context->out[47] = (context->H6    ) & 0xff;
	if (hashval)
		memcpy (hashval, context->out, HASH_LENGTH_SHA_384);
	return SUCCESS;
}

uint64	Rlong (uint64 x, int n)	/* right shift */
{
#ifdef	DEBUG1
	uint64 result;
	printf ("R (%016llx, %d) = ", x, n);
	result = (x>>n) & (0x7FFFFFFFFFFFFFFFLL>>(n-1));
	printf ("%016llx\n", result);
	return result;
#else
	return ((x>>n) & (0x7FFFFFFFFFFFFFFFLL>>(n-1)));
#endif
}

uint64	Slong (uint64 x, int n)	/* right rotation */
{
#ifdef	DEBUG1
	uint64 result;
	printf ("S (%016llx, %d) = ", x, n);
	result = (x<<(64-n)) | ((x>>n) & (0x7FFFFFFFFFFFFFFFLL>>(n-1)));
	printf ("%016llx\n", result);
	return result;
#else
	return ((x<<(64-n)) | ((x>>n) & (0x7FFFFFFFFFFFFFFFLL>>(n-1))));
#endif
}

/* sha512	 - implement the Secure Hash Algorithm SHA512
 */

HashReturn SHA512_init (hashState  *state, int hashbitlen)
{
	/* verify correct hash length	*/
	if (hashbitlen != HASH_BITLENGTH_SHA_512)
		return BAD_HASHBITLEN;

	/* allocate context and fill it	*/
	SHA512_CTX *context = (SHA512_CTX *)malloc (sizeof (SHA512_CTX));
	memset (context, 0, sizeof (SHA512_CTX));
	context->hashbitlen = HASH_BITLENGTH_SHA_512;
	context->magic = HASH_MAGIC_SHA_512;
	context->H1 = 0x6a09e667f3bcc908LL;
	context->H2 = 0xbb67ae8584caa73bLL;
	context->H3 = 0x3c6ef372fe94f82bLL;
	context->H4 = 0xa54ff53a5f1d36f1LL;
	context->H5 = 0x510e527fade682d1LL;
	context->H6 = 0x9b05688c2b3e6c1fLL;
	context->H7 = 0x1f83d9abfb41bd6bLL;
	context->H8 = 0x5be0cd19137e2179LL;
	*state = (hashState *) context;
	return SUCCESS;
}

static void 	SHA512_transform (SHA512_CTX *context)
/*	processes one full m_buffer of 128 characters */
{
	uint64	a, b, c, d, e, f, g, h;
	uint64	W[80];
	int	i;
	uint64	T1, T2;

	for (i=0; i<HASH_INPUTBUFFER_W_SHA_512; i++){
		W[i] = context->m_buffer[i];
#ifdef	DEBUG
		printf ("W[%d] = %016llX\n", i, W[i]);
#endif
	}

	for (i=HASH_INPUTBUFFER_W_SHA_512; i<80; i++)
		W[i] = sigma1long(W[i-2])+W[i-7]+sigma0long(W[i-15])+W[i-16];


	a = context->H1;
	b = context->H2;
	c = context->H3;
	d = context->H4;
	e = context->H5;
	f = context->H6;
	g = context->H7;
	h = context->H8;

#ifdef	DEBUG_TRANSFORM
		printf ("i = %d: %016llX %016llX %016llX %016llX %016llX %016llX %016llX %016llX\n", 
			-1, a, b, c, d, e, f, g, h);
#endif

	for (i=0; i<80; i++){
		T1 = h + SIGMA1long(e) + Chlong(e, f, g) + K_384_512[i] + W[i];
		T2 = SIGMA0long(a) + Majlong(a, b, c);
		h = g; g = f; f = e; e = d + T1;
		d = c; c = b; b = a; a = T1 + T2;
#ifdef	DEBUG_TRANSFORM
		printf ("i = %d: %016llX %016llX %016llX %016llX %016llX %016llX %016llX %016llX\n", 
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
		printf ("H1 - H8: %016llX %016llX %016llX %016llX %016llX %016llX %016llX %016llX\n", 
			context->H1, context->H2, context->H3, context->H4,
			context->H5, context->H6, context->H7, context->H8);
#endif

	context->bitcount = 0;
	for (i=0; i<HASH_INPUTBUFFER_W_SHA_512; i++)
		context->m_buffer[i] = 0LL;
}

HashReturn 	SHA512_update (
	hashState state, 			/* previously initialized context */
	const BitSequence *buffer, 	/* bit buffer, first bit is MSB in [0] */
	DataLength databitlen)		/* number of bits to process from buffer */
{	
	/* can be called once or many times */
	/* verify correct hashbitlen and magic	*/

	SHA512_CTX *context = (SHA512_CTX *) state;
	if (context->hashbitlen != HASH_BITLENGTH_SHA_512)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_SHA_512)
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
			context->m_buffer[c>>3] |= (uint64)buffer[i]<<(56-((c&0x07)<<3));
			context->total_count += 8LL;	/* 8 bits per byte */
			context->bitcount += 8LL;	/* 8 bits per byte */
			if (c == (HASH_INPUTBUFFER_SHA_512 - 1)) 
				SHA512_transform (context);
		}
	}
	else {	/* bitwise processing, slower */
		while (bitsprocessed < databitlen) {
			ibits = AddBitsToArrayOfLL (
					context->m_buffer,
					context->bitcount,
					buffer,
					databitlen,
					bitsprocessed);
			context->bitcount += ibits;
			context->total_count += ibits;
			bitsprocessed += ibits;
#ifdef DEBUG
			printf ("SHA512_update: databitlen = %lld, bitsprocessed = %lld, ibits = %lld, bitcount = %d, totalcount = %lld\n",
				databitlen, bitsprocessed, ibits, context->bitcount, context->total_count);
#endif
			if (context->bitcount == HASH_INPUTBUFFER_BITS_SHA_512)
				SHA512_transform (context);
		}
	}
	return SUCCESS;
}
	 
HashReturn	SHA512_final (hashState state, BitSequence *hashval)
{	/*	does padding of last block	*/
	SHA512_CTX *context = (SHA512_CTX *) state;
	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_SHA_512)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_SHA_512)
		return BAD_ALGORITHM;

	BitSequence Paddy = 0x80;
	AddBitsToArrayOfLL (
		context->m_buffer, 
		context->bitcount,
		&Paddy,
		1ULL,
		0);
	if (context->bitcount >= (HASH_INPUTBUFFER_BITS_SHA_512 - 128))
		SHA512_transform (context);

	context->m_buffer[15] = context->total_count;
	SHA512_transform (context);
	context->out[ 0] = (context->H1>>56) & 0xff;
	context->out[ 1] = (context->H1>>48) & 0xff;
	context->out[ 2] = (context->H1>>40) & 0xff;
	context->out[ 3] = (context->H1>>32) & 0xff;
	context->out[ 4] = (context->H1>>24) & 0xff;
	context->out[ 5] = (context->H1>>16) & 0xff;
	context->out[ 6] = (context->H1>> 8) & 0xff;
	context->out[ 7] = (context->H1    ) & 0xff;
	context->out[ 8] = (context->H2>>56) & 0xff;
	context->out[ 9] = (context->H2>>48) & 0xff;
	context->out[10] = (context->H2>>40) & 0xff;
	context->out[11] = (context->H2>>32) & 0xff;
	context->out[12] = (context->H2>>24) & 0xff;
	context->out[13] = (context->H2>>16) & 0xff;
	context->out[14] = (context->H2>> 8) & 0xff;
	context->out[15] = (context->H2    ) & 0xff;
	context->out[16] = (context->H3>>56) & 0xff;
	context->out[17] = (context->H3>>48) & 0xff;
	context->out[18] = (context->H3>>40) & 0xff;
	context->out[19] = (context->H3>>32) & 0xff;
	context->out[20] = (context->H3>>24) & 0xff;
	context->out[21] = (context->H3>>16) & 0xff;
	context->out[22] = (context->H3>> 8) & 0xff;
	context->out[23] = (context->H3    ) & 0xff;
	context->out[24] = (context->H4>>56) & 0xff;
	context->out[25] = (context->H4>>48) & 0xff;
	context->out[26] = (context->H4>>40) & 0xff;
	context->out[27] = (context->H4>>32) & 0xff;
	context->out[28] = (context->H4>>24) & 0xff;
	context->out[29] = (context->H4>>16) & 0xff;
	context->out[30] = (context->H4>> 8) & 0xff;
	context->out[31] = (context->H4    ) & 0xff;
	context->out[32] = (context->H5>>56) & 0xff;
	context->out[33] = (context->H5>>48) & 0xff;
	context->out[34] = (context->H5>>40) & 0xff;
	context->out[35] = (context->H5>>32) & 0xff;
	context->out[36] = (context->H5>>24) & 0xff;
	context->out[37] = (context->H5>>16) & 0xff;
	context->out[38] = (context->H5>> 8) & 0xff;
	context->out[39] = (context->H5    ) & 0xff;
	context->out[40] = (context->H6>>56) & 0xff;
	context->out[41] = (context->H6>>48) & 0xff;
	context->out[42] = (context->H6>>40) & 0xff;
	context->out[43] = (context->H6>>32) & 0xff;
	context->out[44] = (context->H6>>24) & 0xff;
	context->out[45] = (context->H6>>16) & 0xff;
	context->out[46] = (context->H6>> 8) & 0xff;
	context->out[47] = (context->H6    ) & 0xff;
	context->out[48] = (context->H7>>56) & 0xff;
	context->out[49] = (context->H7>>48) & 0xff;
	context->out[50] = (context->H7>>40) & 0xff;
	context->out[51] = (context->H7>>32) & 0xff;
	context->out[52] = (context->H7>>24) & 0xff;
	context->out[53] = (context->H7>>16) & 0xff;
	context->out[54] = (context->H7>> 8) & 0xff;
	context->out[55] = (context->H7    ) & 0xff;
	context->out[56] = (context->H8>>56) & 0xff;
	context->out[57] = (context->H8>>48) & 0xff;
	context->out[58] = (context->H8>>40) & 0xff;
	context->out[59] = (context->H8>>32) & 0xff;
	context->out[60] = (context->H8>>24) & 0xff;
	context->out[61] = (context->H8>>16) & 0xff;
	context->out[62] = (context->H8>> 8) & 0xff;
	context->out[63] = (context->H8    ) & 0xff;
	if (hashval)
		memcpy (hashval, context->out, HASH_LENGTH_SHA_512);
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
HashReturn SHA384_File (hashState state, FILE *in)
{
	SHA384_CTX *context = (SHA384_CTX *) state;
	int len;
	unsigned char buffer[BUFFERSIZE];
	HashReturn retval;

	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_SHA_384)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_SHA_384)
		return BAD_ALGORITHM;

	while ((len = fread (buffer, 1, BUFFERSIZE, in))) {
		retval = SHA384_update (context, buffer, (DataLength)len << 3);
		if (retval != SUCCESS) return retval;
	}
	retval = SHA384_final (context, NULL);

	fclose (in);
	return retval;
}

HashReturn SHA384_HashToByte (hashState state, BYTE *out) 
{
	SHA384_CTX *context = (SHA384_CTX *) state;

	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_SHA_384)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_SHA_384)
		return BAD_ALGORITHM;

	memcpy (out, context->out, HASH_LENGTH_SHA_384);
	return SUCCESS;
}

/* all-in-one hash function as required by SHA3-C-API */

HashReturn SHA384_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval) 
{
	hashState	state;
	HashReturn	retval;
	
	retval = SHA384_init (&state, HASH_BITLENGTH_SHA_384);
	if (retval != SUCCESS) {
		fprintf (stderr, "SHA384_init failed, reason %d, hash length %d\n",
                 retval, HASH_BITLENGTH_SHA_384);
        exit (1);
    }

	retval = SHA384_update (state, data, databitlen);
	if (retval != SUCCESS) {
		fprintf (stderr, "SHA384_update failed, reason %d\n", retval);
        exit (1);
    }

	retval = SHA384_final (state, hashval);
	if (retval != SUCCESS) {
		fprintf (stderr, "SHA384_final failed, reason %d\n", retval);
        exit (1);
    }
	free (state);
 	return retval;
}

/* Digests a file and prints the result.
 */
HashReturn SHA512_File (hashState state, FILE *in)
{
	SHA512_CTX *context = (SHA512_CTX *) state;
	int len;
	unsigned char buffer[BUFFERSIZE];
	HashReturn retval;

	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_SHA_512)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_SHA_512)
		return BAD_ALGORITHM;

	while ((len = fread (buffer, 1, BUFFERSIZE, in))) {
		retval = SHA512_update (context, buffer, (DataLength)len << 3);
		if (retval != SUCCESS) return retval;
	}
	retval = SHA512_final (context, NULL);

	fclose (in);
	return retval;
}

HashReturn SHA512_HashToByte (hashState state, BYTE *out) 
{
	SHA512_CTX *context = (SHA512_CTX *) state;

	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_SHA_512)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_SHA_512)
		return BAD_ALGORITHM;

	memcpy (out, context->out, HASH_LENGTH_SHA_512);
	return SUCCESS;
}

/* all-in-one hash function as required by SHA3-C-API */

HashReturn SHA512_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval) 
{
	hashState	state;
	HashReturn	retval;
	
	retval = SHA512_init (&state, HASH_BITLENGTH_SHA_512);
	if (retval != SUCCESS) {
		fprintf (stderr, "SHA512_init failed, reason %d, hash length %d\n",
                 retval, HASH_BITLENGTH_SHA_512);
        exit (1);
    }

	retval = SHA512_update (state, data, databitlen);
	if (retval != SUCCESS) {
		fprintf (stderr, "SHA512_update failed, reason %d\n", retval);
        exit (1);
    }

	retval = SHA512_final (state, hashval);
	if (retval != SUCCESS) {
		fprintf (stderr, "SHA512_final failed, reason %d\n", retval);
        exit (1);
    }
	free (state);
 	return retval;
}

/* sha512_224	 - implement the Secure Hash Algorithm SHA512/224
 */

HashReturn SHA512_224_init (hashState  *state, int hashbitlen)
{
	/* verify correct hash length	*/
	if (hashbitlen != HASH_BITLENGTH_SHA_512_224)
		return BAD_HASHBITLEN;

	/* allocate context and fill it	*/
	SHA512_224_CTX *context = (SHA512_224_CTX *)malloc (sizeof (SHA512_224_CTX));
	memset (context, 0, sizeof (SHA512_224_CTX));
	context->hashbitlen = HASH_BITLENGTH_SHA_512_224;
	context->magic = HASH_MAGIC_SHA_512_224;
	context->H1 = 0x8C3D37C819544DA2LL;
	context->H2 = 0x73E1996689DCD4D6LL;
	context->H3 = 0x1DFAB7AE32FF9C82LL;
	context->H4 = 0x679DD514582F9FCFLL;
	context->H5 = 0x0F6D2B697BD44DA8LL;
	context->H6 = 0x77E36F7304C48942LL;
	context->H7 = 0x3F9D85A86A1D36C8LL;
	context->H8 = 0x1112E6AD91D692A1LL;
	*state = (hashState *) context;
	return SUCCESS;
}

static void 	SHA512_224_transform (SHA512_224_CTX *context)
/*	processes one full m_buffer of 128 characters */
{
	uint64	a, b, c, d, e, f, g, h;
	uint64	W[80];
	int	i;
	uint64	T1, T2;

	for (i=0; i<HASH_INPUTBUFFER_W_SHA_512_224; i++){
		W[i] = context->m_buffer[i];
#ifdef	DEBUG
		printf ("W[%d] = %016llX\n", i, W[i]);
#endif
	}

	for (i=HASH_INPUTBUFFER_W_SHA_512_224; i<80; i++)
		W[i] = sigma1long(W[i-2])+W[i-7]+sigma0long(W[i-15])+W[i-16];


	a = context->H1;
	b = context->H2;
	c = context->H3;
	d = context->H4;
	e = context->H5;
	f = context->H6;
	g = context->H7;
	h = context->H8;

#ifdef	DEBUG_TRANSFORM
		printf ("i = %d: %016llX %016llX %016llX %016llX %016llX %016llX %016llX %016llX\n", 
			-1, a, b, c, d, e, f, g, h);
#endif

	for (i=0; i<80; i++){
		T1 = h + SIGMA1long(e) + Chlong(e, f, g) + K_384_512[i] + W[i];
		T2 = SIGMA0long(a) + Majlong(a, b, c);
		h = g; g = f; f = e; e = d + T1;
		d = c; c = b; b = a; a = T1 + T2;
#ifdef	DEBUG_TRANSFORM
		printf ("i = %d: %016llX %016llX %016llX %016llX %016llX %016llX %016llX %016llX\n", 
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
		printf ("H1 - H8: %016llX %016llX %016llX %016llX %016llX %016llX %016llX %016llX\n", 
			context->H1, context->H2, context->H3, context->H4,
			context->H5, context->H6, context->H7, context->H8);
#endif

	context->bitcount = 0;
	for (i=0; i<HASH_INPUTBUFFER_W_SHA_512_224; i++)
		context->m_buffer[i] = 0LL;
}

HashReturn 	SHA512_224_update (
	hashState state, 			/* previously initialized context */
	const BitSequence *buffer, 	/* bit buffer, first bit is MSB in [0] */
	DataLength databitlen)		/* number of bits to process from buffer */
{	
	/* can be called once or many times */
	/* verify correct hashbitlen and magic	*/

	SHA512_224_CTX *context = (SHA512_224_CTX *) state;
	if (context->hashbitlen != HASH_BITLENGTH_SHA_512_224)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_SHA_512_224)
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
			context->m_buffer[c>>3] |= (uint64)buffer[i]<<(56-((c&0x07)<<3));
			context->total_count += 8LL;	/* 8 bits per byte */
			context->bitcount += 8LL;	/* 8 bits per byte */
			if (c == (HASH_INPUTBUFFER_SHA_512_224 - 1)) 
				SHA512_224_transform (context);
		}
	}
	else {	/* bitwise processing, slower */
		while (bitsprocessed < databitlen) {
			ibits = AddBitsToArrayOfLL (
					context->m_buffer,
					context->bitcount,
					buffer,
					databitlen,
					bitsprocessed);
			context->bitcount += ibits;
			context->total_count += ibits;
			bitsprocessed += ibits;
#ifdef DEBUG
			printf ("SHA512_224_update: databitlen = %lld, bitsprocessed = %lld, ibits = %lld, bitcount = %d, totalcount = %lld\n",
				databitlen, bitsprocessed, ibits, context->bitcount, context->total_count);
#endif
			if (context->bitcount == HASH_INPUTBUFFER_BITS_SHA_512_224)
				SHA512_224_transform (context);
		}
	}
	return SUCCESS;
}
	 
HashReturn	SHA512_224_final (hashState state, BitSequence *hashval)
{	/*	does padding of last block	*/
	SHA512_224_CTX *context = (SHA512_224_CTX *) state;
	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_SHA_512_224)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_SHA_512_224)
		return BAD_ALGORITHM;

	BitSequence Paddy = 0x80;
	AddBitsToArrayOfLL (
		context->m_buffer, 
		context->bitcount,
		&Paddy,
		1ULL,
		0);
	if (context->bitcount >= (HASH_INPUTBUFFER_BITS_SHA_512_224 - 128))
		SHA512_224_transform (context);

	context->m_buffer[15] = context->total_count;
	SHA512_224_transform (context);
	context->out[ 0] = (context->H1>>56) & 0xff;
	context->out[ 1] = (context->H1>>48) & 0xff;
	context->out[ 2] = (context->H1>>40) & 0xff;
	context->out[ 3] = (context->H1>>32) & 0xff;
	context->out[ 4] = (context->H1>>24) & 0xff;
	context->out[ 5] = (context->H1>>16) & 0xff;
	context->out[ 6] = (context->H1>> 8) & 0xff;
	context->out[ 7] = (context->H1    ) & 0xff;
	context->out[ 8] = (context->H2>>56) & 0xff;
	context->out[ 9] = (context->H2>>48) & 0xff;
	context->out[10] = (context->H2>>40) & 0xff;
	context->out[11] = (context->H2>>32) & 0xff;
	context->out[12] = (context->H2>>24) & 0xff;
	context->out[13] = (context->H2>>16) & 0xff;
	context->out[14] = (context->H2>> 8) & 0xff;
	context->out[15] = (context->H2    ) & 0xff;
	context->out[16] = (context->H3>>56) & 0xff;
	context->out[17] = (context->H3>>48) & 0xff;
	context->out[18] = (context->H3>>40) & 0xff;
	context->out[19] = (context->H3>>32) & 0xff;
	context->out[20] = (context->H3>>24) & 0xff;
	context->out[21] = (context->H3>>16) & 0xff;
	context->out[22] = (context->H3>> 8) & 0xff;
	context->out[23] = (context->H3    ) & 0xff;
	context->out[24] = (context->H4>>56) & 0xff;
	context->out[25] = (context->H4>>48) & 0xff;
	context->out[26] = (context->H4>>40) & 0xff;
	context->out[27] = (context->H4>>32) & 0xff;
	if (hashval)
		memcpy (hashval, context->out, HASH_LENGTH_SHA_512_224);
	return SUCCESS;
}

/* sha512_256	 - implement the Secure Hash Algorithm SHA512/256
 */

HashReturn SHA512_256_init (hashState  *state, int hashbitlen)
{
	/* verify correct hash length	*/
	if (hashbitlen != HASH_BITLENGTH_SHA_512_256)
		return BAD_HASHBITLEN;

	/* allocate context and fill it	*/
	SHA512_256_CTX *context = (SHA512_256_CTX *)malloc (sizeof (SHA512_256_CTX));
	memset (context, 0, sizeof (SHA512_256_CTX));
	context->hashbitlen = HASH_BITLENGTH_SHA_512_256;
	context->magic = HASH_MAGIC_SHA_512_256;
	context->H1 = 0x22312194FC2BF72CLL;
	context->H2 = 0x9F555FA3C84C64C2LL;
	context->H3 = 0x2393B86B6F53B151LL;
	context->H4 = 0x963877195940EABDLL;
	context->H5 = 0x96283EE2A88EFFE3LL;
	context->H6 = 0xBE5E1E2553863992LL;
	context->H7 = 0x2B0199FC2C85B8AALL;
	context->H8 = 0x0EB72DDC81C52CA2LL;
	*state = (hashState *) context;
	return SUCCESS;
}

static void 	SHA512_256_transform (SHA512_256_CTX *context)
/*	processes one full m_buffer of 128 characters */
{
	uint64	a, b, c, d, e, f, g, h;
	uint64	W[80];
	int	i;
	uint64	T1, T2;

	for (i=0; i<HASH_INPUTBUFFER_W_SHA_512_256; i++){
		W[i] = context->m_buffer[i];
#ifdef	DEBUG
		printf ("W[%d] = %016llX\n", i, W[i]);
#endif
	}

	for (i=HASH_INPUTBUFFER_W_SHA_512_256; i<80; i++)
		W[i] = sigma1long(W[i-2])+W[i-7]+sigma0long(W[i-15])+W[i-16];


	a = context->H1;
	b = context->H2;
	c = context->H3;
	d = context->H4;
	e = context->H5;
	f = context->H6;
	g = context->H7;
	h = context->H8;

#ifdef	DEBUG_TRANSFORM
		printf ("i = %d: %016llX %016llX %016llX %016llX %016llX %016llX %016llX %016llX\n", 
			-1, a, b, c, d, e, f, g, h);
#endif

	for (i=0; i<80; i++){
		T1 = h + SIGMA1long(e) + Chlong(e, f, g) + K_384_512[i] + W[i];
		T2 = SIGMA0long(a) + Majlong(a, b, c);
		h = g; g = f; f = e; e = d + T1;
		d = c; c = b; b = a; a = T1 + T2;
#ifdef	DEBUG_TRANSFORM
		printf ("i = %d: %016llX %016llX %016llX %016llX %016llX %016llX %016llX %016llX\n", 
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
		printf ("H1 - H8: %016llX %016llX %016llX %016llX %016llX %016llX %016llX %016llX\n", 
			context->H1, context->H2, context->H3, context->H4,
			context->H5, context->H6, context->H7, context->H8);
#endif

	context->bitcount = 0;
	for (i=0; i<HASH_INPUTBUFFER_W_SHA_512_256; i++)
		context->m_buffer[i] = 0LL;
}

HashReturn 	SHA512_256_update (
	hashState state, 			/* previously initialized context */
	const BitSequence *buffer, 	/* bit buffer, first bit is MSB in [0] */
	DataLength databitlen)		/* number of bits to process from buffer */
{	
	/* can be called once or many times */
	/* verify correct hashbitlen and magic	*/

	SHA512_256_CTX *context = (SHA512_256_CTX *) state;
	if (context->hashbitlen != HASH_BITLENGTH_SHA_512_256)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_SHA_512_256)
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
			context->m_buffer[c>>3] |= (uint64)buffer[i]<<(56-((c&0x07)<<3));
			context->total_count += 8LL;	/* 8 bits per byte */
			context->bitcount += 8LL;	/* 8 bits per byte */
			if (c == (HASH_INPUTBUFFER_SHA_512_256 - 1)) 
				SHA512_256_transform (context);
		}
	}
	else {	/* bitwise processing, slower */
		while (bitsprocessed < databitlen) {
			ibits = AddBitsToArrayOfLL (
					context->m_buffer,
					context->bitcount,
					buffer,
					databitlen,
					bitsprocessed);
			context->bitcount += ibits;
			context->total_count += ibits;
			bitsprocessed += ibits;
#ifdef DEBUG
			printf ("SHA512_256_update: databitlen = %lld, bitsprocessed = %lld, ibits = %lld, bitcount = %d, totalcount = %lld\n",
				databitlen, bitsprocessed, ibits, context->bitcount, context->total_count);
#endif
			if (context->bitcount == HASH_INPUTBUFFER_BITS_SHA_512_256)
				SHA512_256_transform (context);
		}
	}
	return SUCCESS;
}
	 
HashReturn	SHA512_256_final (hashState state, BitSequence *hashval)
{	/*	does padding of last block	*/
	SHA512_256_CTX *context = (SHA512_256_CTX *) state;
	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_SHA_512_256)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_SHA_512_256)
		return BAD_ALGORITHM;

	BitSequence Paddy = 0x80;
	AddBitsToArrayOfLL (
		context->m_buffer, 
		context->bitcount,
		&Paddy,
		1ULL,
		0);
	if (context->bitcount >= (HASH_INPUTBUFFER_BITS_SHA_512_256 - 128))
		SHA512_256_transform (context);

	context->m_buffer[15] = context->total_count;
	SHA512_256_transform (context);
	context->out[ 0] = (context->H1>>56) & 0xff;
	context->out[ 1] = (context->H1>>48) & 0xff;
	context->out[ 2] = (context->H1>>40) & 0xff;
	context->out[ 3] = (context->H1>>32) & 0xff;
	context->out[ 4] = (context->H1>>24) & 0xff;
	context->out[ 5] = (context->H1>>16) & 0xff;
	context->out[ 6] = (context->H1>> 8) & 0xff;
	context->out[ 7] = (context->H1    ) & 0xff;
	context->out[ 8] = (context->H2>>56) & 0xff;
	context->out[ 9] = (context->H2>>48) & 0xff;
	context->out[10] = (context->H2>>40) & 0xff;
	context->out[11] = (context->H2>>32) & 0xff;
	context->out[12] = (context->H2>>24) & 0xff;
	context->out[13] = (context->H2>>16) & 0xff;
	context->out[14] = (context->H2>> 8) & 0xff;
	context->out[15] = (context->H2    ) & 0xff;
	context->out[16] = (context->H3>>56) & 0xff;
	context->out[17] = (context->H3>>48) & 0xff;
	context->out[18] = (context->H3>>40) & 0xff;
	context->out[19] = (context->H3>>32) & 0xff;
	context->out[20] = (context->H3>>24) & 0xff;
	context->out[21] = (context->H3>>16) & 0xff;
	context->out[22] = (context->H3>> 8) & 0xff;
	context->out[23] = (context->H3    ) & 0xff;
	context->out[24] = (context->H4>>56) & 0xff;
	context->out[25] = (context->H4>>48) & 0xff;
	context->out[26] = (context->H4>>40) & 0xff;
	context->out[27] = (context->H4>>32) & 0xff;
	context->out[28] = (context->H4>>24) & 0xff;
	context->out[29] = (context->H4>>16) & 0xff;
	context->out[30] = (context->H4>> 8) & 0xff;
	context->out[31] = (context->H4    ) & 0xff;
	if (hashval)
		memcpy (hashval, context->out, HASH_LENGTH_SHA_512_256);
	return SUCCESS;
}


/* SHA utility routines for SHA512-224
 */

/* Digests a file and prints the result.
 */
HashReturn SHA512_224_File (hashState state, FILE *in)
{
	SHA512_224_CTX *context = (SHA512_224_CTX *) state;
	int len;
	unsigned char buffer[BUFFERSIZE];
	HashReturn retval;

	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_SHA_512_224)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_SHA_512_224)
		return BAD_ALGORITHM;

	while ((len = fread (buffer, 1, BUFFERSIZE, in))) {
		retval = SHA512_224_update (context, buffer, (DataLength)len << 3);
		if (retval != SUCCESS) return retval;
	}
	retval = SHA512_224_final (context, NULL);

	fclose (in);
	return retval;
}

HashReturn SHA512_224_HashToByte (hashState state, BYTE *out) 
{
	SHA512_224_CTX *context = (SHA512_224_CTX *) state;

	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_SHA_512_224)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_SHA_512_224)
		return BAD_ALGORITHM;

	memcpy (out, context->out, HASH_LENGTH_SHA_512_224);
	return SUCCESS;
}

/* all-in-one hash function as required by SHA3-C-API */

HashReturn SHA512_224_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval) 
{
	hashState	state;
	HashReturn	retval;
	
	retval = SHA512_224_init (&state, HASH_BITLENGTH_SHA_512_224);
	if (retval != SUCCESS) {
		fprintf (stderr, "SHA512_224_init failed, reason %d, hash length %d\n",
                 retval, HASH_BITLENGTH_SHA_512_224);
        exit (1);
    }

	retval = SHA512_224_update (state, data, databitlen);
	if (retval != SUCCESS) {
		fprintf (stderr, "SHA512_224_update failed, reason %d\n", retval);
        exit (1);
    }

	retval = SHA512_224_final (state, hashval);
	if (retval != SUCCESS) {
		fprintf (stderr, "SHA512_224_final failed, reason %d\n", retval);
        exit (1);
    }
	free (state);
 	return retval;
}


/* SHA utility routines for SHA512-256
 */

/* Digests a file and prints the result.
 */
HashReturn SHA512_256_File (hashState state, FILE *in)
{
	SHA512_256_CTX *context = (SHA512_256_CTX *) state;
	int len;
	unsigned char buffer[BUFFERSIZE];
	HashReturn retval;

	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_SHA_512_256)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_SHA_512_256)
		return BAD_ALGORITHM;

	while ((len = fread (buffer, 1, BUFFERSIZE, in))) {
		retval = SHA512_256_update (context, buffer, (DataLength)len << 3);
		if (retval != SUCCESS) return retval;
	}
	retval = SHA512_256_final (context, NULL);

	fclose (in);
	return retval;
}

HashReturn SHA512_256_HashToByte (hashState state, BYTE *out) 
{
	SHA512_256_CTX *context = (SHA512_256_CTX *) state;

	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_SHA_512_256)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_SHA_512_256)
		return BAD_ALGORITHM;

	memcpy (out, context->out, HASH_LENGTH_SHA_512_256);
	return SUCCESS;
}

/* all-in-one hash function as required by SHA3-C-API */

HashReturn SHA512_256_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval) 
{
	hashState	state;
	HashReturn	retval;
	
	retval = SHA512_256_init (&state, HASH_BITLENGTH_SHA_512_256);
	if (retval != SUCCESS) {
		fprintf (stderr, "SHA512_256_init failed, reason %d, hash length %d\n",
                 retval, HASH_BITLENGTH_SHA_512_256);
        exit (1);
    }

	retval = SHA512_256_update (state, data, databitlen);
	if (retval != SUCCESS) {
		fprintf (stderr, "SHA512_256_update failed, reason %d\n", retval);
        exit (1);
    }

	retval = SHA512_256_final (state, hashval);
	if (retval != SUCCESS) {
		fprintf (stderr, "SHA512_256_final failed, reason %d\n", retval);
        exit (1);
    }
	free (state);
 	return retval;
}

