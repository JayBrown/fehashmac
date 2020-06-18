/* MD5C.C - RSA Data Security, Inc., MD5 message-digest algorithm
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

/* Copyright (C) 1991-2, RSA Data Security, Inc. Created 1991. All
rights reserved.

License to copy and use this software is granted provided that it
is identified as the "RSA Data Security, Inc. MD5 Message-Digest
Algorithm" in all material mentioning or referencing this software
or this function.

License is also granted to make and use derivative works provided
that such works are identified as "derived from the RSA Data
Security, Inc. MD5 Message-Digest Algorithm" in all material
mentioning or referencing the derived work.

RSA Data Security, Inc. makes no representations concerning either
the merchantability of this software or the suitability of this
software for any particular purpose. It is provided "as is"
without express or implied warranty of any kind.

These notices must be retained in any copies of any part of this
documentation and/or software.
 */

/* integrated in fehashmac - hvf 12.08.01 
 *  hvf 14.02.2009 aligned with SHA3-C-API
 * disabled MD5_Print - hvf 19.04.2015
 */

#include	"mdx.h"
#include	<string.h>
#include	<stdlib.h>
#include	<stdio.h>

#define DEBUG
#undef  DEBUG

/* Constants for MD5Transform routine.
 */

#define S11 7
#define S12 12
#define S13 17
#define S14 22
#define S21 5
#define S22 9
#define S23 14
#define S24 20
#define S31 4
#define S32 11
#define S33 16
#define S34 23
#define S41 6
#define S42 10
#define S43 15
#define S44 21

static void MD5_update_old (MD5_CTX *context, const BYTE *input, unsigned int inputLen);
static void MD5_final_old (MD5_CTX *context);
static void MD5_Transform (unsigned int [4], const BYTE [64]);
static void Encode (BYTE *, unsigned int *, unsigned int);
static void Decode (unsigned int *, const BYTE *, unsigned int);

static BYTE PADDING[64] = {
  0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/* F, G, H and I are basic MD5 functions.
 */
#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z)))

/* ROTATE_LEFT rotates x left n bits.
 */
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

/* FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4.
Rotation is separate from addition to prevent recomputation.
 */
#define FF(a, b, c, d, x, s, ac) { \
 (a) += F ((b), (c), (d)) + (x) + (unsigned int)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
  }
#define GG(a, b, c, d, x, s, ac) { \
 (a) += G ((b), (c), (d)) + (x) + (unsigned int)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
  }
#define HH(a, b, c, d, x, s, ac) { \
 (a) += H ((b), (c), (d)) + (x) + (unsigned int)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
  }
#define II(a, b, c, d, x, s, ac) { \
 (a) += I ((b), (c), (d)) + (x) + (unsigned int)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
  }

/* MD5 initialization. Begins an MD5 operation, writing a new context.
 */

HashReturn MD5_init (hashState  *state, int hashbitlen)
{
	/* verify correct hash length	*/
	if (hashbitlen != HASH_BITLENGTH_MD5)
		return BAD_HASHBITLEN;

	/* allocate context and fill it	*/
	MD5_CTX *context = (MD5_CTX *)malloc (sizeof (MD5_CTX));
	memset (context, 0, sizeof (MD5_CTX));
	context->hashbitlen = HASH_BITLENGTH_MD5;
	context->magic = HASH_MAGIC_MD5;

	/* Load magic initialization constants.
	*/
	context->state[0] = 0x67452301;
	context->state[1] = 0xefcdab89;
	context->state[2] = 0x98badcfe;
	context->state[3] = 0x10325476;
	*state = (hashState *) context;
	return SUCCESS;
}

/* MD5 block update operation. Continues an MD5 message-digest
  operation, processing another message block, and updating the
  context.
 */

HashReturn 	MD5_update (
	hashState state, 			/* previously initialized context */
	const BitSequence *buffer, 	/* bit buffer, first bit is MSB in [0] */
	DataLength databitlen)		/* number of bits to process from buffer */
{	
	/* can be called once or many times */
	/* verify correct hashbitlen and magic	*/

	MD5_CTX *context = (MD5_CTX *) state;
	if (context->hashbitlen != HASH_BITLENGTH_MD5)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_MD5)
		return BAD_ALGORITHM;

	/* check for byte alignment */
	if ((databitlen & 0x7)) {
		return FAIL;
	}

	MD5_update_old (context, buffer, (unsigned int)(databitlen>>3));
	context->total_count += databitlen;
	return SUCCESS;
}

/* MD5 finalization. Ends an MD5 message-digest operation, writing the
  the message digest and zeroizing the context.
 */

HashReturn	MD5_final (hashState state, BitSequence *hashval)
{	/*	does padding of last block	*/
	MD5_CTX *context = (MD5_CTX *) state;
	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_MD5)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_MD5)
		return BAD_ALGORITHM;

	MD5_final_old (context);

	if (hashval)
		memcpy (hashval, context->out, HASH_LENGTH_MD5);
	return SUCCESS;
}

static void MD5_update_old (MD5_CTX *context, const BYTE *input, unsigned int inputLen)
{
	unsigned int i, index, partLen;

	/* Compute number of bytes mod 64 */
	index = (unsigned int)((context->count[0] >> 3) & 0x3F);

	/* Update number of bits */
	if ((context->count[0] += ((unsigned int)inputLen << 3))
		< ((unsigned int)inputLen << 3))
		context->count[1]++;
	context->count[1] += ((unsigned int)inputLen >> 29);

	partLen = 64 - index;

	/* Transform as many times as possible.
	*/
	if (inputLen >= partLen) {
		memcpy ((BYTE *)&context->buffer[index], (BYTE *)input, partLen);
		MD5_Transform (context->state, context->buffer);

		for (i = partLen; i + 63 < inputLen; i += 64)
			MD5_Transform (context->state, &input[i]);

	index = 0;
	}
	else
		i = 0;

	/* Buffer remaining input */
	memcpy ((BYTE *)&context->buffer[index], (BYTE *)&input[i], inputLen-i);
}

/* MD5 finalization. Ends an MD5 message-digest operation, writing the
  the message digest and zeroizing the context.
 */
static void MD5_final_old (MD5_CTX *context)
{
	BYTE bits[8];
	unsigned int index, padLen;

	/* Save number of bits */
	Encode (bits, context->count, 8);

	/* Pad out to 56 mod 64.
	*/
	index = (unsigned int)((context->count[0] >> 3) & 0x3f);
	padLen = (index < 56) ? (56 - index) : (120 - index);
	MD5_update_old (context, PADDING, padLen);

	/* Append length (before padding) */
	MD5_update_old (context, bits, 8);

	/* Store state in digest */
	Encode (context->out, context->state, 16);

}

/* MD5 basic transformation. Transforms state based on block.
 */
static void MD5_Transform (unsigned int state[4], const BYTE block[64])
{
	unsigned int a = state[0], b = state[1], c = state[2], d = state[3], x[16];

	Decode (x, block, 64);
#ifdef DEBUG
	int i;
	for (i=0; i<16; i++) 
		printf ("W[%d] = %8.8x\n", i, x[i]);
#endif

	/* Round 1 */
	FF (a, b, c, d, x[ 0], S11, 0xd76aa478); /* 1 */
	FF (d, a, b, c, x[ 1], S12, 0xe8c7b756); /* 2 */
	FF (c, d, a, b, x[ 2], S13, 0x242070db); /* 3 */
	FF (b, c, d, a, x[ 3], S14, 0xc1bdceee); /* 4 */
	FF (a, b, c, d, x[ 4], S11, 0xf57c0faf); /* 5 */
	FF (d, a, b, c, x[ 5], S12, 0x4787c62a); /* 6 */
	FF (c, d, a, b, x[ 6], S13, 0xa8304613); /* 7 */
	FF (b, c, d, a, x[ 7], S14, 0xfd469501); /* 8 */
	FF (a, b, c, d, x[ 8], S11, 0x698098d8); /* 9 */
	FF (d, a, b, c, x[ 9], S12, 0x8b44f7af); /* 10 */
	FF (c, d, a, b, x[10], S13, 0xffff5bb1); /* 11 */
	FF (b, c, d, a, x[11], S14, 0x895cd7be); /* 12 */
	FF (a, b, c, d, x[12], S11, 0x6b901122); /* 13 */
	FF (d, a, b, c, x[13], S12, 0xfd987193); /* 14 */
	FF (c, d, a, b, x[14], S13, 0xa679438e); /* 15 */
	FF (b, c, d, a, x[15], S14, 0x49b40821); /* 16 */

	/* Round 2 */
	GG (a, b, c, d, x[ 1], S21, 0xf61e2562); /* 17 */
	GG (d, a, b, c, x[ 6], S22, 0xc040b340); /* 18 */
	GG (c, d, a, b, x[11], S23, 0x265e5a51); /* 19 */
	GG (b, c, d, a, x[ 0], S24, 0xe9b6c7aa); /* 20 */
	GG (a, b, c, d, x[ 5], S21, 0xd62f105d); /* 21 */
	GG (d, a, b, c, x[10], S22,  0x2441453); /* 22 */
	GG (c, d, a, b, x[15], S23, 0xd8a1e681); /* 23 */
	GG (b, c, d, a, x[ 4], S24, 0xe7d3fbc8); /* 24 */
	GG (a, b, c, d, x[ 9], S21, 0x21e1cde6); /* 25 */
	GG (d, a, b, c, x[14], S22, 0xc33707d6); /* 26 */
	GG (c, d, a, b, x[ 3], S23, 0xf4d50d87); /* 27 */
	GG (b, c, d, a, x[ 8], S24, 0x455a14ed); /* 28 */
	GG (a, b, c, d, x[13], S21, 0xa9e3e905); /* 29 */
	GG (d, a, b, c, x[ 2], S22, 0xfcefa3f8); /* 30 */
	GG (c, d, a, b, x[ 7], S23, 0x676f02d9); /* 31 */
	GG (b, c, d, a, x[12], S24, 0x8d2a4c8a); /* 32 */

	/* Round 3 */
	HH (a, b, c, d, x[ 5], S31, 0xfffa3942); /* 33 */
	HH (d, a, b, c, x[ 8], S32, 0x8771f681); /* 34 */
	HH (c, d, a, b, x[11], S33, 0x6d9d6122); /* 35 */
	HH (b, c, d, a, x[14], S34, 0xfde5380c); /* 36 */
	HH (a, b, c, d, x[ 1], S31, 0xa4beea44); /* 37 */
	HH (d, a, b, c, x[ 4], S32, 0x4bdecfa9); /* 38 */
	HH (c, d, a, b, x[ 7], S33, 0xf6bb4b60); /* 39 */
	HH (b, c, d, a, x[10], S34, 0xbebfbc70); /* 40 */
	HH (a, b, c, d, x[13], S31, 0x289b7ec6); /* 41 */
	HH (d, a, b, c, x[ 0], S32, 0xeaa127fa); /* 42 */
	HH (c, d, a, b, x[ 3], S33, 0xd4ef3085); /* 43 */
	HH (b, c, d, a, x[ 6], S34,  0x4881d05); /* 44 */
	HH (a, b, c, d, x[ 9], S31, 0xd9d4d039); /* 45 */
	HH (d, a, b, c, x[12], S32, 0xe6db99e5); /* 46 */
	HH (c, d, a, b, x[15], S33, 0x1fa27cf8); /* 47 */
	HH (b, c, d, a, x[ 2], S34, 0xc4ac5665); /* 48 */

	/* Round 4 */
	II (a, b, c, d, x[ 0], S41, 0xf4292244); /* 49 */
	II (d, a, b, c, x[ 7], S42, 0x432aff97); /* 50 */
	II (c, d, a, b, x[14], S43, 0xab9423a7); /* 51 */
	II (b, c, d, a, x[ 5], S44, 0xfc93a039); /* 52 */
	II (a, b, c, d, x[12], S41, 0x655b59c3); /* 53 */
	II (d, a, b, c, x[ 3], S42, 0x8f0ccc92); /* 54 */
	II (c, d, a, b, x[10], S43, 0xffeff47d); /* 55 */
	II (b, c, d, a, x[ 1], S44, 0x85845dd1); /* 56 */
	II (a, b, c, d, x[ 8], S41, 0x6fa87e4f); /* 57 */
	II (d, a, b, c, x[15], S42, 0xfe2ce6e0); /* 58 */
	II (c, d, a, b, x[ 6], S43, 0xa3014314); /* 59 */
	II (b, c, d, a, x[13], S44, 0x4e0811a1); /* 60 */
	II (a, b, c, d, x[ 4], S41, 0xf7537e82); /* 61 */
	II (d, a, b, c, x[11], S42, 0xbd3af235); /* 62 */
	II (c, d, a, b, x[ 2], S43, 0x2ad7d2bb); /* 63 */
	II (b, c, d, a, x[ 9], S44, 0xeb86d391); /* 64 */

	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;

	/* Zeroize sensitive information.
	*/
	memset ((BYTE *)x, 0, sizeof (x));
}

/* Encodes input (unsigned int) into output (BYTE). Assumes len is
  a multiple of 4.
 */
static void Encode (BYTE *output, unsigned int *input, unsigned int len)
{
	unsigned int i, j;

	for (i = 0, j = 0; j < len; i++, j += 4) {
		output[j] = (BYTE)(input[i] & 0xff);
		output[j+1] = (BYTE)((input[i] >> 8) & 0xff);
		output[j+2] = (BYTE)((input[i] >> 16) & 0xff);
		output[j+3] = (BYTE)((input[i] >> 24) & 0xff);
	}
}

/* Decodes input (BYTE) into output (unsigned int). Assumes len is
  a multiple of 4.
 */
static void Decode (unsigned int *output, const BYTE *input, unsigned int len)
{
	unsigned int i, j;

	for (i = 0, j = 0; j < len; i++, j += 4)
		output[i] = ((unsigned int)input[j]) | 
			(((unsigned int)input[j+1]) << 8) |
			(((unsigned int)input[j+2]) << 16) | 
			(((unsigned int)input[j+3]) << 24);
}

/* utility routines
 * adapted for MDx hashes
 *
 * hvf 23.1.2000
 * hvf 13.2.01
 * hvf 10.8.01
 * hvf 12.8.01
 */

/* Digests a file and prints the result.
 */

HashReturn MD5_File (hashState state, FILE *in)
{
	MD5_CTX *context = (MD5_CTX *) state;
	int len;
	unsigned char buffer[BUFFERSIZE];
	HashReturn retval;

	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_MD5)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_MD5)
		return BAD_ALGORITHM;

	while ((len = fread (buffer, 1, BUFFERSIZE, in))) {
		retval = MD5_update (context, buffer, (DataLength)len << 3);
		if (retval != SUCCESS) return retval;
	}
	retval = MD5_final (context, NULL);

	fclose (in);
	return retval;
}

HashReturn MD5_HashToByte (hashState state, BYTE *out) 
{
	MD5_CTX *context = (MD5_CTX *) state;

	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_MD5)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_MD5)
		return BAD_ALGORITHM;

	memcpy (out, context->out, HASH_LENGTH_MD5);
	return SUCCESS;
}

/* all-in-one hash function as required by SHA3-C-API */

HashReturn MD5_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval) 
{
	hashState	state;
	HashReturn	retval;
	
	retval = MD5_init (&state, HASH_BITLENGTH_MD5);
	//HashReturn MD5_init (hashState  *state, int hashbitlen)
	if (retval != SUCCESS) {
		fprintf (stderr, "MD5_init failed, reason %d, hash length %d\n",
                 retval, HASH_BITLENGTH_MD5);
        exit (1);
    }

	retval = MD5_update (state, data, databitlen);
	if (retval != SUCCESS) {
		fprintf (stderr, "MD5_update failed, reason %d\n", retval);
        exit (1);
    }

	retval = MD5_final (state, hashval);
	if (retval != SUCCESS) {
		fprintf (stderr, "MD5_final failed, reason %d\n", retval);
        exit (1);
    }
	free (state);
 	return retval;
}

