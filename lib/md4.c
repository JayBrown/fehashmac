/* MD4C.C - RSA Data Security, Inc., MD4 message-digest algorithm
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

/* Copyright (C) 1990-2, RSA Data Security, Inc. All rights reserved.

   License to copy and use this software is granted provided that it
   is identified as the "RSA Data Security, Inc. MD4 Message-Digest
   Algorithm" in all material mentioning or referencing this software
   or this function.

   License is also granted to make and use derivative works provided
   that such works are identified as "derived from the RSA Data
   Security, Inc. MD4 Message-Digest Algorithm" in all material
   mentioning or referencing the derived work.

   RSA Data Security, Inc. makes no representations concerning either
   the merchantability of this software or the suitability of this
   software for any particular purpose. It is provided "as is"
   without express or implied warranty of any kind.

   These notices must be retained in any copies of any part of this
   documentation and/or software.
 */

/* integrated into fehashmac - hvf 12.08.01	
 *  hvf 14.02.2009 aligned with SHA3-C-API
 * disabled MD4_Print - hvf 19.04.2015
 */

#include	"mdx.h"
#include	<stdlib.h>
#include	<string.h>
#include	<stdio.h>

/* Constants for MD4Transform routine.
 */
#define S11 3
#define S12 7
#define S13 11
#define S14 19
#define S21 3
#define S22 5
#define S23 9
#define S24 13
#define S31 3
#define S32 9
#define S33 11
#define S34 15

static void MD4_update_old (MD4_CTX *context, const BYTE *input, unsigned int inputLen);
static void MD4_final_old (MD4_CTX *context);
static void MD4_Transform (unsigned int [4], const BYTE [64]);
static void Encode (BYTE *, unsigned int *, unsigned int);
static void Decode (unsigned int *, const BYTE *, unsigned int);

static BYTE PADDING[64] = {
  0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/* F, G and H are basic MD4 functions.
 */
#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))

/* ROTATE_LEFT rotates x left n bits.
 */
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

/* FF, GG and HH are transformations for rounds 1, 2 and 3 */
/* Rotation is separate from addition to prevent recomputation */

#define FF(a, b, c, d, x, s) { \
    (a) += F ((b), (c), (d)) + (x); \
    (a) = ROTATE_LEFT ((a), (s)); \
  }
#define GG(a, b, c, d, x, s) { \
    (a) += G ((b), (c), (d)) + (x) + (unsigned int)0x5a827999; \
    (a) = ROTATE_LEFT ((a), (s)); \
  }
#define HH(a, b, c, d, x, s) { \
    (a) += H ((b), (c), (d)) + (x) + (unsigned int)0x6ed9eba1; \
    (a) = ROTATE_LEFT ((a), (s)); \
  }

/* MD4 initialization. Begins an MD4 operation, writing a new context.
 */

HashReturn MD4_init (hashState  *state, int hashbitlen)
{
	/* verify correct hash length	*/
	if (hashbitlen != HASH_BITLENGTH_MD4)
		return BAD_HASHBITLEN;

	/* allocate context and fill it	*/
	MD4_CTX *context = (MD4_CTX *)malloc (sizeof (MD4_CTX));
	memset (context, 0, sizeof (MD4_CTX));
	context->hashbitlen = HASH_BITLENGTH_MD4;
	context->magic = HASH_MAGIC_MD4;

	/* Load magic initialization constants.
	*/
	context->state[0] = 0x67452301;
	context->state[1] = 0xefcdab89;
	context->state[2] = 0x98badcfe;
	context->state[3] = 0x10325476;
	*state = (hashState *) context;
	return SUCCESS;
}

/* MD4 block update operation. Continues an MD4 message-digest
     operation, processing another message block, and updating the
     context.
 */
HashReturn 	MD4_update (
	hashState state, 			/* previously initialized context */
	const BitSequence *buffer, 	/* bit buffer, first bit is MSB in [0] */
	DataLength databitlen)		/* number of bits to process from buffer */
{	
	/* can be called once or many times */
	/* verify correct hashbitlen and magic	*/

	MD4_CTX *context = (MD4_CTX *) state;
	if (context->hashbitlen != HASH_BITLENGTH_MD4)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_MD4)
		return BAD_ALGORITHM;

    /* check for byte alignment */
    if ((databitlen & 0x7)) {
        return FAIL;
    }

    MD4_update_old (context, buffer, (unsigned int)(databitlen>>3));
    context->total_count += databitlen;
    return SUCCESS;
}

/* MD4 finalization. Ends an MD4 message-digest operation, writing the
     the message digest and zeroizing the context.
 */

HashReturn	MD4_final (hashState state, BitSequence *hashval)
{	/*	does padding of last block	*/
	MD4_CTX *context = (MD4_CTX *) state;
	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_MD4)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_MD4)
		return BAD_ALGORITHM;

	MD4_final_old (context);

	if (hashval)
		memcpy (hashval, context->out, HASH_LENGTH_MD4);
	return SUCCESS;
}

/* MD4 block update operation. Continues an MD4 message-digest
     operation, processing another message block, and updating the
     context.
 */
static void MD4_update_old (MD4_CTX *context, const BYTE *input, unsigned int inputLen)
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
		MD4_Transform (context->state, context->buffer);

		for (i = partLen; i + 63 < inputLen; i += 64)
			MD4_Transform (context->state, &input[i]);

		index = 0;
	}
	else
		i = 0;

	/* Buffer remaining input */
	memcpy ((BYTE *)&context->buffer[index], (BYTE *)&input[i], inputLen-i);
}

/* MD4 finalization. Ends an MD4 message-digest operation, writing the
     the message digest and zeroizing the context.
 */
static void MD4_final_old (MD4_CTX *context)
{
	BYTE bits[8];
	unsigned int index, padLen;

	/* Save number of bits */
	Encode (bits, context->count, 8);

	/* Pad out to 56 mod 64.
	*/
	index = (unsigned int)((context->count[0] >> 3) & 0x3f);
	padLen = (index < 56) ? (56 - index) : (120 - index);
	MD4_update_old (context, PADDING, padLen);

	/* Append length (before padding) */
	MD4_update_old (context, bits, 8);
	/* Store state in digest */
	Encode (context->out, context->state, 16);

}

/* MD4 basic transformation. Transforms state based on block.
 */
static void MD4_Transform (unsigned int state[4], const BYTE block[64])
{
	unsigned int a = state[0], b = state[1], c = state[2], d = state[3], x[16];

	Decode (x, block, 64);

	/* Round 1 */
	FF (a, b, c, d, x[ 0], S11); /* 1 */
	FF (d, a, b, c, x[ 1], S12); /* 2 */
	FF (c, d, a, b, x[ 2], S13); /* 3 */
	FF (b, c, d, a, x[ 3], S14); /* 4 */
	FF (a, b, c, d, x[ 4], S11); /* 5 */
	FF (d, a, b, c, x[ 5], S12); /* 6 */
	FF (c, d, a, b, x[ 6], S13); /* 7 */
	FF (b, c, d, a, x[ 7], S14); /* 8 */
	FF (a, b, c, d, x[ 8], S11); /* 9 */
	FF (d, a, b, c, x[ 9], S12); /* 10 */
	FF (c, d, a, b, x[10], S13); /* 11 */
	FF (b, c, d, a, x[11], S14); /* 12 */
	FF (a, b, c, d, x[12], S11); /* 13 */
	FF (d, a, b, c, x[13], S12); /* 14 */
	FF (c, d, a, b, x[14], S13); /* 15 */
	FF (b, c, d, a, x[15], S14); /* 16 */

	/* Round 2 */
	GG (a, b, c, d, x[ 0], S21); /* 17 */
	GG (d, a, b, c, x[ 4], S22); /* 18 */
	GG (c, d, a, b, x[ 8], S23); /* 19 */
	GG (b, c, d, a, x[12], S24); /* 20 */
	GG (a, b, c, d, x[ 1], S21); /* 21 */
	GG (d, a, b, c, x[ 5], S22); /* 22 */
	GG (c, d, a, b, x[ 9], S23); /* 23 */
	GG (b, c, d, a, x[13], S24); /* 24 */
	GG (a, b, c, d, x[ 2], S21); /* 25 */
	GG (d, a, b, c, x[ 6], S22); /* 26 */
	GG (c, d, a, b, x[10], S23); /* 27 */
	GG (b, c, d, a, x[14], S24); /* 28 */
	GG (a, b, c, d, x[ 3], S21); /* 29 */
	GG (d, a, b, c, x[ 7], S22); /* 30 */
	GG (c, d, a, b, x[11], S23); /* 31 */
	GG (b, c, d, a, x[15], S24); /* 32 */

	/* Round 3 */
	HH (a, b, c, d, x[ 0], S31); /* 33 */
	HH (d, a, b, c, x[ 8], S32); /* 34 */
	HH (c, d, a, b, x[ 4], S33); /* 35 */
	HH (b, c, d, a, x[12], S34); /* 36 */
	HH (a, b, c, d, x[ 2], S31); /* 37 */
	HH (d, a, b, c, x[10], S32); /* 38 */
	HH (c, d, a, b, x[ 6], S33); /* 39 */
	HH (b, c, d, a, x[14], S34); /* 40 */
	HH (a, b, c, d, x[ 1], S31); /* 41 */
	HH (d, a, b, c, x[ 9], S32); /* 42 */
	HH (c, d, a, b, x[ 5], S33); /* 43 */
	HH (b, c, d, a, x[13], S34); /* 44 */
	HH (a, b, c, d, x[ 3], S31); /* 45 */
	HH (d, a, b, c, x[11], S32); /* 46 */
	HH (c, d, a, b, x[ 7], S33); /* 47 */
	HH (b, c, d, a, x[15], S34); /* 48 */

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

HashReturn MD4_File (hashState state, FILE *in)
{
	MD4_CTX *context = (MD4_CTX *) state;
	int len;
	unsigned char buffer[BUFFERSIZE];
	HashReturn retval;

	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_MD4)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_MD4)
		return BAD_ALGORITHM;

	while ((len = fread (buffer, 1, BUFFERSIZE, in))) {
		retval = MD4_update (context, buffer, (DataLength)len << 3);
		if (retval != SUCCESS) return retval;
	}
	retval = MD4_final (context, NULL);

	fclose (in);
	return retval;
}

HashReturn MD4_HashToByte (hashState state, BYTE *out) 
{
	MD4_CTX *context = (MD4_CTX *) state;

	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_MD4)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_MD4)
		return BAD_ALGORITHM;

	memcpy (out, context->out, HASH_LENGTH_MD4);
	return SUCCESS;
}

/* all-in-one hash function as required by SHA3-C-API */

HashReturn MD4_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval) 
{
	hashState	state;
	HashReturn	retval;
	
	retval = MD4_init (&state, HASH_BITLENGTH_MD4);
	//HashReturn MD4_init (hashState  *state, int hashbitlen)
	if (retval != SUCCESS) {
		fprintf (stderr, "MD4_init failed, reason %d, hash length %d\n",
                 retval, HASH_BITLENGTH_MD4);
        exit (1);
    }

	retval = MD4_update (state, data, databitlen);
	if (retval != SUCCESS) {
		fprintf (stderr, "MD4_update failed, reason %d\n", retval);
        exit (1);
    }

	retval = MD4_final (state, hashval);
	if (retval != SUCCESS) {
		fprintf (stderr, "MD4_final failed, reason %d\n", retval);
        exit (1);
    }
	free (state);
 	return retval;
}

