/* MD2C.C - RSA Data Security, Inc., MD2 message-digest algorithm
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

/* Copyright (C) 1990-2, RSA Data Security, Inc. Created 1990. All
   rights reserved.

   License to copy and use this software is granted for
   non-commercial Internet Privacy-Enhanced Mail provided that it is
   identified as the "RSA Data Security, Inc. MD2 Message Digest
   Algorithm" in all material mentioning or referencing this software
   or this function.

   RSA Data Security, Inc. makes no representations concerning either
   the merchantability of this software or the suitability of this
   software for any particular purpose. It is provided "as is"
   without express or implied warranty of any kind.

   These notices must be retained in any copies of any part of this
   documentation and/or software.
 */

/* integrated into fehashmac - hvf 12.08.01 
 * hvf 10.02.2009 adapt to SHA3-C-API 
 * disabled MD2_Print - hvf 19.04.2015
 */

#include	"mdx.h"
#include	<string.h>
#include	<stdlib.h>
#include	<stdio.h>

#define DEBUG
#undef DEBUG

static void MD2_Transform (BYTE [16], BYTE [16], const BYTE [16]);

/* Permutation of 0..255 constructed from the digits of pi. It gives a
   "random" nonlinear byte substitution operation.
 */
static BYTE PI_SUBST[256] = {
	41, 46, 67, 201, 162, 216, 124, 1, 61, 54, 84, 161, 236, 240, 6,
	19, 98, 167, 5, 243, 192, 199, 115, 140, 152, 147, 43, 217, 188,
	76, 130, 202, 30, 155, 87, 60, 253, 212, 224, 22, 103, 66, 111, 24,
	138, 23, 229, 18, 190, 78, 196, 214, 218, 158, 222, 73, 160, 251,
	245, 142, 187, 47, 238, 122, 169, 104, 121, 145, 21, 178, 7, 63,
	148, 194, 16, 137, 11, 34, 95, 33, 128, 127, 93, 154, 90, 144, 50,
	39, 53, 62, 204, 231, 191, 247, 151, 3, 255, 25, 48, 179, 72, 165,
	181, 209, 215, 94, 146, 42, 172, 86, 170, 198, 79, 184, 56, 210,
	150, 164, 125, 182, 118, 252, 107, 226, 156, 116, 4, 241, 69, 157,
	112, 89, 100, 113, 135, 32, 134, 91, 207, 101, 230, 45, 168, 2, 27,
	96, 37, 173, 174, 176, 185, 246, 28, 70, 97, 105, 52, 64, 126, 15,
	85, 71, 163, 35, 221, 81, 175, 58, 195, 92, 249, 206, 186, 197,
	234, 38, 44, 83, 13, 110, 133, 40, 132, 9, 211, 223, 205, 244, 65,
	129, 77, 82, 106, 220, 55, 200, 108, 193, 171, 250, 36, 225, 123,
	8, 12, 189, 177, 74, 120, 136, 149, 139, 227, 99, 232, 109, 233,
	203, 213, 254, 59, 0, 29, 57, 242, 239, 183, 14, 102, 88, 208, 228,
	166, 119, 114, 248, 235, 117, 75, 10, 49, 68, 80, 180, 143, 237,
	31, 26, 219, 153, 141, 51, 159, 17, 131, 20
};

static BYTE *PADDING[] = {
	(BYTE *)"",
	(BYTE *)"\001",
	(BYTE *)"\002\002",
	(BYTE *)"\003\003\003",
	(BYTE *)"\004\004\004\004",
	(BYTE *)"\005\005\005\005\005",
	(BYTE *)"\006\006\006\006\006\006",
	(BYTE *)"\007\007\007\007\007\007\007",
	(BYTE *)"\010\010\010\010\010\010\010\010",
	(BYTE *)"\011\011\011\011\011\011\011\011\011",
	(BYTE *)"\012\012\012\012\012\012\012\012\012\012",
	(BYTE *)"\013\013\013\013\013\013\013\013\013\013\013",
	(BYTE *)"\014\014\014\014\014\014\014\014\014\014\014\014",
	(BYTE *)
	"\015\015\015\015\015\015\015\015\015\015\015\015\015",
	(BYTE *)
	"\016\016\016\016\016\016\016\016\016\016\016\016\016\016",
	(BYTE *)
	"\017\017\017\017\017\017\017\017\017\017\017\017\017\017\017",
	(BYTE *)
	"\020\020\020\020\020\020\020\020\020\020\020\020\020\020\020\020"
};

void MD2_update_old (MD2_CTX *context, const BYTE *input, unsigned int inputLen);
void MD2_final_old (MD2_CTX *context);

/* MD2 initialization. Begins an MD2 operation, writing a new context.
 */

HashReturn MD2_init (hashState  *state, int hashbitlen)
{
	/* verify correct hash length	*/
	if (hashbitlen != HASH_BITLENGTH_MD2)
		return BAD_HASHBITLEN;

	/* allocate context and fill it	*/
	MD2_CTX *context = (MD2_CTX *)malloc (sizeof (MD2_CTX));
	memset (context, 0, sizeof (MD2_CTX));
	context->hashbitlen = HASH_BITLENGTH_MD2;
	context->magic = HASH_MAGIC_MD2;

	*state = (hashState *) context;
	return SUCCESS;
}

HashReturn 	MD2_update (
	hashState state, 			/* previously initialized context */
	const BitSequence *buffer, 	/* bit buffer, first bit is MSB in [0] */
	DataLength databitlen)		/* number of bits to process from buffer */
{	
	/* can be called once or many times */
	/* verify correct hashbitlen and magic	*/

	MD2_CTX *context = (MD2_CTX *) state;
	if (context->hashbitlen != HASH_BITLENGTH_MD2)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_MD2)
		return BAD_ALGORITHM;

	MD2_update_old (context, buffer, (unsigned int)(databitlen >> 3));

	return SUCCESS;
}

void MD2_update_old (MD2_CTX *context, const BYTE *input, unsigned int inputLen)
{	/* can be called once or many times	*/
	unsigned int i, index, partLen;

	/* Update number of bytes mod 16 */
	index = context->count;
	context->count = (index + inputLen) & 0xf;

	partLen = 16 - index;

	/* Transform as many times as possible.
	*/
	if (inputLen >= partLen) {
		memcpy ((BYTE *)&context->buffer[index], (BYTE *)input, partLen);
		MD2_Transform (context->state, context->checksum, context->buffer);

		for (i = partLen; i + 15 < inputLen; i += 16)
		  MD2_Transform (context->state, context->checksum, &input[i]);

		index = 0;
	}
	else
		i = 0;

	/* Buffer remaining input */
	memcpy ((BYTE *)&context->buffer[index], (BYTE *)&input[i], inputLen-i);
}

HashReturn	MD2_final (hashState state, BitSequence *hashval)
{	/*	does padding of last block	*/
	MD2_CTX *context = (MD2_CTX *) state;
	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_MD2)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_MD2)
		return BAD_ALGORITHM;

	MD2_final_old (context);

	if (hashval)
		memcpy (hashval, context->out, HASH_LENGTH_MD2);
	return SUCCESS;
}

void MD2_final_old (MD2_CTX *context)
{	/* does padding of last block	*/
	unsigned int index, padLen;

	/* Pad out to multiple of 16.
	*/
	index = context->count;
	padLen = 16 - index;
	MD2_update_old (context, PADDING[padLen], padLen);

	/* Extend with checksum */
	MD2_update_old (context, context->checksum, 16);

	/* Store state in digest */
	memcpy (context->out, context->state, 16);

}

/* MD2 basic transformation. Transforms state and updates checksum
     based on block.
 */
static void MD2_Transform (BYTE state[16], BYTE checksum[16], const BYTE block[16])
{
	unsigned int i, j, t;
	BYTE x[48];

#ifdef DEBUG
	for (i=0; i<16; i++)
		printf ("W[%d] = %2.2x\n", i, block[i]);
#endif

	/* Form encryption block from state, block, state ^ block.
	*/
	memcpy ((BYTE *)x, (BYTE *)state, 16);
	memcpy ((BYTE *)x+16, (BYTE *)block, 16);
	for (i = 0; i < 16; i++)
		x[i+32] = state[i] ^ block[i];

	/* Encrypt block (18 rounds).
	*/
	t = 0;
	for (i = 0; i < 18; i++) {
		for (j = 0; j < 48; j++)
			t = x[j] ^= PI_SUBST[t];
		t = (t + i) & 0xff;
	}

	/* Save new state */
	memcpy ((BYTE *)state, (BYTE *)x, 16);

	/* Update checksum.
	*/
	t = checksum[15];
	for (i = 0; i < 16; i++)
		t = checksum[i] ^= PI_SUBST[block[i] ^ t];

	/* Zeroize sensitive information.
	*/
	memset ((BYTE *)x, 0, sizeof (x));
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

HashReturn MD2_File (hashState state, FILE *in)
{
	MD2_CTX *context = (MD2_CTX *) state;
	int len;
	unsigned char buffer[BUFFERSIZE];
	HashReturn retval;

	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_MD2)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_MD2)
		return BAD_ALGORITHM;

	while ((len = fread (buffer, 1, BUFFERSIZE, in))) {
		retval = MD2_update (context, buffer, (DataLength)len << 3);
		if (retval != SUCCESS) return retval;
	}
	retval = MD2_final (context, NULL);

	fclose (in);
	return retval;
}

HashReturn MD2_HashToByte (hashState state, BYTE *out) 
{
	MD2_CTX *context = (MD2_CTX *) state;

	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_MD2)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_MD2)
		return BAD_ALGORITHM;

	memcpy (out, context->out, HASH_LENGTH_MD2);
	return SUCCESS;
}

/* all-in-one hash function as required by SHA3-C-API */

HashReturn MD2_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval) 
{
	hashState	state;
	HashReturn	retval;
	
	retval = MD2_init (&state, HASH_BITLENGTH_MD2);
	//HashReturn MD2_init (hashState  *state, int hashbitlen)
	if (retval != SUCCESS) {
		fprintf (stderr, "MD2_init failed, reason %d, hash length %d\n",
                 retval, HASH_BITLENGTH_MD2);
        exit (1);
    }

	retval = MD2_update (state, data, databitlen);
	if (retval != SUCCESS) {
		fprintf (stderr, "MD2_update failed, reason %d\n", retval);
        exit (1);
    }

	retval = MD2_final (state, hashval);
	if (retval != SUCCESS) {
		fprintf (stderr, "MD2_final failed, reason %d\n", retval);
        exit (1);
    }
	free (state);
 	return retval;
}

