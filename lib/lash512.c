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

// lash-512.c
// implements the LASH-512 algorithm
//
// hvf 19.10.2008
// hvf 10.11.2008 cond.compilation for the 3 memory models 
// LASH-SMALL, LASH_MEDIUM, LASH_LARGE
// hvf 19.01.2009 create tables dynamically
//
// hvf 16.02.2009 align with SHA3-C-API
//

#include "lash.h"

BYTE *LASH_A_512;	// [640]
BYTE *LASH_H_512;	// [640][40]
BYTE *LASH_G_512;	// [80][256][40]

// initialize context

HashReturn LASH512_init (hashState  *state, int hashbitlen)
{
	/* verify correct hash length	*/
	if (hashbitlen != HASH_BITLENGTH_LASH512)
		return BAD_HASHBITLEN;

	/* allocate context and fill it	*/
	LASH512_CTX *context = (LASH512_CTX *)malloc (sizeof (LASH512_CTX));
	memset (context, 0, sizeof (LASH512_CTX));
	context->hashbitlen = HASH_BITLENGTH_LASH512;
	context->magic = HASH_MAGIC_LASH512;

	*state = (hashState *) context;
	return SUCCESS;
}

// process one buffer full of data
// will be called more than once from LASH512_final

static void LASH512_transform (LASH512_CTX *context)
{
	// compression function
	
	int i, j, k;
	BYTE b;

	static uint64 totalbytecount = 0;
	
	// keep track of total number of bytes processed
	totalbytecount += HASH_INPUTBUFFER_LASH512;

	// create arrays as required
	// LASH_A_512 is always required
	if (!LASH_A_512) {
		LASH_A_512 = (BYTE *) malloc (HASH_BITVECTORLENGTH_LASH512); 
		if (!LASH_A_512) {
			perror ("malloc LASH_A_512");
			exit (1);
		}
		mk_avector (HASH_BITVECTORLENGTH_LASH512, LASH_A_512);
	}

	// create LASH_H_512
	if (!LASH_H_512 && totalbytecount >= THRESHOLD_1_512) {
		LASH_H_512 = (BYTE *) malloc (HASH_BITVECTORLENGTH_LASH512 *
			HASH_INPUTBUFFER_LASH512); 
		if (!LASH_H_512) {
			perror ("malloc LASH_H_512");
			exit (1);
		}
		//printf ("LASH512_transform: create array H[%d][%d]\n", HASH_BITVECTORLENGTH_LASH512, HASH_INPUTBUFFER_LASH512);
		mk_hvector (HASH_BITVECTORLENGTH_LASH512, HASH_INPUTBUFFER_LASH512, 
			LASH_A_512, LASH_H_512);
	}
	
	// create LASH_G_512
	if (!LASH_G_512 && totalbytecount >= THRESHOLD_2_512) {
		LASH_G_512 = (BYTE *) malloc (HASH_BITVECTORLENGTH_LASH512/8 * 
			256 * HASH_INPUTBUFFER_LASH512); 
		if (!LASH_G_512) {
			perror ("malloc LASH_G_512");
			exit (1);
		}
		mk_gvector (HASH_BITVECTORLENGTH_LASH512, HASH_INPUTBUFFER_LASH512, 
			LASH_H_512, LASH_G_512);
	}
	
	// XOR of r and s
	for (i=0; i<HASH_INPUTBUFFER_LASH512; i++) {
		context->tcomp[i] = context->r[i] ^ context->s[i];
	}

	// LASH_LARGE
	// bytewise substitution with G
	if (LASH_G_512) {
		for (j=0; j<HASH_INPUTBUFFER_LASH512; j++) {
			b = context->r[j];
			for (i=0; i<HASH_INPUTBUFFER_LASH512; i++) {
				context->tcomp[i] += LASH_G_512[addr3(j,b,256,i,
					HASH_INPUTBUFFER_LASH512)];
			}
			b = context->s[j];
			for (i=0; i<HASH_INPUTBUFFER_LASH512; i++) {
				context->tcomp[i] += LASH_G_512[addr3(j+HASH_INPUTBUFFER_LASH512,b,256,i,HASH_INPUTBUFFER_LASH512)];
			}
		}
	}
	else if (LASH_H_512) {
	// LASH_MEDIUM
	// bitwise substitution
		for (j=0; j<2*HASH_INPUTBUFFER_LASH512; j++) {
			if (j<HASH_INPUTBUFFER_LASH512)
				b = context->r[j];
			else
				b = context->s[j-HASH_INPUTBUFFER_LASH512];
	
			for (i=7; i>=0; i--) {
				if ((b>>i) & 0x01) {
					for (k=0; k<HASH_INPUTBUFFER_LASH512; k++) {
						context->tcomp[k] += LASH_H_512[addr2(8*j+7-i,k,
							HASH_INPUTBUFFER_LASH512)];
					}
				}
			}
		}
	}
	else {
	// LASH_SMALL
	// bitwise substitution
		for (j=0; j<2*HASH_INPUTBUFFER_LASH512; j++) {
			if (j<HASH_INPUTBUFFER_LASH512)
				b = context->r[j];
			else
				b = context->s[j-HASH_INPUTBUFFER_LASH512];
	
			for (i=7; i>=0; i--) {
				if ((b>>i) & 0x01) {
					for (k=0; k<HASH_INPUTBUFFER_LASH512; k++) {
						context->tcomp[k] += LASH_A_512[(HASH_BITVECTORLENGTH_LASH512+k-8*j-7+i)%HASH_BITVECTORLENGTH_LASH512];
					}
				}
			}
		}
	}

	// copy tcomp to r
	memcpy (context->r, context->tcomp, HASH_INPUTBUFFER_LASH512);

	// clear s, count
	memset (context->s, 0, HASH_INPUTBUFFER_LASH512);
	context->count = 0;
}

// process a buffer of input data
//
void LASH512_update_old (LASH512_CTX *context, const BYTE *buffer, unsigned int n)
{
	int i, c;
	context->bitcount += n;	// transforming to bits will be done later
	for (i=0; i<n; i++) {
		c = context->count++;
		context->s[c] = buffer[i];
		if (c == HASH_INPUTBUFFER_LASH512-1) {
			LASH512_transform (context); // resets count
		}
	}
}

// terminate and pad the input data, 
// produce the final hash value

void LASH512_final_old (LASH512_CTX *context)
{
	// pad message
	int i;
	BYTE padbuffer[HASH_INPUTBUFFER_LASH512];
	padbuffer[0] = 0x80;
	memset (padbuffer+1, 0, HASH_INPUTBUFFER_LASH512-1);
	
	if (context->count == HASH_INPUTBUFFER_LASH512) { // cannot happen
		LASH512_transform (context); // resets count
	}

	// save bitcount - the pad buffer does not add to the msg length
	uint64 save_bitcount = context->bitcount << 3;

	// process padbuffer
	LASH512_update_old (context, padbuffer, 
		HASH_INPUTBUFFER_LASH512 - context->count);

	// process message length in bits 
	
	if (context->count != 0) {
		fprintf (stderr, "LASH512_final: context->count should be 0 after padding, but is %d\n", context->count);
	}
	for (i=0; i<8 && i<HASH_INPUTBUFFER_LASH512; i++) {
		context->s[i] = (save_bitcount >> (8*i)) & 0xff;
	}
	context->count = 8;

	// compress again
		
	LASH512_transform (context); // resets count

	// produce hash
	
	for (i=0; i<HASH_LENGTH_LASH512; i++) {
		context->t[i] = (context->r[i+i] & 0xF0) | 
						((context->r[i+i+1] & 0xF0) >> 4);
	}
}

HashReturn 	LASH512_update (
	hashState state, 			/* previously initialized context */
	const BitSequence *buffer, 	/* bit buffer, first bit is MSB in [0] */
	DataLength databitlen)		/* number of bits to process from buffer */
{	
	/* can be called once or many times */
	/* verify correct hashbitlen and magic	*/

	LASH512_CTX *context = (LASH512_CTX *) state;
	if (context->hashbitlen != HASH_BITLENGTH_LASH512)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_LASH512)
		return BAD_ALGORITHM;

	/* check for byte alignment */
	if ((databitlen & 0x7)) {
		return FAIL;
	}

	LASH512_update_old (context, buffer, (unsigned int)(databitlen>>3));
	return SUCCESS;
}

HashReturn	LASH512_final (hashState state, BitSequence *hashval)
{	/*	does padding of last block	*/
	LASH512_CTX *context = (LASH512_CTX *) state;
	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_LASH512)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_LASH512)
		return BAD_ALGORITHM;

	LASH512_final_old (context);

	if (hashval)
		memcpy (hashval, context->t, HASH_LENGTH_LASH512);
	return SUCCESS;
}

/* LASH512 utility routines
 *
 * hvf 23.1.2000
 * hvf 13.2.01
 * hvf 10.8.01
 * hvf 15.02.2009
 */

/* Digests a file and prints the result.
 */

HashReturn LASH512_File (hashState state, FILE *in)
{
	LASH512_CTX *context = (LASH512_CTX *) state;
	int len;
	unsigned char buffer[BUFFERSIZE];
	HashReturn retval;

	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_LASH512)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_LASH512)
		return BAD_ALGORITHM;

	while ((len = fread (buffer, 1, BUFFERSIZE, in))) {
		retval = LASH512_update (context, buffer, (DataLength)len << 3);
		if (retval != SUCCESS) return retval;
	}
	retval = LASH512_final (context, NULL);

	fclose (in);
	return retval;
}


HashReturn LASH512_HashToByte (hashState state, BYTE *out) 
{
	LASH512_CTX *context = (LASH512_CTX *) state;

	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_LASH512)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_LASH512)
		return BAD_ALGORITHM;

	memcpy (out, context->t, HASH_LENGTH_LASH512);
	return SUCCESS;
}

/* all-in-one hash function as required by SHA3-C-API */

HashReturn LASH512_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval) 
{
	hashState	state;
	HashReturn	retval;
	
	retval = LASH512_init (&state, HASH_BITLENGTH_LASH512);
	if (retval != SUCCESS) {
		fprintf (stderr, "LASH512_init failed, reason %d, hash length %d\n",
                 retval, HASH_BITLENGTH_LASH512);
        exit (1);
    }

	retval = LASH512_update (state, data, databitlen);
	if (retval != SUCCESS) {
		fprintf (stderr, "LASH512_update failed, reason %d\n", retval);
        exit (1);
    }

	retval = LASH512_final (state, hashval);
	if (retval != SUCCESS) {
		fprintf (stderr, "LASH512_final failed, reason %d\n", retval);
        exit (1);
    }
	free (state);
 	return retval;
}

