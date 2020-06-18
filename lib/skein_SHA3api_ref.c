/*
 * Generic Hash and HMAC Program
 *
 * Copyright (C) 2009 2011 Harald von Fellenberg <hvf@hvf.ch>
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

/*
 * The files 
 * skein_block.c  skein.c  skein_SHA3api_ref.c 
 * skein.h  skein_iv.h  skein_port.h  skein_SHA3api_ref.h
 * have been taken from the Skein submission to the SHA3 contest, see
 * http://csrc.nist.gov/groups/ST/hash/sha-3/Round3/submissions_rnd3.html
 * The Skein homepage is http://www.skein-hash.info/
 * The authors of Skein are
 * Niels Ferguson (Microsoft Corp.)
 * Stefan Lucks (Bauhaus-Universität Weimar)
 * Bruce Schneier (BT Group plc)
 * Doug Whiting (Hifn, Inc.)
 * Mihir Bellare (University of California San Diego)
 * Tadayoshi Kohno (University of Washington)
 * Jon Callas (PGP Corp.)
 * Jesse Walker (Intel Corp.)
 *
 * integration into fehashmac by hvf 11.04.2011
 * hvf 01.09.2011 correct error in SKEIN_Final()
 * disabled SKEINxxx_Print - hvf 19.04.2015
 */

/***********************************************************************
**
** Implementation of the AHS API using the Skein hash function.
**
** Source code author: Doug Whiting, 2008.
**
** This algorithm and source code is released to the public domain.
** 
************************************************************************/

#include <string.h>     /* get the memcpy/memset functions */
#include "skein.h"      /* get the Skein API definitions   */
#include "skein_SHA3api_ref.h"/* get the  AHS  API definitions   */

/******************************************************************/
/*     AHS API code                                               */
/******************************************************************/

/*++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
/* select the context size and init the context */
HashReturn SKEIN_Init(SKEIN_CTX *state, int hashbitlen)
    {
#if SKEIN_256_NIST_MAX_HASH_BITS
    if (hashbitlen <= SKEIN_256_NIST_MAX_HASHBITS)
        {
        Skein_Assert(hashbitlen > 0,BAD_HASHLEN);
        state->statebits = 64*SKEIN_256_STATE_WORDS;	/* 256	*/
        return Skein_256_Init(&state->u.ctx_256,(size_t) hashbitlen);
        }
#endif
    if (hashbitlen <= SKEIN_512_NIST_MAX_HASHBITS)
        {
        state->statebits = 64*SKEIN_512_STATE_WORDS;	/* 512	*/
        return Skein_512_Init(&state->u.ctx_512,(size_t) hashbitlen);
        }
    else
        {
        state->statebits = 64*SKEIN1024_STATE_WORDS;	/* 1024	*/
        return Skein1024_Init(&state->u.ctx1024,(size_t) hashbitlen);
        }
    }

/*++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
/* process data to be hashed */
HashReturn SKEIN_Update(SKEIN_CTX *state, const BitSequence *data, DataLength databitlen)
    {
    /* only the final Update() call is allowed do partial bytes, else assert an error */
    Skein_Assert((state->u.h.T[1] & SKEIN_T1_FLAG_BIT_PAD) == 0 || databitlen == 0, FAIL);

    Skein_Assert(state->statebits % 256 == 0 && (state->statebits-256) < 1024,FAIL);
    if ((databitlen & 7) == 0)  /* partial bytes? */
        {
        switch ((state->statebits >> 8) & 3)
            {
            case 2:  return Skein_512_Update(&state->u.ctx_512,data,databitlen >> 3);
            case 1:  return Skein_256_Update(&state->u.ctx_256,data,databitlen >> 3);
            case 0:  return Skein1024_Update(&state->u.ctx1024,data,databitlen >> 3);
            default: return FAIL;
            }
        }
    else
        {   /* handle partial final byte */
        size_t bCnt = (databitlen >> 3) + 1;                  /* number of bytes to handle (nonzero here!) */
        u08b_t b,mask;

        mask = (u08b_t) (1u << (7 - (databitlen & 7)));       /* partial byte bit mask */
        b    = (u08b_t) ((data[bCnt-1] & (0-mask)) | mask);   /* apply bit padding on final byte */

        switch ((state->statebits >> 8) & 3)
            {
            case 2:  Skein_512_Update(&state->u.ctx_512,data,bCnt-1); /* process all but the final byte    */
                     Skein_512_Update(&state->u.ctx_512,&b  ,  1   ); /* process the (masked) partial byte */
                     break;
            case 1:  Skein_256_Update(&state->u.ctx_256,data,bCnt-1); /* process all but the final byte    */
                     Skein_256_Update(&state->u.ctx_256,&b  ,  1   ); /* process the (masked) partial byte */
                     break;
            case 0:  Skein1024_Update(&state->u.ctx1024,data,bCnt-1); /* process all but the final byte    */
                     Skein1024_Update(&state->u.ctx1024,&b  ,  1   ); /* process the (masked) partial byte */
                     break;
            default: return FAIL;
            }
        Skein_Set_Bit_Pad_Flag(state->u.h);                    /* set tweak flag for the final call */
        
        return SUCCESS;
        }
    }

/*++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
/* finalize hash computation and output the result (hashbitlen bits) */
HashReturn SKEIN_Final(SKEIN_CTX *state, BitSequence *hashval)
    {
	HashReturn ret;
    Skein_Assert(state->statebits % 256 == 0 && (state->statebits-256) < 1024,FAIL);
    switch ((state->statebits >> 8) & 3)
        {
        case 2:  ret = Skein_512_Final(&state->u.ctx_512,state->out); break;
        case 1:  ret = Skein_256_Final(&state->u.ctx_256,state->out); break;
        case 0:  ret = Skein1024_Final(&state->u.ctx1024,state->out); break;
        default: return FAIL;
        }
		if (hashval)
			memcpy (hashval, state->out, state->hashbitlen>>3);
		return ret;
    }

/*++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
/* all-in-one hash function */
HashReturn SKEIN_Hash(int hashbitlen, const BitSequence *data, /* all-in-one call */
                DataLength databitlen,BitSequence *hashval)
    {
    SKEIN_CTX  state;
    HashReturn r = SKEIN_Init(&state,hashbitlen);
    if (r == SUCCESS)
        { /* these calls do not fail when called properly */
        r = SKEIN_Update(&state,data,databitlen);
        SKEIN_Final(&state,hashval);
        }
    return r;
    }



/* 
 * parameter safe wrappers for SKEIN routines for each hash length
 */

 /*************************** 224 ************************************/

HashReturn SKEIN224_init (hashState  *state, int hashbitlen)
{
    /* verify correct hash length   */
    if (hashbitlen != HASH_BITLENGTH_SKEIN_224)
        return BAD_HASHBITLEN;

    /* allocate context and fill it */
    SKEIN_CTX *context = (SKEIN_CTX *)malloc (sizeof (SKEIN_CTX));
    memset (context, 0, sizeof (SKEIN_CTX));
    context->hashbitlen = HASH_BITLENGTH_SKEIN_224;
    context->magic = HASH_MAGIC_SKEIN_224;
	*state = (hashState *) context;
	return SKEIN_Init (context, hashbitlen);
}

HashReturn  SKEIN224_update (
    hashState state,          /* previously initialized context */
    const BitSequence *buffer,  /* bit buffer, first bit is MSB in [0] */
    DataLength databitlen)      /* number of bits to process from buffer */
{
    /* can be called once or many times */
    /* verify correct hashbitlen and magic  */

    SKEIN_CTX *context = (SKEIN_CTX *) state;
    if (context->hashbitlen != HASH_BITLENGTH_SKEIN_224)
        return BAD_HASHBITLEN;

    if (context->magic != HASH_MAGIC_SKEIN_224)
        return BAD_ALGORITHM;

	return SKEIN_Update (context, buffer, databitlen);
}

HashReturn  SKEIN224_final (hashState state, BitSequence *hashval)
{
    SKEIN_CTX *context = (SKEIN_CTX *) state;
    if (context->hashbitlen != HASH_BITLENGTH_SKEIN_224)
        return BAD_HASHBITLEN;

    if (context->magic != HASH_MAGIC_SKEIN_224)
        return BAD_ALGORITHM;

	return SKEIN_Final (context, hashval);
}

HashReturn SKEIN224_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval)
{
    hashState   state;
    HashReturn  retval;

    retval = SKEIN224_init (&state, HASH_BITLENGTH_SKEIN_224);
    if (retval != SUCCESS) {
        fprintf (stderr, "SKEIN224_init failed, reason %d, hash length %d\n",
                 retval, HASH_BITLENGTH_SKEIN_224);
        exit (1);
    }

    retval = SKEIN224_update (state, data, databitlen);
    if (retval != SUCCESS) {
        fprintf (stderr, "SKEIN224_update failed, reason %d\n", retval);
        exit (1);
    }

    retval = SKEIN224_final (state, hashval);
    if (retval != SUCCESS) {
        fprintf (stderr, "SKEIN224_final failed, reason %d\n", retval);
        exit (1);
    }
    free (state);
    return retval;
}

/*
 * three functions in MD5 style for each hash length
 */

/* Digests a file and prints the result.
 */
HashReturn SKEIN224_File (hashState state, FILE *in)
{
	SKEIN_CTX *context = (SKEIN_CTX *) state;
	int len;
	unsigned char buffer[BUFFERSIZE];
	HashReturn retval;

	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_SKEIN_224)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_SKEIN_224)
		return BAD_ALGORITHM;

	while ((len = fread (buffer, 1, BUFFERSIZE, in))) {
		retval = SKEIN224_update (context, buffer, (DataLength)len << 3);
		if (retval != SUCCESS) return retval;
	}
	retval = SKEIN224_final (context, NULL);

	fclose (in);
	return retval;
}

HashReturn SKEIN224_HashToByte (hashState state, BYTE *out) 
{
	SKEIN_CTX *context = (SKEIN_CTX *) state;

	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_SKEIN_224)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_SKEIN_224)
		return BAD_ALGORITHM;

	memcpy (out, context->out, HASH_LENGTH_SKEIN_224);
	return SUCCESS;
}


 /*************************** 256 ************************************/

HashReturn SKEIN256_init (hashState  *state, int hashbitlen)
{
    /* verify correct hash length   */
    if (hashbitlen != HASH_BITLENGTH_SKEIN_256)
        return BAD_HASHBITLEN;

    /* allocate context and fill it */
    SKEIN_CTX *context = (SKEIN_CTX *)malloc (sizeof (SKEIN_CTX));
    memset (context, 0, sizeof (SKEIN_CTX));
    context->hashbitlen = HASH_BITLENGTH_SKEIN_256;
    context->magic = HASH_MAGIC_SKEIN_256;
	*state = (hashState *) context;
	return SKEIN_Init (context, hashbitlen);
}

HashReturn  SKEIN256_update (
    hashState state,          /* previously initialized context */
    const BitSequence *buffer,  /* bit buffer, first bit is MSB in [0] */
    DataLength databitlen)      /* number of bits to process from buffer */
{
    /* can be called once or many times */
    /* verify correct hashbitlen and magic  */

    SKEIN_CTX *context = (SKEIN_CTX *) state;
    if (context->hashbitlen != HASH_BITLENGTH_SKEIN_256)
        return BAD_HASHBITLEN;

    if (context->magic != HASH_MAGIC_SKEIN_256)
        return BAD_ALGORITHM;

	return SKEIN_Update (context, buffer, databitlen);
}

HashReturn  SKEIN256_final (hashState state, BitSequence *hashval)
{
    SKEIN_CTX *context = (SKEIN_CTX *) state;
    if (context->hashbitlen != HASH_BITLENGTH_SKEIN_256)
        return BAD_HASHBITLEN;

    if (context->magic != HASH_MAGIC_SKEIN_256)
        return BAD_ALGORITHM;

	return SKEIN_Final (context, hashval);
}

HashReturn SKEIN256_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval)
{
    hashState   state;
    HashReturn  retval;

    retval = SKEIN256_init (&state, HASH_BITLENGTH_SKEIN_256);
    if (retval != SUCCESS) {
        fprintf (stderr, "SKEIN256_init failed, reason %d, hash length %d\n",
                 retval, HASH_BITLENGTH_SKEIN_256);
        exit (1);
    }

    retval = SKEIN256_update (state, data, databitlen);
    if (retval != SUCCESS) {
        fprintf (stderr, "SKEIN256_update failed, reason %d\n", retval);
        exit (1);
    }

    retval = SKEIN256_final (state, hashval);
    if (retval != SUCCESS) {
        fprintf (stderr, "SKEIN256_final failed, reason %d\n", retval);
        exit (1);
    }
    free (state);
    return retval;
}

/*
 * three functions in MD5 style for each hash length
 */

/* Digests a file and prints the result.
 */
HashReturn SKEIN256_File (hashState state, FILE *in)
{
	SKEIN_CTX *context = (SKEIN_CTX *) state;
	int len;
	unsigned char buffer[BUFFERSIZE];
	HashReturn retval;

	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_SKEIN_256)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_SKEIN_256)
		return BAD_ALGORITHM;

	while ((len = fread (buffer, 1, BUFFERSIZE, in))) {
		retval = SKEIN256_update (context, buffer, (DataLength)len << 3);
		if (retval != SUCCESS) return retval;
	}
	retval = SKEIN256_final (context, NULL);

	fclose (in);
	return retval;
}

HashReturn SKEIN256_HashToByte (hashState state, BYTE *out) 
{
	SKEIN_CTX *context = (SKEIN_CTX *) state;

	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_SKEIN_256)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_SKEIN_256)
		return BAD_ALGORITHM;

	memcpy (out, context->out, HASH_LENGTH_SKEIN_256);
	return SUCCESS;
}


 /*************************** 384 ************************************/

HashReturn SKEIN384_init (hashState  *state, int hashbitlen)
{
    /* verify correct hash length   */
    if (hashbitlen != HASH_BITLENGTH_SKEIN_384)
        return BAD_HASHBITLEN;

    /* allocate context and fill it */
    SKEIN_CTX *context = (SKEIN_CTX *)malloc (sizeof (SKEIN_CTX));
    memset (context, 0, sizeof (SKEIN_CTX));
    context->hashbitlen = HASH_BITLENGTH_SKEIN_384;
    context->magic = HASH_MAGIC_SKEIN_384;
	*state = (hashState *) context;
	return SKEIN_Init (context, hashbitlen);
}

HashReturn  SKEIN384_update (
    hashState state,          /* previously initialized context */
    const BitSequence *buffer,  /* bit buffer, first bit is MSB in [0] */
    DataLength databitlen)      /* number of bits to process from buffer */
{
    /* can be called once or many times */
    /* verify correct hashbitlen and magic  */

    SKEIN_CTX *context = (SKEIN_CTX *) state;
    if (context->hashbitlen != HASH_BITLENGTH_SKEIN_384)
        return BAD_HASHBITLEN;

    if (context->magic != HASH_MAGIC_SKEIN_384)
        return BAD_ALGORITHM;

	return SKEIN_Update (context, buffer, databitlen);
}

HashReturn  SKEIN384_final (hashState state, BitSequence *hashval)
{
    SKEIN_CTX *context = (SKEIN_CTX *) state;
    if (context->hashbitlen != HASH_BITLENGTH_SKEIN_384)
        return BAD_HASHBITLEN;

    if (context->magic != HASH_MAGIC_SKEIN_384)
        return BAD_ALGORITHM;

	return SKEIN_Final (context, hashval);
}

HashReturn SKEIN384_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval)
{
    hashState   state;
    HashReturn  retval;

    retval = SKEIN384_init (&state, HASH_BITLENGTH_SKEIN_384);
    if (retval != SUCCESS) {
        fprintf (stderr, "SKEIN384_init failed, reason %d, hash length %d\n",
                 retval, HASH_BITLENGTH_SKEIN_384);
        exit (1);
    }

    retval = SKEIN384_update (state, data, databitlen);
    if (retval != SUCCESS) {
        fprintf (stderr, "SKEIN384_update failed, reason %d\n", retval);
        exit (1);
    }

    retval = SKEIN384_final (state, hashval);
    if (retval != SUCCESS) {
        fprintf (stderr, "SKEIN384_final failed, reason %d\n", retval);
        exit (1);
    }
    free (state);
    return retval;
}

/*
 * three functions in MD5 style for each hash length
 */

/* Digests a file and prints the result.
 */
HashReturn SKEIN384_File (hashState state, FILE *in)
{
	SKEIN_CTX *context = (SKEIN_CTX *) state;
	int len;
	unsigned char buffer[BUFFERSIZE];
	HashReturn retval;

	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_SKEIN_384)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_SKEIN_384)
		return BAD_ALGORITHM;

	while ((len = fread (buffer, 1, BUFFERSIZE, in))) {
		retval = SKEIN384_update (context, buffer, (DataLength)len << 3);
		if (retval != SUCCESS) return retval;
	}
	retval = SKEIN384_final (context, NULL);

	fclose (in);
	return retval;
}

HashReturn SKEIN384_HashToByte (hashState state, BYTE *out) 
{
	SKEIN_CTX *context = (SKEIN_CTX *) state;

	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_SKEIN_384)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_SKEIN_384)
		return BAD_ALGORITHM;

	memcpy (out, context->out, HASH_LENGTH_SKEIN_384);
	return SUCCESS;
}


 /*************************** 512 ************************************/

HashReturn SKEIN512_init (hashState  *state, int hashbitlen)
{
    /* verify correct hash length   */
    if (hashbitlen != HASH_BITLENGTH_SKEIN_512)
        return BAD_HASHBITLEN;

    /* allocate context and fill it */
    SKEIN_CTX *context = (SKEIN_CTX *)malloc (sizeof (SKEIN_CTX));
    memset (context, 0, sizeof (SKEIN_CTX));
    context->hashbitlen = HASH_BITLENGTH_SKEIN_512;
    context->magic = HASH_MAGIC_SKEIN_512;
	*state = (hashState *) context;
	return SKEIN_Init (context, hashbitlen);
}

HashReturn  SKEIN512_update (
    hashState state,          /* previously initialized context */
    const BitSequence *buffer,  /* bit buffer, first bit is MSB in [0] */
    DataLength databitlen)      /* number of bits to process from buffer */
{
    /* can be called once or many times */
    /* verify correct hashbitlen and magic  */

    SKEIN_CTX *context = (SKEIN_CTX *) state;
    if (context->hashbitlen != HASH_BITLENGTH_SKEIN_512)
        return BAD_HASHBITLEN;

    if (context->magic != HASH_MAGIC_SKEIN_512)
        return BAD_ALGORITHM;

	return SKEIN_Update (context, buffer, databitlen);
}

HashReturn  SKEIN512_final (hashState state, BitSequence *hashval)
{
    SKEIN_CTX *context = (SKEIN_CTX *) state;
    if (context->hashbitlen != HASH_BITLENGTH_SKEIN_512)
        return BAD_HASHBITLEN;

    if (context->magic != HASH_MAGIC_SKEIN_512)
        return BAD_ALGORITHM;

	return SKEIN_Final (context, hashval);
}

HashReturn SKEIN512_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval)
{
    hashState   state;
    HashReturn  retval;

    retval = SKEIN512_init (&state, HASH_BITLENGTH_SKEIN_512);
    if (retval != SUCCESS) {
        fprintf (stderr, "SKEIN512_init failed, reason %d, hash length %d\n",
                 retval, HASH_BITLENGTH_SKEIN_512);
        exit (1);
    }

    retval = SKEIN512_update (state, data, databitlen);
    if (retval != SUCCESS) {
        fprintf (stderr, "SKEIN512_update failed, reason %d\n", retval);
        exit (1);
    }

    retval = SKEIN512_final (state, hashval);
    if (retval != SUCCESS) {
        fprintf (stderr, "SKEIN512_final failed, reason %d\n", retval);
        exit (1);
    }
    free (state);
    return retval;
}

/*
 * three functions in MD5 style for each hash length
 */

/* Digests a file and prints the result.
 */
HashReturn SKEIN512_File (hashState state, FILE *in)
{
	SKEIN_CTX *context = (SKEIN_CTX *) state;
	int len;
	unsigned char buffer[BUFFERSIZE];
	HashReturn retval;

	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_SKEIN_512)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_SKEIN_512)
		return BAD_ALGORITHM;

	while ((len = fread (buffer, 1, BUFFERSIZE, in))) {
		retval = SKEIN512_update (context, buffer, (DataLength)len << 3);
		if (retval != SUCCESS) return retval;
	}
	retval = SKEIN512_final (context, NULL);

	fclose (in);
	return retval;
}

HashReturn SKEIN512_HashToByte (hashState state, BYTE *out) 
{
	SKEIN_CTX *context = (SKEIN_CTX *) state;

	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_SKEIN_512)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_SKEIN_512)
		return BAD_ALGORITHM;

	memcpy (out, context->out, HASH_LENGTH_SKEIN_512);
	return SUCCESS;
}

 /*************************** 1024 ************************************/

HashReturn SKEIN1024_init (hashState  *state, int hashbitlen)
{
    /* verify correct hash length   */
    if (hashbitlen != HASH_BITLENGTH_SKEIN_1024)
        return BAD_HASHBITLEN;

    /* allocate context and fill it */
    SKEIN_CTX *context = (SKEIN_CTX *)malloc (sizeof (SKEIN_CTX));
    memset (context, 0, sizeof (SKEIN_CTX));
    context->hashbitlen = HASH_BITLENGTH_SKEIN_1024;
    context->magic = HASH_MAGIC_SKEIN_1024;
	*state = (hashState *) context;
	return SKEIN_Init (context, hashbitlen);
}

HashReturn  SKEIN1024_update (
    hashState state,          /* previously initialized context */
    const BitSequence *buffer,  /* bit buffer, first bit is MSB in [0] */
    DataLength databitlen)      /* number of bits to process from buffer */
{
    /* can be called once or many times */
    /* verify correct hashbitlen and magic  */

    SKEIN_CTX *context = (SKEIN_CTX *) state;
    if (context->hashbitlen != HASH_BITLENGTH_SKEIN_1024)
        return BAD_HASHBITLEN;

    if (context->magic != HASH_MAGIC_SKEIN_1024)
        return BAD_ALGORITHM;

	return SKEIN_Update (context, buffer, databitlen);
}

HashReturn  SKEIN1024_final (hashState state, BitSequence *hashval)
{
    SKEIN_CTX *context = (SKEIN_CTX *) state;
    if (context->hashbitlen != HASH_BITLENGTH_SKEIN_1024)
        return BAD_HASHBITLEN;

    if (context->magic != HASH_MAGIC_SKEIN_1024)
        return BAD_ALGORITHM;

	return SKEIN_Final (context, hashval);
}

HashReturn SKEIN1024_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval)
{
    hashState   state;
    HashReturn  retval;

    retval = SKEIN1024_init (&state, HASH_BITLENGTH_SKEIN_1024);
    if (retval != SUCCESS) {
        fprintf (stderr, "SKEIN1024_init failed, reason %d, hash length %d\n",
                 retval, HASH_BITLENGTH_SKEIN_1024);
        exit (1);
    }

    retval = SKEIN1024_update (state, data, databitlen);
    if (retval != SUCCESS) {
        fprintf (stderr, "SKEIN1024_update failed, reason %d\n", retval);
        exit (1);
    }

    retval = SKEIN1024_final (state, hashval);
    if (retval != SUCCESS) {
        fprintf (stderr, "SKEIN1024_final failed, reason %d\n", retval);
        exit (1);
    }
    free (state);
    return retval;
}

/*
 * three functions in MD5 style for each hash length
 */

/* Digests a file and prints the result.
 */
HashReturn SKEIN1024_File (hashState state, FILE *in)
{
	SKEIN_CTX *context = (SKEIN_CTX *) state;
	int len;
	unsigned char buffer[BUFFERSIZE];
	HashReturn retval;

	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_SKEIN_1024)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_SKEIN_1024)
		return BAD_ALGORITHM;

	while ((len = fread (buffer, 1, BUFFERSIZE, in))) {
		retval = SKEIN1024_update (context, buffer, (DataLength)len << 3);
		if (retval != SUCCESS) return retval;
	}
	retval = SKEIN1024_final (context, NULL);

	fclose (in);
	return retval;
}

HashReturn SKEIN1024_HashToByte (hashState state, BYTE *out) 
{
	SKEIN_CTX *context = (SKEIN_CTX *) state;

	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_SKEIN_1024)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_SKEIN_1024)
		return BAD_ALGORITHM;

	memcpy (out, context->out, HASH_LENGTH_SKEIN_1024);
	return SUCCESS;
}


