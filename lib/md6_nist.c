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

/* File:    md6_nist.c
** Author:  Ronald L. Rivest
** Address: Room 32G-692 Stata Center 
**          32 Vassar Street 
**          Cambridge, MA 02139
** Email:   rivest@mit.edu
** Date:    9/25/2008
**
** (The following license is known as "The MIT License")
** 
** Copyright (c) 2008 Ronald L. Rivest
** 
** Permission is hereby granted, free of charge, to any person obtaining a copy
** of this software and associated documentation files (the "Software"), to deal
** in the Software without restriction, including without limitation the rights
** to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
** copies of the Software, and to permit persons to whom the Software is
** furnished to do so, subject to the following conditions:
** 
** The above copyright notice and this permission notice shall be included in
** all copies or substantial portions of the Software.
** 
** THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
** IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
** FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
** AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
** LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
** OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
** THE SOFTWARE.
**
** (end of license)
**
** This is part of the definition of the MD6 hash function.
** The files defining the MD6 hash function are:
**    md6.h
**    md6_compress.c
**    md6_mode.c
**
** The files defining the interface between MD6 and the NIST SHA-3
** API are:
**    md6_nist.h
**    md6_nist.c
** The NIST SHA-3 API is defined in:
**    http://www.csrc.nist.gov/groups/ST/hash/documents/SHA3-C-API.pdf
**
** See  http://groups.csail.mit.edu/cis/md6  for more information.
*/

/* 07.03.2016 hvf integrated into FEHASHMAC
*/

#include <stdio.h>
#include "md6.h"
#include "md6_nist.h"

/* declare these functions as static to avoid namespace clashes */
static HashReturn Init( md6_state *state, 
		 int hashbitlen
		 )
{ int err;
  if ((err = md6_init( (md6_state *) state, 
		       hashbitlen
		       )))
    return err;
  state->hashbitlen = hashbitlen;
  return SUCCESS;
}

static HashReturn Update( md6_state *state, 
		   const BitSequence *data, 
		   DataLength databitlen
		   )
{ return md6_update( (md6_state *) state, 
		     (unsigned char *)data, 
		     (uint64_t) databitlen );
}

static HashReturn Final( md6_state *state,
		  BitSequence *hashval
		  )
{ return md6_final( (md6_state *) state,
		    (unsigned char *) hashval
		    );
}

static HashReturn Hash( int hashbitlen,
		 const BitSequence *data,
		 DataLength databitlen,
		 BitSequence *hashval
		 )
{ int err;
  md6_state state;
  if ((err = Init( &state, hashbitlen ))) 
    return err;
  if ((err = Update( &state, data, databitlen ))) 
    return err;
  return Final( &state, hashval );
}


/* 
 * parameter safe wrappers for MD6 routines for each hash length
 */

 /*************************** 224 ************************************/

HashReturn MD6_224_init (hashState  *state, int hashbitlen)
{
    HashReturn retval;
    /* verify correct hash length   */
    if (hashbitlen != HASH_BITLENGTH_MD6_224)
        return BAD_HASHBITLEN;

    /* allocate context and fill it */
    MD6_CTX *context = (MD6_CTX *)malloc (sizeof (MD6_CTX));
    memset (context, 0, sizeof (MD6_CTX));
	*state = (hashState *) context;
	retval = Init (context, hashbitlen);

    /* Init resets context (again), so we fill in our parameters here   */ 
    context->hashbitlen = HASH_BITLENGTH_MD6_224;
    context->magic = HASH_MAGIC_MD6_224;
    return retval;
}

HashReturn  MD6_224_update (
    hashState state,          /* previously initialized context */
    const BitSequence *buffer,  /* bit buffer, first bit is MSB in [0] */
    DataLength databitlen)      /* number of bits to process from buffer */
{
    /* can be called once or many times */
    /* verify correct hashbitlen and magic  */

    MD6_CTX *context = (MD6_CTX *) state;
    if (context->hashbitlen != HASH_BITLENGTH_MD6_224){
        return BAD_HASHBITLEN;
    }

    if (context->magic != HASH_MAGIC_MD6_224) {
        return BAD_ALGORITHM;
    }

	return Update (context, buffer, databitlen);
}

HashReturn  MD6_224_final (hashState state, BitSequence *hashval)
{
    MD6_CTX *context = (MD6_CTX *) state;
    if (context->hashbitlen != HASH_BITLENGTH_MD6_224)
        return BAD_HASHBITLEN;

    if (context->magic != HASH_MAGIC_MD6_224)
        return BAD_ALGORITHM;

	HashReturn retval = Final (context, context->out);
	if (hashval) memcpy (hashval, context->out, HASH_LENGTH_MD6_224);
	return retval;
}

HashReturn MD6_224_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval)
{
    hashState   state;
    HashReturn  retval;

    retval = MD6_224_init (&state, HASH_BITLENGTH_MD6_224);
    if (retval != SUCCESS) {
        fprintf (stderr, "MD6_224_init failed, reason %d, hash length %d\n",
                 retval, HASH_BITLENGTH_MD6_224);
        exit (1);
    }

    retval = MD6_224_update (state, data, databitlen);
    if (retval != SUCCESS) {
        fprintf (stderr, "MD6_224_update failed, reason %d\n", retval);
        exit (1);
    }

    retval = MD6_224_final (state, hashval);
    if (retval != SUCCESS) {
        fprintf (stderr, "MD6_224_final failed, reason %d\n", retval);
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
HashReturn MD6_224_File (hashState state, FILE *in)
{
	MD6_CTX *context = (MD6_CTX *) state;
	int len;
	unsigned char buffer[BUFFERSIZE];
	HashReturn retval;

	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_MD6_224)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_MD6_224)
		return BAD_ALGORITHM;

	while ((len = fread (buffer, 1, BUFFERSIZE, in))) {
		retval = MD6_224_update (context, buffer, (DataLength)len << 3);
		if (retval != SUCCESS) return retval;
	}
	retval = MD6_224_final (context, NULL);

	fclose (in);
	return retval;
}

HashReturn MD6_224_HashToByte (hashState state, BYTE *out) 
{
	MD6_CTX *context = (MD6_CTX *) state;

	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_MD6_224)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_MD6_224)
		return BAD_ALGORITHM;

	memcpy (out, context->out, HASH_LENGTH_MD6_224);
	return SUCCESS;
}


 /*************************** 256 ************************************/

HashReturn MD6_256_init (hashState  *state, int hashbitlen)
{
    HashReturn retval;
    /* verify correct hash length   */
    if (hashbitlen != HASH_BITLENGTH_MD6_256)
        return BAD_HASHBITLEN;

    /* allocate context and fill it */
    MD6_CTX *context = (MD6_CTX *)malloc (sizeof (MD6_CTX));
    memset (context, 0, sizeof (MD6_CTX));
	*state = (hashState *) context;
	retval = Init (context, hashbitlen);
    context->hashbitlen = HASH_BITLENGTH_MD6_256;
    context->magic = HASH_MAGIC_MD6_256;
    return retval;
}

HashReturn  MD6_256_update (
    hashState state,          /* previously initialized context */
    const BitSequence *buffer,  /* bit buffer, first bit is MSB in [0] */
    DataLength databitlen)      /* number of bits to process from buffer */
{
    /* can be called once or many times */
    /* verify correct hashbitlen and magic  */

    MD6_CTX *context = (MD6_CTX *) state;
    if (context->hashbitlen != HASH_BITLENGTH_MD6_256)
        return BAD_HASHBITLEN;

    if (context->magic != HASH_MAGIC_MD6_256)
        return BAD_ALGORITHM;

	return Update (context, buffer, databitlen);
}

HashReturn  MD6_256_final (hashState state, BitSequence *hashval)
{
    MD6_CTX *context = (MD6_CTX *) state;
    if (context->hashbitlen != HASH_BITLENGTH_MD6_256)
        return BAD_HASHBITLEN;

    if (context->magic != HASH_MAGIC_MD6_256)
        return BAD_ALGORITHM;

	HashReturn retval = Final (context, context->out);
	if (hashval) memcpy (hashval, context->out, HASH_LENGTH_MD6_256);
	return retval;
}

HashReturn MD6_256_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval)
{
    hashState   state;
    HashReturn  retval;

    retval = MD6_256_init (&state, HASH_BITLENGTH_MD6_256);
    if (retval != SUCCESS) {
        fprintf (stderr, "MD6_256_init failed, reason %d, hash length %d\n",
                 retval, HASH_BITLENGTH_MD6_256);
        exit (1);
    }

    retval = MD6_256_update (state, data, databitlen);
    if (retval != SUCCESS) {
        fprintf (stderr, "MD6_256_update failed, reason %d\n", retval);
        exit (1);
    }

    retval = MD6_256_final (state, hashval);
    if (retval != SUCCESS) {
        fprintf (stderr, "MD6_256_final failed, reason %d\n", retval);
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
HashReturn MD6_256_File (hashState state, FILE *in)
{
	MD6_CTX *context = (MD6_CTX *) state;
	int len;
	unsigned char buffer[BUFFERSIZE];
	HashReturn retval;

	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_MD6_256)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_MD6_256)
		return BAD_ALGORITHM;

	while ((len = fread (buffer, 1, BUFFERSIZE, in))) {
		retval = MD6_256_update (context, buffer, (DataLength)len << 3);
		if (retval != SUCCESS) return retval;
	}
	retval = MD6_256_final (context, NULL);

	fclose (in);
	return retval;
}

HashReturn MD6_256_HashToByte (hashState state, BYTE *out) 
{
	MD6_CTX *context = (MD6_CTX *) state;

	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_MD6_256)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_MD6_256)
		return BAD_ALGORITHM;

	memcpy (out, context->out, HASH_LENGTH_MD6_256);
	return SUCCESS;
}


 /*************************** 384 ************************************/

HashReturn MD6_384_init (hashState  *state, int hashbitlen)
{
    HashReturn retval;
    /* verify correct hash length   */
    if (hashbitlen != HASH_BITLENGTH_MD6_384)
        return BAD_HASHBITLEN;

    /* allocate context and fill it */
    MD6_CTX *context = (MD6_CTX *)malloc (sizeof (MD6_CTX));
    memset (context, 0, sizeof (MD6_CTX));
	*state = (hashState *) context;
	retval = Init (context, hashbitlen);
    context->hashbitlen = HASH_BITLENGTH_MD6_384;
    context->magic = HASH_MAGIC_MD6_384;
    return retval;
}

HashReturn  MD6_384_update (
    hashState state,          /* previously initialized context */
    const BitSequence *buffer,  /* bit buffer, first bit is MSB in [0] */
    DataLength databitlen)      /* number of bits to process from buffer */
{
    /* can be called once or many times */
    /* verify correct hashbitlen and magic  */

    MD6_CTX *context = (MD6_CTX *) state;
    if (context->hashbitlen != HASH_BITLENGTH_MD6_384)
        return BAD_HASHBITLEN;

    if (context->magic != HASH_MAGIC_MD6_384)
        return BAD_ALGORITHM;

	return Update (context, buffer, databitlen);
}

HashReturn  MD6_384_final (hashState state, BitSequence *hashval)
{
    MD6_CTX *context = (MD6_CTX *) state;
    if (context->hashbitlen != HASH_BITLENGTH_MD6_384)
        return BAD_HASHBITLEN;

    if (context->magic != HASH_MAGIC_MD6_384)
        return BAD_ALGORITHM;

	HashReturn retval = Final (context, context->out);
	if (hashval) memcpy (hashval, context->out, HASH_LENGTH_MD6_384);
	return retval;
}

HashReturn MD6_384_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval)
{
    hashState   state;
    HashReturn  retval;

    retval = MD6_384_init (&state, HASH_BITLENGTH_MD6_384);
    if (retval != SUCCESS) {
        fprintf (stderr, "MD6_384_init failed, reason %d, hash length %d\n",
                 retval, HASH_BITLENGTH_MD6_384);
        exit (1);
    }

    retval = MD6_384_update (state, data, databitlen);
    if (retval != SUCCESS) {
        fprintf (stderr, "MD6_384_update failed, reason %d\n", retval);
        exit (1);
    }

    retval = MD6_384_final (state, hashval);
    if (retval != SUCCESS) {
        fprintf (stderr, "MD6_384_final failed, reason %d\n", retval);
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
HashReturn MD6_384_File (hashState state, FILE *in)
{
	MD6_CTX *context = (MD6_CTX *) state;
	int len;
	unsigned char buffer[BUFFERSIZE];
	HashReturn retval;

	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_MD6_384)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_MD6_384)
		return BAD_ALGORITHM;

	while ((len = fread (buffer, 1, BUFFERSIZE, in))) {
		retval = MD6_384_update (context, buffer, (DataLength)len << 3);
		if (retval != SUCCESS) return retval;
	}
	retval = MD6_384_final (context, NULL);

	fclose (in);
	return retval;
}

HashReturn MD6_384_HashToByte (hashState state, BYTE *out) 
{
	MD6_CTX *context = (MD6_CTX *) state;

	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_MD6_384)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_MD6_384)
		return BAD_ALGORITHM;

	memcpy (out, context->out, HASH_LENGTH_MD6_384);
	return SUCCESS;
}


 /*************************** 512 ************************************/

HashReturn MD6_512_init (hashState  *state, int hashbitlen)
{
    HashReturn retval;
    /* verify correct hash length   */
    if (hashbitlen != HASH_BITLENGTH_MD6_512)
        return BAD_HASHBITLEN;

    /* allocate context and fill it */
    MD6_CTX *context = (MD6_CTX *)malloc (sizeof (MD6_CTX));
    memset (context, 0, sizeof (MD6_CTX));
    context->hashbitlen = HASH_BITLENGTH_MD6_512;
    context->magic = HASH_MAGIC_MD6_512;
	*state = (hashState *) context;
	retval = Init (context, hashbitlen);
    context->hashbitlen = HASH_BITLENGTH_MD6_512;
    context->magic = HASH_MAGIC_MD6_512;
    return retval;
}

HashReturn  MD6_512_update (
    hashState state,          /* previously initialized context */
    const BitSequence *buffer,  /* bit buffer, first bit is MSB in [0] */
    DataLength databitlen)      /* number of bits to process from buffer */
{
    /* can be called once or many times */
    /* verify correct hashbitlen and magic  */

    MD6_CTX *context = (MD6_CTX *) state;
    if (context->hashbitlen != HASH_BITLENGTH_MD6_512)
        return BAD_HASHBITLEN;

    if (context->magic != HASH_MAGIC_MD6_512)
        return BAD_ALGORITHM;

	return Update (context, buffer, databitlen);
}

HashReturn  MD6_512_final (hashState state, BitSequence *hashval)
{
    MD6_CTX *context = (MD6_CTX *) state;
    if (context->hashbitlen != HASH_BITLENGTH_MD6_512)
        return BAD_HASHBITLEN;

    if (context->magic != HASH_MAGIC_MD6_512)
        return BAD_ALGORITHM;

	HashReturn retval = Final (context, context->out);
	if (hashval) memcpy (hashval, context->out, HASH_LENGTH_MD6_512);
	return retval;
}

HashReturn MD6_512_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval)
{
    hashState   state;
    HashReturn  retval;

    retval = MD6_512_init (&state, HASH_BITLENGTH_MD6_512);
    if (retval != SUCCESS) {
        fprintf (stderr, "MD6_512_init failed, reason %d, hash length %d\n",
                 retval, HASH_BITLENGTH_MD6_512);
        exit (1);
    }

    retval = MD6_512_update (state, data, databitlen);
    if (retval != SUCCESS) {
        fprintf (stderr, "MD6_512_update failed, reason %d\n", retval);
        exit (1);
    }

    retval = MD6_512_final (state, hashval);
    if (retval != SUCCESS) {
        fprintf (stderr, "MD6_512_final failed, reason %d\n", retval);
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
HashReturn MD6_512_File (hashState state, FILE *in)
{
	MD6_CTX *context = (MD6_CTX *) state;
	int len;
	unsigned char buffer[BUFFERSIZE];
	HashReturn retval;

	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_MD6_512)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_MD6_512)
		return BAD_ALGORITHM;

	while ((len = fread (buffer, 1, BUFFERSIZE, in))) {
		retval = MD6_512_update (context, buffer, (DataLength)len << 3);
		if (retval != SUCCESS) return retval;
	}
	retval = MD6_512_final (context, NULL);

	fclose (in);
	return retval;
}

HashReturn MD6_512_HashToByte (hashState state, BYTE *out) 
{
	MD6_CTX *context = (MD6_CTX *) state;

	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_MD6_512)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_MD6_512)
		return BAD_ALGORITHM;

	memcpy (out, context->out, HASH_LENGTH_MD6_512);
	return SUCCESS;
}


