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

/*
 *  gosthash.c 
 *  21 Apr 1998  Markku-Juhani Saarinen <mjos@ssh.fi>
 * 
 *  GOST R 34.11-94, Russian Standard Hash Function
 *
 *  Copyright (c) 1998 SSH Communications Security, Finland
 *  All rights reserved.
 */

/*
 * integrated in fehashmac
 * hvf 04.02.2007
 * hvf 16.02.2009 aligned with SHA3-C-API
 * disable unused fct GOST_Print - hvf 19.04.2015
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "gost.h"

/* GOSTLONG replaces the original long
 * hvf 19.02.2007 */

/* lookup tables : each of these has two rotated 4-bit S-Boxes */

GOSTLONG gost_sbox_1[256];
GOSTLONG gost_sbox_2[256];
GOSTLONG gost_sbox_3[256];
GOSTLONG gost_sbox_4[256];

/* initialize the lookup tables */

void gosthash_init()
{
  int a, b, i;
  GOSTLONG ax, bx, cx, dx;
  
  /* 4-bit S-Boxes */ 
  
  GOSTLONG sbox[8][16] =
    {
	{  4, 10,  9,  2, 13,  8,  0, 14,  6, 11,  1, 12,  7, 15,  5,  3 },
	{ 14, 11,  4, 12,  6, 13, 15, 10,  2,  3,  8,  1,  0,  7,  5,  9 },
	{  5,  8,  1, 13, 10,  3,  4,  2, 14, 15, 12,  7,  6,  0,  9, 11 },
	{  7, 13, 10,  1,  0,  8,  9, 15, 14,  4,  6, 12, 11,  2,  5,  3 },
	{  6, 12,  7,  1,  5, 15, 13,  8,  4, 10,  9, 14,  0,  3, 11,  2 },
	{  4, 11, 10,  0,  7,  2,  1, 13,  3,  6,  8,  5,  9, 12, 15, 14 },
	{ 13, 11,  4,  1,  3, 15,  5,  9,  0, 10, 14,  7,  6,  8,  2, 12 },
	{  1, 15, 13,  0,  5,  7, 10,  4,  9,  2,  3, 14,  6, 11,  8, 12 }  
    };
  
  /* s-box precomputation */
  
  i = 0;
  for (a = 0; a < 16; a++)
    {
      ax = sbox[1][a] << 15;	  
      bx = sbox[3][a] << 23;
      cx = sbox[5][a];	      
      cx = (cx >> 1) | (cx << 31);
      dx = sbox[7][a] << 7;
      
      for (b = 0; b < 16; b++)
	{
	  gost_sbox_1[i] = ax | (sbox[0][b] << 11);		  
	  gost_sbox_2[i] = bx | (sbox[2][b] << 19);
	  gost_sbox_3[i] = cx | (sbox[4][b] << 27);	  
	  gost_sbox_4[i++] = dx | (sbox[6][b] << 3);
	}
    }
}

/*
 *  A macro that performs a full encryption round of GOST 28147-89.
 *  Temporary variable t assumed and variables r and l for left and right
 *  blocks
 */ 

#define GOST_ENCRYPT_ROUND(k1, k2) \
t = (k1) + r; \
l ^= gost_sbox_1[t & 0xff] ^ gost_sbox_2[(t >> 8) & 0xff] ^ \
gost_sbox_3[(t >> 16) & 0xff] ^ gost_sbox_4[t >> 24]; \
t = (k2) + l; \
r ^= gost_sbox_1[t & 0xff] ^ gost_sbox_2[(t >> 8) & 0xff] ^ \
gost_sbox_3[(t >> 16) & 0xff] ^ gost_sbox_4[t >> 24]; \

/* encrypt a block with the given key */

#define GOST_ENCRYPT(key) \
GOST_ENCRYPT_ROUND(key[0], key[1]) \
GOST_ENCRYPT_ROUND(key[2], key[3]) \
GOST_ENCRYPT_ROUND(key[4], key[5]) \
GOST_ENCRYPT_ROUND(key[6], key[7]) \
GOST_ENCRYPT_ROUND(key[0], key[1]) \
GOST_ENCRYPT_ROUND(key[2], key[3]) \
GOST_ENCRYPT_ROUND(key[4], key[5]) \
GOST_ENCRYPT_ROUND(key[6], key[7]) \
GOST_ENCRYPT_ROUND(key[0], key[1]) \
GOST_ENCRYPT_ROUND(key[2], key[3]) \
GOST_ENCRYPT_ROUND(key[4], key[5]) \
GOST_ENCRYPT_ROUND(key[6], key[7]) \
GOST_ENCRYPT_ROUND(key[7], key[6]) \
GOST_ENCRYPT_ROUND(key[5], key[4]) \
GOST_ENCRYPT_ROUND(key[3], key[2]) \
GOST_ENCRYPT_ROUND(key[1], key[0]) \
t = r; \
r = l; \
l = t;

/* 
 *  "chi" compression function. the result is stored over h
 */

static void gosthash_compress(GOSTLONG *h, GOSTLONG *m)
{
  int i;
  GOSTLONG l, r, t, key[8], u[8], v[8], w[8], s[8];
  
  memcpy(u, h, sizeof(u));
  memcpy(v, m, sizeof(u));
  
  for (i = 0; i < 8; i += 2)
    {        
      w[0] = u[0] ^ v[0];	       /* w = u xor v */
      w[1] = u[1] ^ v[1];
      w[2] = u[2] ^ v[2];
      w[3] = u[3] ^ v[3];
      w[4] = u[4] ^ v[4];
      w[5] = u[5] ^ v[5];
      w[6] = u[6] ^ v[6];
      w[7] = u[7] ^ v[7];      
      
      /* P-Transformation */
      
      key[0] = (w[0]  & 0x000000ff) | ((w[2] & 0x000000ff) << 8) |
	((w[4] & 0x000000ff) << 16) | ((w[6] & 0x000000ff) << 24);
      key[1] = ((w[0] & 0x0000ff00) >> 8)  | (w[2]  & 0x0000ff00) |
	((w[4] & 0x0000ff00) << 8) | ((w[6] & 0x0000ff00) << 16);
      key[2] = ((w[0] & 0x00ff0000) >> 16) | ((w[2] & 0x00ff0000) >> 8) |
	(w[4] & 0x00ff0000) | ((w[6] & 0x00ff0000) << 8);
      key[3] = ((w[0] & 0xff000000) >> 24) | ((w[2] & 0xff000000) >> 16) |
	((w[4] & 0xff000000) >> 8) | (w[6] & 0xff000000);  
      key[4] = (w[1] & 0x000000ff) | ((w[3] & 0x000000ff) << 8) |
	((w[5] & 0x000000ff) << 16) | ((w[7] & 0x000000ff) << 24);
      key[5] = ((w[1] & 0x0000ff00) >> 8) | (w[3]  & 0x0000ff00) |
	((w[5] & 0x0000ff00) << 8) | ((w[7] & 0x0000ff00) << 16);
      key[6] = ((w[1] & 0x00ff0000) >> 16) | ((w[3] & 0x00ff0000) >> 8) |
	(w[5] & 0x00ff0000) | ((w[7] & 0x00ff0000) << 8);
      key[7] = ((w[1] & 0xff000000) >> 24) | ((w[3] & 0xff000000) >> 16) |
	((w[5] & 0xff000000) >> 8) | (w[7] & 0xff000000);  
            
      r = h[i];			       /* encriphering transformation */
      l = h[i + 1];      
      GOST_ENCRYPT(key);
      
      s[i] = r;
      s[i + 1] = l;
            
      if (i == 6)
	break;
      
      l = u[0] ^ u[2];		       /* U = A(U) */
      r = u[1] ^ u[3];
      u[0] = u[2];
      u[1] = u[3];
      u[2] = u[4];
      u[3] = u[5];
      u[4] = u[6];
      u[5] = u[7];
      u[6] = l;
      u[7] = r;
            
      if (i == 2)		       /* Constant C_3 */
	{
	  u[0] ^= 0xff00ff00; 
	  u[1] ^= 0xff00ff00; 
	  u[2] ^= 0x00ff00ff;
	  u[3] ^= 0x00ff00ff;
	  u[4] ^= 0x00ffff00;
	  u[5] ^= 0xff0000ff;
	  u[6] ^= 0x000000ff;
	  u[7] ^= 0xff00ffff;	    
	}
      
      l = v[0];			       /* V = A(A(V)) */
      r = v[2];
      v[0] = v[4];
      v[2] = v[6];
      v[4] = l ^ r;
      v[6] = v[0] ^ r;
      l = v[1];
      r = v[3];
      v[1] = v[5];
      v[3] = v[7];
      v[5] = l ^ r;
      v[7] = v[1] ^ r;
    }
  
  /* 12 rounds of the LFSR (computed from a product matrix) and xor in M */
  
  u[0] = m[0] ^ s[6];
  u[1] = m[1] ^ s[7];
  u[2] = m[2] ^ (s[0] << 16) ^ (s[0] >> 16) ^ (s[0] & 0xffff) ^ 
    (s[1] & 0xffff) ^ (s[1] >> 16) ^ (s[2] << 16) ^ s[6] ^ (s[6] << 16) ^
    (s[7] & 0xffff0000) ^ (s[7] >> 16);
  u[3] = m[3] ^ (s[0] & 0xffff) ^ (s[0] << 16) ^ (s[1] & 0xffff) ^ 
    (s[1] << 16) ^ (s[1] >> 16) ^ (s[2] << 16) ^ (s[2] >> 16) ^
    (s[3] << 16) ^ s[6] ^ (s[6] << 16) ^ (s[6] >> 16) ^ (s[7] & 0xffff) ^ 
    (s[7] << 16) ^ (s[7] >> 16);
  u[4] = m[4] ^ 
    (s[0] & 0xffff0000) ^ (s[0] << 16) ^ (s[0] >> 16) ^ 
    (s[1] & 0xffff0000) ^ (s[1] >> 16) ^ (s[2] << 16) ^ (s[2] >> 16) ^
    (s[3] << 16) ^ (s[3] >> 16) ^ (s[4] << 16) ^ (s[6] << 16) ^ 
    (s[6] >> 16) ^(s[7] & 0xffff) ^ (s[7] << 16) ^ (s[7] >> 16);
  u[5] = m[5] ^ (s[0] << 16) ^ (s[0] >> 16) ^ (s[0] & 0xffff0000) ^
    (s[1] & 0xffff) ^ s[2] ^ (s[2] >> 16) ^ (s[3] << 16) ^ (s[3] >> 16) ^
    (s[4] << 16) ^ (s[4] >> 16) ^ (s[5] << 16) ^  (s[6] << 16) ^ 
    (s[6] >> 16) ^ (s[7] & 0xffff0000) ^ (s[7] << 16) ^ (s[7] >> 16);
  u[6] = m[6] ^ s[0] ^ (s[1] >> 16) ^ (s[2] << 16) ^ s[3] ^ (s[3] >> 16) ^
    (s[4] << 16) ^ (s[4] >> 16) ^ (s[5] << 16) ^ (s[5] >> 16) ^ s[6] ^ 
    (s[6] << 16) ^ (s[6] >> 16) ^ (s[7] << 16);
  u[7] = m[7] ^ (s[0] & 0xffff0000) ^ (s[0] << 16) ^ (s[1] & 0xffff) ^ 
    (s[1] << 16) ^ (s[2] >> 16) ^ (s[3] << 16) ^ s[4] ^ (s[4] >> 16) ^
    (s[5] << 16) ^ (s[5] >> 16) ^ (s[6] >> 16) ^ (s[7] & 0xffff) ^ 
    (s[7] << 16) ^ (s[7] >> 16);
      
  /* 16 * 1 round of the LFSR and xor in H */
  
  v[0] = h[0] ^ (u[1] << 16) ^ (u[0] >> 16);
  v[1] = h[1] ^ (u[2] << 16) ^ (u[1] >> 16);
  v[2] = h[2] ^ (u[3] << 16) ^ (u[2] >> 16);
  v[3] = h[3] ^ (u[4] << 16) ^ (u[3] >> 16);
  v[4] = h[4] ^ (u[5] << 16) ^ (u[4] >> 16);
  v[5] = h[5] ^ (u[6] << 16) ^ (u[5] >> 16);
  v[6] = h[6] ^ (u[7] << 16) ^ (u[6] >> 16);
  v[7] = h[7] ^ (u[0] & 0xffff0000) ^ (u[0] << 16) ^ (u[7] >> 16) ^
    (u[1] & 0xffff0000) ^ (u[1] << 16) ^ (u[6] << 16) ^ (u[7] & 0xffff0000);
  
  /* 61 rounds of LFSR, mixing up h (computed from a product matrix) */

  h[0] = (v[0] & 0xffff0000) ^ (v[0] << 16) ^ (v[0] >> 16) ^ (v[1] >> 16) ^ 
    (v[1] & 0xffff0000) ^ (v[2] << 16) ^ (v[3] >> 16) ^ (v[4] << 16) ^
    (v[5] >> 16) ^ v[5] ^ (v[6] >> 16) ^ (v[7] << 16) ^ (v[7] >> 16) ^ 
    (v[7] & 0xffff);
  h[1] = (v[0] << 16) ^ (v[0] >> 16) ^ (v[0] & 0xffff0000) ^ (v[1] & 0xffff) ^ 
    v[2] ^ (v[2] >> 16) ^ (v[3] << 16) ^ (v[4] >> 16) ^ (v[5] << 16) ^ 
    (v[6] << 16) ^ v[6] ^ (v[7] & 0xffff0000) ^ (v[7] >> 16);
  h[2] = (v[0] & 0xffff) ^ (v[0] << 16) ^ (v[1] << 16) ^ (v[1] >> 16) ^ 
    (v[1] & 0xffff0000) ^ (v[2] << 16) ^ (v[3] >> 16) ^ v[3] ^ (v[4] << 16) ^
    (v[5] >> 16) ^ v[6] ^ (v[6] >> 16) ^ (v[7] & 0xffff) ^ (v[7] << 16) ^
    (v[7] >> 16);
  h[3] = (v[0] << 16) ^ (v[0] >> 16) ^ (v[0] & 0xffff0000) ^ 
    (v[1] & 0xffff0000) ^ (v[1] >> 16) ^ (v[2] << 16) ^ (v[2] >> 16) ^ v[2] ^ 
    (v[3] << 16) ^ (v[4] >> 16) ^ v[4] ^ (v[5] << 16) ^ (v[6] << 16) ^ 
    (v[7] & 0xffff) ^ (v[7] >> 16);
  h[4] = (v[0] >> 16) ^ (v[1] << 16) ^ v[1] ^ (v[2] >> 16) ^ v[2] ^ 
    (v[3] << 16) ^ (v[3] >> 16) ^ v[3] ^ (v[4] << 16) ^ (v[5] >> 16) ^ 
    v[5] ^ (v[6] << 16) ^ (v[6] >> 16) ^ (v[7] << 16);
  h[5] = (v[0] << 16) ^ (v[0] & 0xffff0000) ^ (v[1] << 16) ^ (v[1] >> 16) ^ 
    (v[1] & 0xffff0000) ^ (v[2] << 16) ^ v[2] ^ (v[3] >> 16) ^ v[3] ^ 
    (v[4] << 16) ^ (v[4] >> 16) ^ v[4] ^ (v[5] << 16) ^ (v[6] << 16) ^
    (v[6] >> 16) ^ v[6] ^ (v[7] << 16) ^ (v[7] >> 16) ^ (v[7] & 0xffff0000);
  h[6] = v[0] ^ v[2] ^ (v[2] >> 16) ^ v[3] ^ (v[3] << 16) ^ v[4] ^ 
    (v[4] >> 16) ^ (v[5] << 16) ^ (v[5] >> 16) ^ v[5] ^ (v[6] << 16) ^ 
    (v[6] >> 16) ^ v[6] ^ (v[7] << 16) ^ v[7];
  h[7] = v[0] ^ (v[0] >> 16) ^ (v[1] << 16) ^ (v[1] >> 16) ^ (v[2] << 16) ^
    (v[3] >> 16) ^ v[3] ^ (v[4] << 16) ^ v[4] ^ (v[5] >> 16) ^ v[5] ^
    (v[6] << 16) ^ (v[6] >> 16) ^ (v[7] << 16) ^ v[7];
}

/* Clear the state of the given context structure. */

void gosthash_reset(GostHashCtx *ctx)
{
  memset(ctx->sum, 0, 32);
  memset(ctx->hash, 0, 32);
  memset(ctx->len, 0, 32);
  memset(ctx->partial, 0, 32);
  ctx->partial_bytes = 0;  
}

/* Mix in a 32-byte chunk ("stage 3") */

static void gosthash_bytes(GostHashCtx *ctx, const unsigned char *buf, size_t bits)
{
  int i, j;
  GOSTLONG a, b, c, m[8];
  
  /* convert bytes to a GOSTLONG words and compute the sum */
  
  j = 0;
  c = 0;
  for (i = 0; i < 8; i++)
    {
      a = ((GOSTLONG) buf[j]) | 
	(((GOSTLONG) buf[j + 1]) << 8) | 
	(((GOSTLONG) buf[j + 2]) << 16) | 
	(((GOSTLONG) buf[j + 3]) << 24);
      j += 4;
      m[i] = a;
      b = ctx->sum[i];
      c = a + c + ctx->sum[i];
      ctx->sum[i] = c;
      c = ((c < a) || (c < b)) ? 1 : 0;     
    }
    
  /* compress */
  
  gosthash_compress(ctx->hash, m);
  
  /* a 64-bit counter should be sufficient */
  
  ctx->len[0] += bits;
  if (ctx->len[0] < bits)
    ctx->len[1]++;  
}

/* Mix in len bytes of data for the given buffer. */

void gosthash_update(GostHashCtx *ctx, const unsigned char *buf, size_t len)
{
  size_t i, j;
  
  i = ctx->partial_bytes;
  j = 0;
  while (i < 32 && j < len)
    ctx->partial[i++] = buf[j++];
  
  if (i < 32)
    {
      ctx->partial_bytes = i;
      return;
    }  
  gosthash_bytes(ctx, ctx->partial, 256);
  
  while ((j + 32) < len)
    {
      gosthash_bytes(ctx, &buf[j], 256);
      j += 32;
    }
  
  i = 0;
  while (j < len)
    ctx->partial[i++] = buf[j++];
  ctx->partial_bytes = i;
}


/* Compute and save the 32-byte digest. */

void gosthash_final(GostHashCtx *ctx, unsigned char *digest)
{
  int i, j;
  GOSTLONG a;
  
  /* adjust and mix in the last chunk */
  
  if (ctx->partial_bytes > 0)
    {
      memset(&ctx->partial[ctx->partial_bytes], 0, 32 - ctx->partial_bytes);
      gosthash_bytes(ctx, ctx->partial, ctx->partial_bytes << 3);      
    }
  
  /* mix in the length and the sum */
  
  gosthash_compress(ctx->hash, ctx->len);  
  gosthash_compress(ctx->hash, ctx->sum);  
  
  /* convert the output to bytes */
  
  j = 0;
  for (i = 0; i < 8; i++)
    {
      a = ctx->hash[i];
      digest[j] = (unsigned char) a;
      digest[j + 1] = (unsigned char) (a >> 8);
      digest[j + 2] = (unsigned char) (a >> 16);
      digest[j + 3] = (unsigned char) (a >> 24);	
      j += 4;
    }  
}

/* SHA3 fehashmac interface routines - hvf 16.02.2009 */

HashReturn GOST_init (hashState  *state, int hashbitlen)
{
	/* verify correct hash length	*/
	if (hashbitlen != HASH_BITLENGTH_GOST)
		return BAD_HASHBITLEN;

	/* allocate context and fill it	*/
	GOST_CTX *context = (GOST_CTX *)malloc (sizeof (GOST_CTX));
	memset (context, 0, sizeof (GOST_CTX));
	context->hashbitlen = HASH_BITLENGTH_GOST;
	context->magic = HASH_MAGIC_GOST;

	/* call GOST init functions */
	gosthash_init();
	gosthash_reset (context);

	*state = (hashState *) context;
	return SUCCESS;
}

void GOST_update_old (GOST_CTX *context, const unsigned char *input, unsigned int inputLen)
{
	gosthash_update(context, input, inputLen);
}

void GOST_final_old (GOST_CTX *context)
{
	gosthash_final(context, context->out);
}

HashReturn 	GOST_update (
	hashState state, 			/* previously initialized context */
	const BitSequence *buffer, 	/* bit buffer, first bit is MSB in [0] */
	DataLength databitlen)		/* number of bits to process from buffer */
{	
	/* can be called once or many times */
	/* verify correct hashbitlen and magic	*/

	GOST_CTX *context = (GOST_CTX *) state;
	if (context->hashbitlen != HASH_BITLENGTH_GOST)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_GOST)
		return BAD_ALGORITHM;

	/* check for byte alignment */
	if ((databitlen & 0x7)) {
		return FAIL;
	}

	GOST_update_old (context, buffer, (unsigned int)(databitlen>>3));
	return SUCCESS;
}

HashReturn	GOST_final (hashState state, BitSequence *hashval)
{	/*	does padding of last block	*/
	GOST_CTX *context = (GOST_CTX *) state;
	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_GOST)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_GOST)
		return BAD_ALGORITHM;

	GOST_final_old (context);

	if (hashval)
		memcpy (hashval, context->out, HASH_LENGTH_GOST);
	return SUCCESS;
}

/* GOST utility routines
 *
 * hvf 23.1.2000
 * hvf 13.2.01
 * hvf 10.8.01
 * hvf 15.02.2009
 */

/* Digests a file and prints the result.
 */

HashReturn GOST_File (hashState state, FILE *in)
{
	GOST_CTX *context = (GOST_CTX *) state;
	int len;
	unsigned char buffer[BUFFERSIZE];
	HashReturn retval;

	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_GOST)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_GOST)
		return BAD_ALGORITHM;

	while ((len = fread (buffer, 1, BUFFERSIZE, in))) {
		retval = GOST_update (context, buffer, (DataLength)len << 3);
		if (retval != SUCCESS) return retval;
	}
	retval = GOST_final (context, NULL);

	fclose (in);
	return retval;
}


HashReturn GOST_HashToByte (hashState state, BYTE *out) 
{
	GOST_CTX *context = (GOST_CTX *) state;

	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_GOST)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_GOST)
		return BAD_ALGORITHM;

	memcpy (out, context->out, HASH_LENGTH_GOST);
	return SUCCESS;
}

/* all-in-one hash function as required by SHA3-C-API */

HashReturn GOST_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval) 
{
	hashState	state;
	HashReturn	retval;
	
	retval = GOST_init (&state, HASH_BITLENGTH_GOST);
	if (retval != SUCCESS) {
		fprintf (stderr, "GOST_init failed, reason %d, hash length %d\n",
                 retval, HASH_BITLENGTH_GOST);
        exit (1);
    }

	retval = GOST_update (state, data, databitlen);
	if (retval != SUCCESS) {
		fprintf (stderr, "GOST_update failed, reason %d\n", retval);
        exit (1);
    }

	retval = GOST_final (state, hashval);
	if (retval != SUCCESS) {
		fprintf (stderr, "GOST_final failed, reason %d\n", retval);
        exit (1);
    }
	free (state);
 	return retval;
}

