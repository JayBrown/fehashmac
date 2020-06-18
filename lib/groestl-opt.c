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
 * The files groestl-opt.c, groestl-opt.h, groestl-tables.h, brg_endian.h,
 * brg_types.h have been taken from the final
 * GROESTL submission to the SHA3 contest, see
 * http://csrc.nist.gov/groups/ST/hash/sha-3/Round3/submissions_rnd3.html
 * The GROESTL homepage is http://www.groestl.info/index.html
 * The authors of GROESTL are    
 * Praveen Gauravaram, Lars R. Knudsen, Soren S. Thomsen
 * (Technical University of Denmark, Lyngby, Denmark)
 * Krystian Matusiewicz (Intel Technology Poland, Gdansk, Poland)
 * Florian Mendel, Martin Schlaeffer 
 * (IAIK, Graz University of Technology, Graz, Austria)
 * Christian Rechberger 
 * (ESAT/COSIC, Katholieke Universiteit Leuven, Heverlee, Belgium)
 *
 * integration into fehashmac by hvf 09.04.2011
 * disable Hash, PrintHash, GROESTLxxx_Print - hvf 19.04.2014
 */

/* Groestl-opt.c     January 2011
 * ANSI C code optimised for 32-bit machines
 * Authors: Soeren S. Thomsen
 *          Krystian Matusiewicz
 *
 * This code is placed in the public domain
 */

#include "groestl-opt.h"
#include "groestl-tables.h"

/* these static function declarations go into the source file */
static HashReturn Init(GROESTL_CTX*, int);
static HashReturn Update(GROESTL_CTX*, const BitSequence*, DataLength);
static HashReturn Final(GROESTL_CTX*, BitSequence*);
/* NIST API end   */

/* compute one new state column */
#define COLUMN(x,y,i,c0,c1,c2,c3,c4,c5,c6,c7)				\
  y[i] =								\
    T[0*256+EXT_BYTE(x[c0], 0)]^					\
    T[1*256+EXT_BYTE(x[c1], 1)]^					\
    T[2*256+EXT_BYTE(x[c2], 2)]^					\
    T[3*256+EXT_BYTE(x[c3], 3)]^					\
    T[4*256+EXT_BYTE(x[c4], 0)]^					\
    T[5*256+EXT_BYTE(x[c5], 1)]^					\
    T[6*256+EXT_BYTE(x[c6], 2)]^					\
    T[7*256+EXT_BYTE(x[c7], 3)]

/* compute one round of P (short variants) */
void RND512P(u32 *x, u32 *y, u32 r) {
  x[ 0] ^= U32BIG((u32)0x00000000u)^r;
  x[ 2] ^= U32BIG((u32)0x10000000u)^r;
  x[ 4] ^= U32BIG((u32)0x20000000u)^r;
  x[ 6] ^= U32BIG((u32)0x30000000u)^r;
  x[ 8] ^= U32BIG((u32)0x40000000u)^r;
  x[10] ^= U32BIG((u32)0x50000000u)^r;
  x[12] ^= U32BIG((u32)0x60000000u)^r;
  x[14] ^= U32BIG((u32)0x70000000u)^r;
  COLUMN(x,y, 0,  0,  2,  4,  6,  9, 11, 13, 15);
  COLUMN(x,y, 1,  9, 11, 13, 15,  0,  2,  4,  6);
  COLUMN(x,y, 2,  2,  4,  6,  8, 11, 13, 15,  1);
  COLUMN(x,y, 3, 11, 13, 15,  1,  2,  4,  6,  8);
  COLUMN(x,y, 4,  4,  6,  8, 10, 13, 15,  1,  3);
  COLUMN(x,y, 5, 13, 15,  1,  3,  4,  6,  8, 10);
  COLUMN(x,y, 6,  6,  8, 10, 12, 15,  1,  3,  5);
  COLUMN(x,y, 7, 15,  1,  3,  5,  6,  8, 10, 12);
  COLUMN(x,y, 8,  8, 10, 12, 14,  1,  3,  5,  7);
  COLUMN(x,y, 9,  1,  3,  5,  7,  8, 10, 12, 14);
  COLUMN(x,y,10, 10, 12, 14,  0,  3,  5,  7,  9);
  COLUMN(x,y,11,  3,  5,  7,  9, 10, 12, 14,  0);
  COLUMN(x,y,12, 12, 14,  0,  2,  5,  7,  9, 11);
  COLUMN(x,y,13,  5,  7,  9, 11, 12, 14,  0,  2);
  COLUMN(x,y,14, 14,  0,  2,  4,  7,  9, 11, 13);
  COLUMN(x,y,15,  7,  9, 11, 13, 14,  0,  2,  4);
}

/* compute one round of Q (short variants) */
void RND512Q(u32 *x, u32 *y, u32 r) {
  x[ 0] = ~x[ 0];
  x[ 1] ^= U32BIG((u32)0xffffffffu)^r;
  x[ 2] = ~x[ 2];
  x[ 3] ^= U32BIG((u32)0xffffffefu)^r;
  x[ 4] = ~x[ 4];
  x[ 5] ^= U32BIG((u32)0xffffffdfu)^r;
  x[ 6] = ~x[ 6];
  x[ 7] ^= U32BIG((u32)0xffffffcfu)^r;
  x[ 8] = ~x[ 8];
  x[ 9] ^= U32BIG((u32)0xffffffbfu)^r;
  x[10] = ~x[10];
  x[11] ^= U32BIG((u32)0xffffffafu)^r;
  x[12] = ~x[12];
  x[13] ^= U32BIG((u32)0xffffff9fu)^r;
  x[14] = ~x[14];
  x[15] ^= U32BIG((u32)0xffffff8fu)^r;
  COLUMN(x,y, 0,  2,  6, 10, 14,  1,  5,  9, 13);
  COLUMN(x,y, 1,  1,  5,  9, 13,  2,  6, 10, 14);
  COLUMN(x,y, 2,  4,  8, 12,  0,  3,  7, 11, 15);
  COLUMN(x,y, 3,  3,  7, 11, 15,  4,  8, 12,  0);
  COLUMN(x,y, 4,  6, 10, 14,  2,  5,  9, 13,  1);
  COLUMN(x,y, 5,  5,  9, 13,  1,  6, 10, 14,  2);
  COLUMN(x,y, 6,  8, 12,  0,  4,  7, 11, 15,  3);
  COLUMN(x,y, 7,  7, 11, 15,  3,  8, 12,  0,  4);
  COLUMN(x,y, 8, 10, 14,  2,  6,  9, 13,  1,  5);
  COLUMN(x,y, 9,  9, 13,  1,  5, 10, 14,  2,  6);
  COLUMN(x,y,10, 12,  0,  4,  8, 11, 15,  3,  7);
  COLUMN(x,y,11, 11, 15,  3,  7, 12,  0,  4,  8);
  COLUMN(x,y,12, 14,  2,  6, 10, 13,  1,  5,  9);
  COLUMN(x,y,13, 13,  1,  5,  9, 14,  2,  6, 10);
  COLUMN(x,y,14,  0,  4,  8, 12, 15,  3,  7, 11);
  COLUMN(x,y,15, 15,  3,  7, 11,  0,  4,  8, 12);
}

/* compute one round of P (short variants) */
void RND1024P(u32 *x, u32 *y, u32 r) {
  x[ 0] ^= U32BIG((u32)0x00000000u)^r;
  x[ 2] ^= U32BIG((u32)0x10000000u)^r;
  x[ 4] ^= U32BIG((u32)0x20000000u)^r;
  x[ 6] ^= U32BIG((u32)0x30000000u)^r;
  x[ 8] ^= U32BIG((u32)0x40000000u)^r;
  x[10] ^= U32BIG((u32)0x50000000u)^r;
  x[12] ^= U32BIG((u32)0x60000000u)^r;
  x[14] ^= U32BIG((u32)0x70000000u)^r;
  x[16] ^= U32BIG((u32)0x80000000u)^r;
  x[18] ^= U32BIG((u32)0x90000000u)^r;
  x[20] ^= U32BIG((u32)0xa0000000u)^r;
  x[22] ^= U32BIG((u32)0xb0000000u)^r;
  x[24] ^= U32BIG((u32)0xc0000000u)^r;
  x[26] ^= U32BIG((u32)0xd0000000u)^r;
  x[28] ^= U32BIG((u32)0xe0000000u)^r;
  x[30] ^= U32BIG((u32)0xf0000000u)^r;

  COLUMN(x,y, 0, 0, 2, 4, 6, 9,11,13,23);
  COLUMN(x,y, 2, 2, 4, 6, 8,11,13,15,25);
  COLUMN(x,y, 4, 4, 6, 8,10,13,15,17,27);
  COLUMN(x,y, 6, 6, 8,10,12,15,17,19,29);
  COLUMN(x,y, 8, 8,10,12,14,17,19,21,31);
  COLUMN(x,y,10,10,12,14,16,19,21,23, 1);
  COLUMN(x,y,12,12,14,16,18,21,23,25, 3);
  COLUMN(x,y,14,14,16,18,20,23,25,27, 5);
  COLUMN(x,y,16,16,18,20,22,25,27,29, 7);
  COLUMN(x,y,18,18,20,22,24,27,29,31, 9);
  COLUMN(x,y,20,20,22,24,26,29,31, 1,11);
  COLUMN(x,y,22,22,24,26,28,31, 1, 3,13);
  COLUMN(x,y,24,24,26,28,30, 1, 3, 5,15);
  COLUMN(x,y,26,26,28,30, 0, 3, 5, 7,17);
  COLUMN(x,y,28,28,30, 0, 2, 5, 7, 9,19);
  COLUMN(x,y,30,30, 0, 2, 4, 7, 9,11,21);

  COLUMN(x,y, 1, 9,11,13,23, 0, 2, 4, 6);
  COLUMN(x,y, 3,11,13,15,25, 2, 4, 6, 8);
  COLUMN(x,y, 5,13,15,17,27, 4, 6, 8,10);
  COLUMN(x,y, 7,15,17,19,29, 6, 8,10,12);
  COLUMN(x,y, 9,17,19,21,31, 8,10,12,14);
  COLUMN(x,y,11,19,21,23, 1,10,12,14,16);
  COLUMN(x,y,13,21,23,25, 3,12,14,16,18);
  COLUMN(x,y,15,23,25,27, 5,14,16,18,20);
  COLUMN(x,y,17,25,27,29, 7,16,18,20,22);
  COLUMN(x,y,19,27,29,31, 9,18,20,22,24);
  COLUMN(x,y,21,29,31, 1,11,20,22,24,26);
  COLUMN(x,y,23,31, 1, 3,13,22,24,26,28);
  COLUMN(x,y,25, 1, 3, 5,15,24,26,28,30);
  COLUMN(x,y,27, 3, 5, 7,17,26,28,30, 0);
  COLUMN(x,y,29, 5, 7, 9,19,28,30, 0, 2);
  COLUMN(x,y,31, 7, 9,11,21,30, 0, 2, 4);
}

/* compute one round of Q (short variants) */
void RND1024Q(u32 *x, u32 *y, u32 r) {
  x[ 0] = ~x[ 0];
  x[ 1] ^= U32BIG((u32)0xffffffffu)^r;
  x[ 2] = ~x[ 2];
  x[ 3] ^= U32BIG((u32)0xffffffefu)^r;
  x[ 4] = ~x[ 4];
  x[ 5] ^= U32BIG((u32)0xffffffdfu)^r;
  x[ 6] = ~x[ 6];
  x[ 7] ^= U32BIG((u32)0xffffffcfu)^r;
  x[ 8] = ~x[ 8];
  x[ 9] ^= U32BIG((u32)0xffffffbfu)^r;
  x[10] = ~x[10];
  x[11] ^= U32BIG((u32)0xffffffafu)^r;
  x[12] = ~x[12];
  x[13] ^= U32BIG((u32)0xffffff9fu)^r;
  x[14] = ~x[14];
  x[15] ^= U32BIG((u32)0xffffff8fu)^r;
  x[16] = ~x[16];
  x[17] ^= U32BIG((u32)0xffffff7fu)^r;
  x[18] = ~x[18];
  x[19] ^= U32BIG((u32)0xffffff6fu)^r;
  x[20] = ~x[20];
  x[21] ^= U32BIG((u32)0xffffff5fu)^r;
  x[22] = ~x[22];
  x[23] ^= U32BIG((u32)0xffffff4fu)^r;
  x[24] = ~x[24];
  x[25] ^= U32BIG((u32)0xffffff3fu)^r;
  x[26] = ~x[26];
  x[27] ^= U32BIG((u32)0xffffff2fu)^r;
  x[28] = ~x[28];
  x[29] ^= U32BIG((u32)0xffffff1fu)^r;
  x[30] = ~x[30];
  x[31] ^= U32BIG((u32)0xffffff0fu)^r;

  COLUMN(x,y, 0,  2,  6, 10, 22,  1,  5,  9, 13);
  COLUMN(x,y, 1,  1,  5,  9, 13,  2,  6, 10, 22);
  COLUMN(x,y, 2,  4,  8, 12, 24,  3,  7, 11, 15);
  COLUMN(x,y, 3,  3,  7, 11, 15,  4,  8, 12, 24);
  COLUMN(x,y, 4,  6, 10, 14, 26,  5,  9, 13, 17);
  COLUMN(x,y, 5,  5,  9, 13, 17,  6, 10, 14, 26);
  COLUMN(x,y, 6,  8, 12, 16, 28,  7, 11, 15, 19);
  COLUMN(x,y, 7,  7, 11, 15, 19,  8, 12, 16, 28);
  COLUMN(x,y, 8, 10, 14, 18, 30,  9, 13, 17, 21);
  COLUMN(x,y, 9,  9, 13, 17, 21, 10, 14, 18, 30);
  COLUMN(x,y,10, 12, 16, 20,  0, 11, 15, 19, 23);
  COLUMN(x,y,11, 11, 15, 19, 23, 12, 16, 20,  0);
  COLUMN(x,y,12, 14, 18, 22,  2, 13, 17, 21, 25);
  COLUMN(x,y,13, 13, 17, 21, 25, 14, 18, 22,  2);
  COLUMN(x,y,14, 16, 20, 24,  4, 15, 19, 23, 27);
  COLUMN(x,y,15, 15, 19, 23, 27, 16, 20, 24,  4);

  COLUMN(x,y,16, 18, 22, 26,  6, 17, 21, 25, 29);
  COLUMN(x,y,17, 17, 21, 25, 29, 18, 22, 26,  6);
  COLUMN(x,y,18, 20, 24, 28,  8, 19, 23, 27, 31);
  COLUMN(x,y,19, 19, 23, 27, 31, 20, 24, 28,  8);
  COLUMN(x,y,20, 22, 26, 30, 10, 21, 25, 29,  1);
  COLUMN(x,y,21, 21, 25, 29,  1, 22, 26, 30, 10);
  COLUMN(x,y,22, 24, 28,  0, 12, 23, 27, 31,  3);
  COLUMN(x,y,23, 23, 27, 31,  3, 24, 28,  0, 12);
  COLUMN(x,y,24, 26, 30,  2, 14, 25, 29,  1,  5);
  COLUMN(x,y,25, 25, 29,  1,  5, 26, 30,  2, 14);
  COLUMN(x,y,26, 28,  0,  4, 16, 27, 31,  3,  7);
  COLUMN(x,y,27, 27, 31,  3,  7, 28,  0,  4, 16);
  COLUMN(x,y,28, 30,  2,  6, 18, 29,  1,  5,  9);
  COLUMN(x,y,29, 29,  1,  5,  9, 30,  2,  6, 18);
  COLUMN(x,y,30,  0,  4,  8, 20, 31,  3,  7, 11);
  COLUMN(x,y,31, 31,  3,  7, 11,  0,  4,  8, 20);
}


/* compute compression function (short variants) */
static void F512(u32 *h, const u32 *m) {
  int i;
  u32 Ptmp[2*COLS512];
  u32 Qtmp[2*COLS512];
  u32 y[2*COLS512];
  u32 z[2*COLS512];

  for (i = 0; i < 2*COLS512; i++) {
    z[i] = m[i];
    Ptmp[i] = h[i]^m[i];
  }

  /* compute Q(m) */
  RND512Q(z, y, U32BIG((u32)0x00000000u));
  RND512Q(y, z, U32BIG((u32)0x00000001u));
  RND512Q(z, y, U32BIG((u32)0x00000002u));
  RND512Q(y, z, U32BIG((u32)0x00000003u));
  RND512Q(z, y, U32BIG((u32)0x00000004u));
  RND512Q(y, z, U32BIG((u32)0x00000005u));
  RND512Q(z, y, U32BIG((u32)0x00000006u));
  RND512Q(y, z, U32BIG((u32)0x00000007u));
  RND512Q(z, y, U32BIG((u32)0x00000008u));
  RND512Q(y, Qtmp, U32BIG((u32)0x00000009u));

  /* compute P(h+m) */
  RND512P(Ptmp, y, U32BIG((u32)0x00000000u));
  RND512P(y, z, U32BIG((u32)0x01000000u));
  RND512P(z, y, U32BIG((u32)0x02000000u));
  RND512P(y, z, U32BIG((u32)0x03000000u));
  RND512P(z, y, U32BIG((u32)0x04000000u));
  RND512P(y, z, U32BIG((u32)0x05000000u));
  RND512P(z, y, U32BIG((u32)0x06000000u));
  RND512P(y, z, U32BIG((u32)0x07000000u));
  RND512P(z, y, U32BIG((u32)0x08000000u));
  RND512P(y, Ptmp, U32BIG((u32)0x09000000u));

  /* compute P(h+m) + Q(m) + h */
  for (i = 0; i < 2*COLS512; i++) {
    h[i] ^= Ptmp[i]^Qtmp[i];
  }
}

/* compute compression function (long variants) */
static void F1024(u32 *h, const u32 *m) {
  int i;
  u32 Ptmp[2*COLS1024];
  u32 Qtmp[2*COLS1024];
  u32 y[2*COLS1024];
  u32 z[2*COLS1024];

  for (i = 0; i < 2*COLS1024; i++) {
    z[i] = m[i];
    Ptmp[i] = h[i]^m[i];
  }

  /* compute Q(m) */
  RND1024Q(z, y, U32BIG((u32)0x00000000u));
  for (i = 1; i < ROUNDS1024-1; i += 2) {
    RND1024Q(y, z, U32BIG((u32)i));
    RND1024Q(z, y, U32BIG((u32)i+1));
  }
  RND1024Q(y, Qtmp, U32BIG((u32)0x0000000du));

  /* compute P(h+m) */
  RND1024P(Ptmp, y, U32BIG((u32)0x00000000u));
  for (i = 1; i < ROUNDS1024-1; i += 2) {
    RND1024P(y, z, U32BIG((u32)i<<24));
    RND1024P(z, y, U32BIG(((u32)i+1)<<24));
  }
  RND1024P(y, Ptmp, U32BIG(((u32)ROUNDS1024-1)<<24));

  /* compute P(h+m) + Q(m) + h */
  for (i = 0; i < 2*COLS1024; i++) {
    h[i] ^= Ptmp[i]^Qtmp[i];
  }
}


/* digest up to msglen bytes of input (full blocks only) */
static void Transform(GROESTL_CTX *ctx, 
	       const u8 *input, 
	       int msglen) {
  /* determine variant, SHORT or LONG, and select underlying
     compression function based on the variant */
  void (*F)(u32*,const u32*);
  switch ( ctx->v ) {
  case SHORT : F = &F512; break;
  case LONG  : 
  default    : F = &F1024; break;
  }

  /* digest message, one block at a time */
  for (; msglen >= ctx->statesize; 
       msglen -= ctx->statesize, input += ctx->statesize) {
    F(ctx->chaining,(u32*)input);

    /* increment block counter */
    ctx->block_counter1++;
    if (ctx->block_counter1 == 0) ctx->block_counter2++;
  }
}

/* given state h, do h <- P(h)+h */
static void OutputTransformation(GROESTL_CTX *ctx) {
  int j;
  u32 *temp, *y, *z;
  temp = malloc(2*ctx->columns*sizeof(u32));
  y    = malloc(2*ctx->columns*sizeof(u32));
  z    = malloc(2*ctx->columns*sizeof(u32));

  /* determine variant */
  switch (ctx->v) {
  case SHORT :
    for (j = 0; j < 2*COLS512; j++) {
      temp[j] = ctx->chaining[j];
    }
    RND512P(temp, y, U32BIG((u32)0x00000000u));
    RND512P(y, z, U32BIG((u32)0x01000000u));
    RND512P(z, y, U32BIG((u32)0x02000000u));
    RND512P(y, z, U32BIG((u32)0x03000000u));
    RND512P(z, y, U32BIG((u32)0x04000000u));
    RND512P(y, z, U32BIG((u32)0x05000000u));
    RND512P(z, y, U32BIG((u32)0x06000000u));
    RND512P(y, z, U32BIG((u32)0x07000000u));
    RND512P(z, y, U32BIG((u32)0x08000000u));
    RND512P(y, temp, U32BIG((u32)0x09000000u));
    for (j = 0; j < 2*COLS512; j++) {
      ctx->chaining[j] ^= temp[j];
    }
    break;
  case LONG  :
    for (j = 0; j < 2*COLS1024; j++) {
      temp[j] = ctx->chaining[j];
    }
    RND1024P(temp,y,U32BIG((u32)0x00000000u));
    for (j = 1; j < ROUNDS1024-1; j += 2) {
      RND1024P(y,z,U32BIG((u32)j<<24));
      RND1024P(z,y,U32BIG(((u32)j+1)<<24));
    }
    RND1024P(y,temp,U32BIG(((u32)ROUNDS1024-1)<<24));
    for (j = 0; j < 2*COLS1024; j++) {
      ctx->chaining[j] ^= temp[j];
    }
    break;
  }

  free(temp);
  free(y);
  free(z);
}

/* initialise context */
static HashReturn Init(GROESTL_CTX* ctx,
		int hashbitlen) {
  /* output size (in bits) must be a positive integer less than or
     equal to 512, and divisible by 8 */
  if (hashbitlen <= 0 || (hashbitlen%8) || hashbitlen > 512)
    return BAD_HASHBITLEN;

  /* set number of state columns and state size depending on
     variant */
  if (hashbitlen <= 256) {
    ctx->columns = COLS512;
    ctx->statesize = SIZE512;
    ctx->v = SHORT;
  }
  else {
    ctx->columns = COLS1024;
    ctx->statesize = SIZE1024;
    ctx->v = LONG;
  }

  /* allocate memory for state and data buffer */
  ctx->chaining = calloc(ctx->statesize,1);
  ctx->buffer = malloc(ctx->statesize);
  if (ctx->chaining == NULL || ctx->buffer == NULL)
    return FAIL;

  /* set initial value */
  ctx->chaining[2*ctx->columns-1] = U32BIG((u32)hashbitlen);

  /* set other variables */
  ctx->hashbitlen = hashbitlen;
  ctx->buf_ptr = 0;
  ctx->block_counter1 = 0;
  ctx->block_counter2 = 0;
  ctx->bits_in_last_byte = 0;

  return SUCCESS;
}

/* update state with databitlen bits of input */
static HashReturn Update(GROESTL_CTX* ctx,
		  const BitSequence* input,
		  DataLength databitlen) {
  int index = 0;
  int msglen = (int)(databitlen/8);
  int rem = (int)(databitlen%8);

  /* non-integral number of message bytes can only be supplied in the
     last call to this function */
  if (ctx->bits_in_last_byte) return FAIL;

  /* if the buffer contains data that has not yet been digested, first
     add data to buffer until full */
  if (ctx->buf_ptr) {
    while (ctx->buf_ptr < ctx->statesize && index < msglen) {
      ctx->buffer[(int)ctx->buf_ptr++] = input[index++];
    }
    if (ctx->buf_ptr < ctx->statesize) {
      /* buffer still not full, return */
      if (rem) {
	ctx->bits_in_last_byte = rem;
	ctx->buffer[(int)ctx->buf_ptr++] = input[index];
      }
      return SUCCESS;
    }

    /* digest buffer */
    ctx->buf_ptr = 0;
    Transform(ctx, ctx->buffer, ctx->statesize);
  }

  /* digest bulk of message */
  Transform(ctx, input+index, msglen-index);
  index += ((msglen-index)/ctx->statesize)*ctx->statesize;

  /* store remaining data in buffer */
  while (index < msglen) {
    ctx->buffer[(int)ctx->buf_ptr++] = input[index++];
  }

  /* if non-integral number of bytes have been supplied, store
     remaining bits in last byte, together with information about
     number of bits */
  if (rem) {
    ctx->bits_in_last_byte = rem;
    ctx->buffer[(int)ctx->buf_ptr++] = input[index];
  }
  return SUCCESS;
}

#define BILB ctx->bits_in_last_byte

/* finalise: process remaining data (including padding), perform
   output transformation, and write hash result to 'output' */
static HashReturn Final(GROESTL_CTX* ctx,
		 BitSequence* output) {
  int i, j = 0, hashbytelen = ctx->hashbitlen/8;
  u8 *s = (BitSequence*)ctx->chaining;

  /* pad with '1'-bit and first few '0'-bits */
  if (BILB) {
    ctx->buffer[(int)ctx->buf_ptr-1] &= ((1<<BILB)-1)<<(8-BILB);
    ctx->buffer[(int)ctx->buf_ptr-1] ^= 0x1<<(7-BILB);
    BILB = 0;
  }
  else ctx->buffer[(int)ctx->buf_ptr++] = 0x80;

  /* pad with '0'-bits */
  if (ctx->buf_ptr > ctx->statesize-LENGTHFIELDLEN) {
    /* padding requires two blocks */
    while (ctx->buf_ptr < ctx->statesize) {
      ctx->buffer[(int)ctx->buf_ptr++] = 0;
    }
    /* digest first padding block */
    Transform(ctx, ctx->buffer, ctx->statesize);
    ctx->buf_ptr = 0;
  }
  while (ctx->buf_ptr < ctx->statesize-LENGTHFIELDLEN) {
    ctx->buffer[(int)ctx->buf_ptr++] = 0;
  }

  /* length padding */
  ctx->block_counter1++;
  if (ctx->block_counter1 == 0) ctx->block_counter2++;
  ctx->buf_ptr = ctx->statesize;

  while (ctx->buf_ptr > ctx->statesize-(int)sizeof(u32)) {
    ctx->buffer[(int)--ctx->buf_ptr] = (u8)ctx->block_counter1;
    ctx->block_counter1 >>= 8;
  }
  while (ctx->buf_ptr > ctx->statesize-LENGTHFIELDLEN) {
    ctx->buffer[(int)--ctx->buf_ptr] = (u8)ctx->block_counter2;
    ctx->block_counter2 >>= 8;
  }

  /* digest final padding block */
  Transform(ctx, ctx->buffer, ctx->statesize);
  /* perform output transformation */
  OutputTransformation(ctx);

  /* store hash result in output */
  for (i = ctx->statesize-hashbytelen; i < ctx->statesize; i++,j++) {
	if (output) output[j] = s[i];
	ctx->out[j] = s[i];
  }

  /* zeroise relevant variables and deallocate memory */
  for (i = 0; i < ctx->columns; i++) {
    ctx->chaining[i] = 0;
  }
  for (i = 0; i < ctx->statesize; i++) {
    ctx->buffer[i] = 0;
  }
  free(ctx->chaining);
  free(ctx->buffer);

  return SUCCESS;
}



/* 
 * parameter safe wrappers for GROESTL routines for each hash length
 */

 /*************************** 224 ************************************/

HashReturn GROESTL224_init (hashState  *state, int hashbitlen)
{
    /* verify correct hash length   */
    if (hashbitlen != HASH_BITLENGTH_GROESTL_224)
        return BAD_HASHBITLEN;

    /* allocate context and fill it */
    GROESTL_CTX *context = (GROESTL_CTX *)malloc (sizeof (GROESTL_CTX));
    memset (context, 0, sizeof (GROESTL_CTX));
    context->hashbitlen = HASH_BITLENGTH_GROESTL_224;
    context->magic = HASH_MAGIC_GROESTL_224;
	*state = (hashState *) context;
	return Init (context, hashbitlen);
}

HashReturn  GROESTL224_update (
    hashState state,          /* previously initialized context */
    const BitSequence *buffer,  /* bit buffer, first bit is MSB in [0] */
    DataLength databitlen)      /* number of bits to process from buffer */
{
    /* can be called once or many times */
    /* verify correct hashbitlen and magic  */

    GROESTL_CTX *context = (GROESTL_CTX *) state;
    if (context->hashbitlen != HASH_BITLENGTH_GROESTL_224)
        return BAD_HASHBITLEN;

    if (context->magic != HASH_MAGIC_GROESTL_224)
        return BAD_ALGORITHM;

	return Update (context, buffer, databitlen);
}

HashReturn  GROESTL224_final (hashState state, BitSequence *hashval)
{
    GROESTL_CTX *context = (GROESTL_CTX *) state;
    if (context->hashbitlen != HASH_BITLENGTH_GROESTL_224)
        return BAD_HASHBITLEN;

    if (context->magic != HASH_MAGIC_GROESTL_224)
        return BAD_ALGORITHM;

	return Final (context, hashval);
}

HashReturn GROESTL224_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval)
{
    hashState   state;
    HashReturn  retval;

    retval = GROESTL224_init (&state, HASH_BITLENGTH_GROESTL_224);
    if (retval != SUCCESS) {
        fprintf (stderr, "GROESTL224_init failed, reason %d, hash length %d\n",
                 retval, HASH_BITLENGTH_GROESTL_224);
        exit (1);
    }

    retval = GROESTL224_update (state, data, databitlen);
    if (retval != SUCCESS) {
        fprintf (stderr, "GROESTL224_update failed, reason %d\n", retval);
        exit (1);
    }

    retval = GROESTL224_final (state, hashval);
    if (retval != SUCCESS) {
        fprintf (stderr, "GROESTL224_final failed, reason %d\n", retval);
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
HashReturn GROESTL224_File (hashState state, FILE *in)
{
	GROESTL_CTX *context = (GROESTL_CTX *) state;
	int len;
	unsigned char buffer[BUFFERSIZE];
	HashReturn retval;

	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_GROESTL_224)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_GROESTL_224)
		return BAD_ALGORITHM;

	while ((len = fread (buffer, 1, BUFFERSIZE, in))) {
		retval = GROESTL224_update (context, buffer, (DataLength)len << 3);
		if (retval != SUCCESS) return retval;
	}
	retval = GROESTL224_final (context, NULL);

	fclose (in);
	return retval;
}

HashReturn GROESTL224_HashToByte (hashState state, BYTE *out) 
{
	GROESTL_CTX *context = (GROESTL_CTX *) state;

	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_GROESTL_224)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_GROESTL_224)
		return BAD_ALGORITHM;

	memcpy (out, context->out, HASH_LENGTH_GROESTL_224);
	return SUCCESS;
}


 /*************************** 256 ************************************/

HashReturn GROESTL256_init (hashState  *state, int hashbitlen)
{
    /* verify correct hash length   */
    if (hashbitlen != HASH_BITLENGTH_GROESTL_256)
        return BAD_HASHBITLEN;

    /* allocate context and fill it */
    GROESTL_CTX *context = (GROESTL_CTX *)malloc (sizeof (GROESTL_CTX));
    memset (context, 0, sizeof (GROESTL_CTX));
    context->hashbitlen = HASH_BITLENGTH_GROESTL_256;
    context->magic = HASH_MAGIC_GROESTL_256;
	*state = (hashState *) context;
	return Init (context, hashbitlen);
}

HashReturn  GROESTL256_update (
    hashState state,          /* previously initialized context */
    const BitSequence *buffer,  /* bit buffer, first bit is MSB in [0] */
    DataLength databitlen)      /* number of bits to process from buffer */
{
    /* can be called once or many times */
    /* verify correct hashbitlen and magic  */

    GROESTL_CTX *context = (GROESTL_CTX *) state;
    if (context->hashbitlen != HASH_BITLENGTH_GROESTL_256)
        return BAD_HASHBITLEN;

    if (context->magic != HASH_MAGIC_GROESTL_256)
        return BAD_ALGORITHM;

	return Update (context, buffer, databitlen);
}

HashReturn  GROESTL256_final (hashState state, BitSequence *hashval)
{
    GROESTL_CTX *context = (GROESTL_CTX *) state;
    if (context->hashbitlen != HASH_BITLENGTH_GROESTL_256)
        return BAD_HASHBITLEN;

    if (context->magic != HASH_MAGIC_GROESTL_256)
        return BAD_ALGORITHM;

	return Final (context, hashval);
}

HashReturn GROESTL256_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval)
{
    hashState   state;
    HashReturn  retval;

    retval = GROESTL256_init (&state, HASH_BITLENGTH_GROESTL_256);
    if (retval != SUCCESS) {
        fprintf (stderr, "GROESTL256_init failed, reason %d, hash length %d\n",
                 retval, HASH_BITLENGTH_GROESTL_256);
        exit (1);
    }

    retval = GROESTL256_update (state, data, databitlen);
    if (retval != SUCCESS) {
        fprintf (stderr, "GROESTL256_update failed, reason %d\n", retval);
        exit (1);
    }

    retval = GROESTL256_final (state, hashval);
    if (retval != SUCCESS) {
        fprintf (stderr, "GROESTL256_final failed, reason %d\n", retval);
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
HashReturn GROESTL256_File (hashState state, FILE *in)
{
	GROESTL_CTX *context = (GROESTL_CTX *) state;
	int len;
	unsigned char buffer[BUFFERSIZE];
	HashReturn retval;

	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_GROESTL_256)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_GROESTL_256)
		return BAD_ALGORITHM;

	while ((len = fread (buffer, 1, BUFFERSIZE, in))) {
		retval = GROESTL256_update (context, buffer, (DataLength)len << 3);
		if (retval != SUCCESS) return retval;
	}
	retval = GROESTL256_final (context, NULL);

	fclose (in);
	return retval;
}

HashReturn GROESTL256_HashToByte (hashState state, BYTE *out) 
{
	GROESTL_CTX *context = (GROESTL_CTX *) state;

	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_GROESTL_256)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_GROESTL_256)
		return BAD_ALGORITHM;

	memcpy (out, context->out, HASH_LENGTH_GROESTL_256);
	return SUCCESS;
}


 /*************************** 384 ************************************/

HashReturn GROESTL384_init (hashState  *state, int hashbitlen)
{
    /* verify correct hash length   */
    if (hashbitlen != HASH_BITLENGTH_GROESTL_384)
        return BAD_HASHBITLEN;

    /* allocate context and fill it */
    GROESTL_CTX *context = (GROESTL_CTX *)malloc (sizeof (GROESTL_CTX));
    memset (context, 0, sizeof (GROESTL_CTX));
    context->hashbitlen = HASH_BITLENGTH_GROESTL_384;
    context->magic = HASH_MAGIC_GROESTL_384;
	*state = (hashState *) context;
	return Init (context, hashbitlen);
}

HashReturn  GROESTL384_update (
    hashState state,          /* previously initialized context */
    const BitSequence *buffer,  /* bit buffer, first bit is MSB in [0] */
    DataLength databitlen)      /* number of bits to process from buffer */
{
    /* can be called once or many times */
    /* verify correct hashbitlen and magic  */

    GROESTL_CTX *context = (GROESTL_CTX *) state;
    if (context->hashbitlen != HASH_BITLENGTH_GROESTL_384)
        return BAD_HASHBITLEN;

    if (context->magic != HASH_MAGIC_GROESTL_384)
        return BAD_ALGORITHM;

	return Update (context, buffer, databitlen);
}

HashReturn  GROESTL384_final (hashState state, BitSequence *hashval)
{
    GROESTL_CTX *context = (GROESTL_CTX *) state;
    if (context->hashbitlen != HASH_BITLENGTH_GROESTL_384)
        return BAD_HASHBITLEN;

    if (context->magic != HASH_MAGIC_GROESTL_384)
        return BAD_ALGORITHM;

	return Final (context, hashval);
}

HashReturn GROESTL384_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval)
{
    hashState   state;
    HashReturn  retval;

    retval = GROESTL384_init (&state, HASH_BITLENGTH_GROESTL_384);
    if (retval != SUCCESS) {
        fprintf (stderr, "GROESTL384_init failed, reason %d, hash length %d\n",
                 retval, HASH_BITLENGTH_GROESTL_384);
        exit (1);
    }

    retval = GROESTL384_update (state, data, databitlen);
    if (retval != SUCCESS) {
        fprintf (stderr, "GROESTL384_update failed, reason %d\n", retval);
        exit (1);
    }

    retval = GROESTL384_final (state, hashval);
    if (retval != SUCCESS) {
        fprintf (stderr, "GROESTL384_final failed, reason %d\n", retval);
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
HashReturn GROESTL384_File (hashState state, FILE *in)
{
	GROESTL_CTX *context = (GROESTL_CTX *) state;
	int len;
	unsigned char buffer[BUFFERSIZE];
	HashReturn retval;

	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_GROESTL_384)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_GROESTL_384)
		return BAD_ALGORITHM;

	while ((len = fread (buffer, 1, BUFFERSIZE, in))) {
		retval = GROESTL384_update (context, buffer, (DataLength)len << 3);
		if (retval != SUCCESS) return retval;
	}
	retval = GROESTL384_final (context, NULL);

	fclose (in);
	return retval;
}

HashReturn GROESTL384_HashToByte (hashState state, BYTE *out) 
{
	GROESTL_CTX *context = (GROESTL_CTX *) state;

	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_GROESTL_384)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_GROESTL_384)
		return BAD_ALGORITHM;

	memcpy (out, context->out, HASH_LENGTH_GROESTL_384);
	return SUCCESS;
}


 /*************************** 512 ************************************/

HashReturn GROESTL512_init (hashState  *state, int hashbitlen)
{
    /* verify correct hash length   */
    if (hashbitlen != HASH_BITLENGTH_GROESTL_512)
        return BAD_HASHBITLEN;

    /* allocate context and fill it */
    GROESTL_CTX *context = (GROESTL_CTX *)malloc (sizeof (GROESTL_CTX));
    memset (context, 0, sizeof (GROESTL_CTX));
    context->hashbitlen = HASH_BITLENGTH_GROESTL_512;
    context->magic = HASH_MAGIC_GROESTL_512;
	*state = (hashState *) context;
	return Init (context, hashbitlen);
}

HashReturn  GROESTL512_update (
    hashState state,          /* previously initialized context */
    const BitSequence *buffer,  /* bit buffer, first bit is MSB in [0] */
    DataLength databitlen)      /* number of bits to process from buffer */
{
    /* can be called once or many times */
    /* verify correct hashbitlen and magic  */

    GROESTL_CTX *context = (GROESTL_CTX *) state;
    if (context->hashbitlen != HASH_BITLENGTH_GROESTL_512)
        return BAD_HASHBITLEN;

    if (context->magic != HASH_MAGIC_GROESTL_512)
        return BAD_ALGORITHM;

	return Update (context, buffer, databitlen);
}

HashReturn  GROESTL512_final (hashState state, BitSequence *hashval)
{
    GROESTL_CTX *context = (GROESTL_CTX *) state;
    if (context->hashbitlen != HASH_BITLENGTH_GROESTL_512)
        return BAD_HASHBITLEN;

    if (context->magic != HASH_MAGIC_GROESTL_512)
        return BAD_ALGORITHM;

	return Final (context, hashval);
}

HashReturn GROESTL512_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval)
{
    hashState   state;
    HashReturn  retval;

    retval = GROESTL512_init (&state, HASH_BITLENGTH_GROESTL_512);
    if (retval != SUCCESS) {
        fprintf (stderr, "GROESTL512_init failed, reason %d, hash length %d\n",
                 retval, HASH_BITLENGTH_GROESTL_512);
        exit (1);
    }

    retval = GROESTL512_update (state, data, databitlen);
    if (retval != SUCCESS) {
        fprintf (stderr, "GROESTL512_update failed, reason %d\n", retval);
        exit (1);
    }

    retval = GROESTL512_final (state, hashval);
    if (retval != SUCCESS) {
        fprintf (stderr, "GROESTL512_final failed, reason %d\n", retval);
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
HashReturn GROESTL512_File (hashState state, FILE *in)
{
	GROESTL_CTX *context = (GROESTL_CTX *) state;
	int len;
	unsigned char buffer[BUFFERSIZE];
	HashReturn retval;

	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_GROESTL_512)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_GROESTL_512)
		return BAD_ALGORITHM;

	while ((len = fread (buffer, 1, BUFFERSIZE, in))) {
		retval = GROESTL512_update (context, buffer, (DataLength)len << 3);
		if (retval != SUCCESS) return retval;
	}
	retval = GROESTL512_final (context, NULL);

	fclose (in);
	return retval;
}

HashReturn GROESTL512_HashToByte (hashState state, BYTE *out) 
{
	GROESTL_CTX *context = (GROESTL_CTX *) state;

	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_GROESTL_512)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_GROESTL_512)
		return BAD_ALGORITHM;

	memcpy (out, context->out, HASH_LENGTH_GROESTL_512);
	return SUCCESS;
}

