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

// generate LASH PRNG sequence
// y0 = 54321
// y[i+1] = y[i]*y[i] + 2 (mod 2^31 - 1)
// a[i] = y[i] mod 256
//
// hvf 16.10.2008
//
// hvf 19.01.2009
// generate tables on the fly

#include "lash.h"

void mk_avector (int n, BYTE *A)
{
	uint64 y0 = 54321;
	int i;
	A[0] = y0 % 256;
	uint64 yi = y0;
	for (i=1; i<n; i++) {
		yi = yi*yi + 2;
		yi %= 0x7fffffffUL;
		A[i] = yi & 0xff;
	}
#ifdef DEBUG
	printf ("\nArray A (%d)\n", n);
	int j;
	for (j=0; j<n; j+= 20) {
		printf ("%3d", j);
		for (i=j; i<j+20 && i<n; i++) {
			printf (" %2x", A[i]);
		}
		printf ("\n");
	}
	printf ("\n");
#endif
}

void    mk_hvector (int len1, int len2, BYTE *Arr1, BYTE *Arr2)
{
//	BYTE Arr1[len1];
//	BYTE Arr2[len1][len2];
	int i, j;
	for (j=0; j<len2;j++) {
		for (i=0; i<len1; i++) {
			Arr2[addr2(i,j,len2)] = Arr1[(len1+j-i)%len1];
		}
	}
#ifdef DEBUG
	printf ("\nMatrix H (%dx%d)\n", len1, len2);
	for (j=0; j<len1; j++) {
		printf ("%3d", j);
		for (i=0; i<len2; i++) {
			printf (" %2x", Arr2[addr2(j,i,len2)]);
		}
		printf ("\n");
	}
	printf ("\n");
#endif
	return;
}

void    mk_gvector (int len1, int len2, BYTE *Arr2, BYTE *Arr3)
{
//	BYTE Arr2[len1][len2];
//	BYTE Arr3[len1/8][256][len2];
	int i, j, k, b;
	int n8 = len1 / 8;
	for (j=0; j<n8; j++) {
		for (b=0; b<256; b++) {
			for (k=0; k<len2; k++) {
				// G[j][b][k] = 0;
				Arr3[addr3(j,b,256,k,len2)] = 0;
				for (i=7; i>=0; i--) {
					if ((b>>i) & 0x01) {
						// G[j][b][k] += H[8*j+7-i][k];
						Arr3[addr3(j,b,256,k,len2)] += 
							Arr2[addr2(8*j+7-i,k,len2)];
					}
				}
			}
		}
	}

#ifdef DEBUG
	printf ("\nMatrix G (%dx%dx%d)\n", n8, 256, len2);
	for (j=0; j<n8; j++) {
		for (b=0; b<256; b++) {
			printf ("%3d b=%d", j, b);
			for (k=0; k<len2; k++) {
				printf (" %2x",  Arr3[addr3(j,b,256,k,len2)]);
			}
			printf ("\n");
		}
	}
	printf ("\n");
#endif
	return;
}
