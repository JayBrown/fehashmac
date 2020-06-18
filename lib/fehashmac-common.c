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

/* hvf 07.02.2009 common bit handlers for int and long long */

#include "generic.h"
#include <stdio.h>
#include <stdlib.h>
#define DEBUG
#undef  DEBUG

/* AddBitsToArrayOfInts adds bits from an array of BitSequence (unsigned char)
 * to an array of unsigned int. At most one byte full of bits is processed
 * per call. The function returns the number of bits that have been processed.
 */

DataLength AddBitsToArrayOfInts (
	unsigned int array[],	/* the array to which we add bits */
	int	bitsusedinarray,	/* says how many bits are already stored in array */
	const BitSequence databuffer[],	/* buffer containing the bits */
	DataLength	bitsindatabuffer,	/* total number of bits in the databuffer,
                                     * some may already have been consumed */
	int	firstbitposindatabuffer /* position of next bit to be consumed */
	)
{
#ifdef DEBUG
	printf ("AddBitsToArrayOfInts: bitsusedinarray = %d, "
		"bitsindatabuffer = %lld, "
		"array word where we will store bits [%d] = %#x, "
		"firstbitposindatabuffer = %d, first data word [%d] = %#x\n", 
		bitsusedinarray, 
		bitsindatabuffer, 
		INTINDEX(bitsusedinarray), array[INTINDEX(bitsusedinarray)], 
		firstbitposindatabuffer, 
		BYTEINDEX(firstbitposindatabuffer), 
		databuffer[BYTEINDEX(firstbitposindatabuffer)]);
#endif
	unsigned int splicevalue;
	DataLength bitscopied;
	int	leftshift;
	splicevalue = ((unsigned int)databuffer[BYTEINDEX(firstbitposindatabuffer)])
				 & INTMASK(bitsusedinarray, firstbitposindatabuffer,
					bitsindatabuffer);

	leftshift = INTLEFTSHIFT (bitsusedinarray, firstbitposindatabuffer);
	if (leftshift >= 0) {
		array[INTINDEX(bitsusedinarray)] |= splicevalue << leftshift;
	}
	else {
		array[INTINDEX(bitsusedinarray)] |= splicevalue >> -leftshift;
	}
	bitscopied = INTBITS2COPY (bitsusedinarray, firstbitposindatabuffer, 
					bitsindatabuffer);
	return bitscopied;
}


/* AddBitsToArrayOfLL adds bits from an array of BitSequence (unsigned char)
 * to an array of unsigned long long. At most one byte full of bits is processed
 * per call. The function returns the number of bits that have been processed.
 */

DataLength AddBitsToArrayOfLL (
	uint64	array[],	/* the array to which we add bits */
	int	bitsusedinarray,	/* says how many bits are already stored in array */
	const BitSequence databuffer[],	/* buffer containing the bits */
	DataLength	bitsindatabuffer,	/* total number of bits in the databuffer,
                                     * some may already have been consumed */
	int	firstbitposindatabuffer /* position of next bit to be consumed */
	)
{
#ifdef DEBUG
	printf ("AddBitsToArrayOfLL: bitsusedinarray = %d, "
		"bitsindatabuffer = %lld, "
		"array word where we will store bits [%d] = %#llx, "
		"firstbitposindatabuffer = %d, first data word [%d] = %#x\n", 
		bitsusedinarray, 
		bitsindatabuffer, 
		LLINDEX(bitsusedinarray), array[LLINDEX(bitsusedinarray)], 
		firstbitposindatabuffer, 
		BYTEINDEX(firstbitposindatabuffer), 
		databuffer[BYTEINDEX(firstbitposindatabuffer)]);
#endif
	uint64 splicevalue;
	DataLength bitscopied;
	int	leftshift;
	splicevalue = ((uint64)databuffer[BYTEINDEX(firstbitposindatabuffer)])
				 & LLMASK(bitsusedinarray, firstbitposindatabuffer,
					bitsindatabuffer);

	leftshift = LLLEFTSHIFT (bitsusedinarray, firstbitposindatabuffer);
	if (leftshift >= 0) {
		array[LLINDEX(bitsusedinarray)] |= splicevalue << leftshift;
	}
	else {
		array[LLINDEX(bitsusedinarray)] |= splicevalue >> -leftshift;
	}
	bitscopied = LLBITS2COPY (bitsusedinarray, firstbitposindatabuffer, 
					bitsindatabuffer);
	return bitscopied;
}

static char *HashErrorTable[] = {
	"", // OK
	"Hash failed",
	"Bad Hash Length",
	"Bad Algorithm",
};
void	hash_error (HashReturn retval) {
	if (retval > 0) {
		fprintf (stderr, "Hash Error %s, abort.\n", retval < (sizeof(HashErrorTable)/sizeof(HashErrorTable[0])) ? HashErrorTable[retval] : "Unknown error");
		exit (1);
	}
}
