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

#include	"fehashmac.h"
#include    <sys/time.h>
#include    <sys/resource.h>
#include	<assert.h>

/* Length of test block, number of test blocks.
 * increase count by a factor of 10 to get better results
 * hvf 15.03.2016
 */
#define TEST_BLOCK_LEN 1000
#define TEST_BLOCK_COUNT 100000

/* Measures the time to digest TEST_BLOCK_COUNT TEST_BLOCK_LEN-byte
 * blocks for all algorithms
 */

void	TimeTrial()
{
	struct hash_algo	*a;
	int i, j;
	struct rusage	time_usage_start;	/* will contain output of getrusage() */
	struct rusage	time_usage_end;	/* will contain output of getrusage() */
	double	totaltime, speed;
	unsigned char block[TEST_BLOCK_LEN];
	char	out[HASHBUFSIZ];	/* output array - bigger than ever needed */

	fprintf (stderr, "Hash time trial. Digesting %d %d-byte blocks.\n",
		TEST_BLOCK_COUNT, TEST_BLOCK_LEN);
	fprintf (stderr, "Algorithm  time[s]     Bytes/s  Digest\n");
    fflush(stderr);

	/* Initialize block */
	for (i = 0; i < TEST_BLOCK_LEN; i++)
		block[i] = (unsigned char)(i & 0xff);

	for (j=0, a=HashTable; j<HashTableSize; j++, a++) {
        void *context;
// XXXXX hack
		HashReturn retval = (*a->init)(&context, a->hash_length<<3, NULL);
		if (retval) hash_error (retval);

		/* get time used up so far */
		getrusage (RUSAGE_SELF, &time_usage_start);

		/* Digest blocks */
		for (i=0; i<TEST_BLOCK_COUNT; i++)
			(*a->update) (context, block, TEST_BLOCK_LEN<<3);
		(*a->final) (context, NULL);

		/* get time used up so far */
		getrusage (RUSAGE_SELF, &time_usage_end);

		totaltime = time_usage_end.ru_utime.tv_sec 
		+ time_usage_end.ru_stime.tv_sec 
		- time_usage_start.ru_utime.tv_sec - time_usage_start.ru_stime.tv_sec 
		+ ((double)(time_usage_end.ru_utime.tv_usec 
		+ time_usage_end.ru_stime.tv_usec - time_usage_start.ru_utime.tv_usec 
		- time_usage_start.ru_stime.tv_usec))/1000000.0;
		speed = (long)TEST_BLOCK_LEN * (long)TEST_BLOCK_COUNT/totaltime;
		fprintf (stderr, "%-9s  %7.2f  %10.0f  ", a->name, totaltime, speed);

		// make sure out is large enough
		assert (sizeof(out) >= a->hash_length);
		(*a->hashtobyte) (context, (unsigned char *) out);
		for (i=0; i<a->hash_length; i++)
			fprintf (stderr, "%2.2x", out[i]&0xff);
		fprintf (stderr, "\n");
		(*a->free) (context); context = NULL;
        fflush (stderr);
	}
}

