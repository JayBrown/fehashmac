/*
 * Generic Hash and HMAC Program
 *
 * Copyright (C) 2009 2012 Harald von Fellenberg <hvf@hvf.ch>
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

/* add base64 support - hvf 27.02.2015	*/
/* add xofshakexxx support - hvf 21.04.2015  */

#include	"fehashmac.h"
#include	"fehashmac-macros.h"

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <assert.h>
#include "base64.h"

// print base64 output
void	print_b64 (const unsigned char *out, size_t outlen);

// hash one file, multiple hashes, in parallel
// file access uses mmap if possible

void	hash_one_file (const char *filename, struct use_algo *ua)
{
	struct use_algo	*algoptr;
	int	j;
    unsigned char out[HASHBUFSIZ];    /* hash output array */

	int fd;
	FILE *fp;
	if (filename) {	// filename specified
		fp = fopen (filename, "rb");
	} else {		// no filename, use stdin
		fp = stdin;
		filename = "(stdin)";	// fake filename for better output reading
	}
	if (!fp) { 
		printf ("%s: no such file\n", filename);
		perror (filename); 
		return;
	}
	fd = fileno(fp);	// mmap, fstat need file descriptor

	// initialize contexts: work our way through all algorithms 
	for (algoptr = ua; algoptr; algoptr = algoptr->next) {
		struct	hash_algo	*a = algoptr->a;
		HashReturn retval = (*a->init)(&algoptr->context, a->hash_length<<3, &algoptr->extra);
		if (retval != SUCCESS) {
				fprintf (stderr, "Init context failed for algo %s, reason %d, hash length %d\n",
				a->name, retval, a->hash_length<<3);
				exit (1);
			}
		// initialize HMAC if requested
		if (algoptr->hmacflag) {
			HMAC_INIT (algoptr, keyflag, hmacprintflag);
			HMAC_UPDATE (algoptr, algoptr->context);
			hmacprintflag = 0;	// once is enough
		}
		// initialize KMAC if requested
		if (algoptr->kmacflag) {
			KMAC_INIT (algoptr, keyflag, kmacprintflag);
			// KMAC_INIT (algoptr, keyflag, 1);
			KMAC_UPDATE (algoptr, algoptr->context);
			kmacprintflag = 0;	// once is enough
		}
	}

	// now read file in large chunks and process for each algo
	// first try to mmap the open file
	size_t len, filelen = 0;
	int	map_OK = 0;		// set if mmap was successful
	char	*mapaddr = NULL, *endaddr = NULL;

	// try to mmap the file, otherwise read it
	// fstat it first
	struct stat sb;
	if (fstat (fd, &sb)) {	
		perror ("fstat");
	} else {
		if (!S_ISREG(sb.st_mode)) {
		} else {
			if ((filelen = sb.st_size) > 0) {
				mapaddr = mmap (NULL, filelen, PROT_READ, MAP_PRIVATE, fd, 
								(off_t) 0);
				if (mapaddr == MAP_FAILED) {
					perror ("mmap");
				} else {
					map_OK = 1;		// mapping successful
					endaddr = mapaddr + filelen;
				}
			}
		}
	}
			
	// process the mmap'ed file
	if (map_OK) {
		char *fileptr;
		for (fileptr=mapaddr; fileptr<endaddr; fileptr+=LARGEBUFSIZ) {
			len = (fileptr+LARGEBUFSIZ)>endaddr ? endaddr-fileptr : LARGEBUFSIZ;
			// work our way through all algorithms 
			for (algoptr = ua; algoptr; algoptr = algoptr->next) {
				struct	hash_algo	*a = algoptr->a;
				(*a->update)(algoptr->context, 
					(const BitSequence *)fileptr, len<<3);
			}
		}
		munmap (mapaddr, filelen);
	} else {	// read the file
		while ((len = fread (filebuffer, 1, sizeof (filebuffer), fp))) {
			// work our way through all algorithms 
			for (algoptr = ua; algoptr; algoptr = algoptr->next) {
				struct	hash_algo	*a = algoptr->a;
				(*a->update)(algoptr->context, 
					(const BitSequence *)filebuffer, len<<3);
			}
		}
	}
	close (fd);

	// finish processing
	for (algoptr = ua; algoptr; algoptr = algoptr->next) {
		struct	hash_algo	*a = algoptr->a;
		// make sure out is large enough
		assert (sizeof(out) >= a->hash_length);
		(*a->final)(algoptr->context, out);
		if (algoptr->hmacflag) {
			HMAC_FINAL (algoptr, out);
			printf ("hmac-");
		}
		if (algoptr->kmacflag) {
			// printf ("kmac-");
		}
		// not HMAC, maybe XOF, or base64, or normal
		// all CTX's start with the two identical elements,
		// so the two casts are safe
		GEN_CTX  *gc = (GEN_CTX *) algoptr->context;
		SHA3_CTX *ctx = (SHA3_CTX *) algoptr->context;
		int do_b64 = algoptr->extra.base64flag && a->base64_OK;
		if (((gc->magic == HASH_MAGIC_SHAKE128) || (gc->magic == HASH_MAGIC_SHAKE256)) && ctx->xof_OK) {
			printf ("length (xof) = %lld\n", ctx->xoflength);
			printf ("%s%s%s (%s) = ", (algoptr->kmacflag ? "kmac-" : ""), 
					a->name, (do_b64 ? "-b64" : ""), filename);
			// base64 is possible
			if (do_b64) {
				print_b64 (out, ctx->this_chunk_size);
			} else {
				for (j=0; j<ctx->this_chunk_size; j++) printf ("%2.2x", out[j]&0xff);
			}
			// second and later chunks
			while (ctx->more_size) {	// either positive or -1
				(*a->final)(algoptr->context, out);
				if (do_b64) {
					print_b64 (out, ctx->this_chunk_size);
				} else {
					for (j=0; j<ctx->this_chunk_size; j++) printf ("%2.2x", out[j]&0xff);
				}
			}
			putchar ('\n');
		}
		else {
			printf ("%s%s%s (%s) = ", (algoptr->kmacflag ? "kmac-" : ""),
					a->name, (do_b64 ? "-b64" : ""), filename);
			// base64 is possible
			if (do_b64) {
				print_b64 (out, a->hash_length);
			} else {
				for (j=0; j<a->hash_length; j++) printf ("%2.2x", out[j]&0xff);
			}
			putchar ('\n');
		}
		(*a->free)(algoptr->context); algoptr->context = NULL;
	}
	
	return;
}

// print base64 output
void	print_b64 (const unsigned char *out, size_t outlen)
{
	char *b64out;
	size_t b64outlen = base64_encode_alloc ((const char *) out, 
						outlen, &b64out);
	if (b64out == NULL && b64outlen == 0 && outlen != 0) {
		fprintf (stderr, "base64 input too long.\n");
		exit (1);
	}
	if (b64out == NULL) {
		fprintf (stderr, "base64  memory allocation error.\n");
			exit (1);
	}
	int j;
	for (j=0; j<b64outlen; j++) putchar (b64out[j]);
	free (b64out);
}
