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

/* 26.02.2015 hvf	allow base64 encoded hashes, e.g. shake128-b64 (file) = ...
 * 01.05.2015 hvf	allow variable length for XOFSHAKEnnn functions
 * 13.05.2015 hvf	KMAC implemented
 *					show algorithm on each result (OK, differ)
 */

#include	"fehashmac.h"
#include	<stdio.h>
#include	"fehashmac-macros.h"
#include	<assert.h>
#include	"base64.h"

char *strsave (char *in); /* save a string and return its pointer */

/* NOTE: HASHBUFSIZ is at least 4k and replaces BUFSIZ, 
 * which is only 1k on certain OS's like FreeBSD, Solaris
 */

// read a file with digests and verify them

void ReadDigest (char *listfilename)
{
	FILE 	*listfile;
	char	buf[HASHBUFSIZ];
	char	printbuf[HASHBUFSIZ];
	char	tempbuf[HASHBUFSIZ];
	char	*algoptr;
	char	*filename;
	FILE	*in;
	char	*filedigest;
	char	*ptr;
	BYTE	out[HASHBUFSIZ];
	int		i, j;
	int		length;
	struct	hash_algo	*a;
	void	*context;
	int		foundalgo, foundleftp, foundrightp, foundfilename, founddigest;
	char	*hmacprefix = NULL;
	char	*kmacprefix = NULL;
	int		do_hmac = 0;	// HMAC for current file requested
	int		do_kmac = 0;	// KMAC for current file requested
	struct	use_algo use;
	int		ok = 0, failed = 0, total = 0, found = 0, notfound = 0, hmacfound = 0;
	int		kmacfound = 0;
	int		lines = 0, algofound = 0, algonotfound = 0;
	long long xoflength = 0;	// length (xof) = nnn for xofshakexxx
	int		xofflag = 0;
	int		xoffound = 0;
	int		keylengthfound = 0;
	char	*displayname = NULL;
	
	hmacflag = kmacflag = keyflag = hexkeyflag = 0;

	if (!listfilename) listfile = stdin;
	else {
		listfile = fopen (listfilename, "rb");
		if (!listfile) {
			perror (listfilename);
			exit (1);
		}
	}

	/* each line has the format:
	 * algorithm (filename) = digest
	 * algorithm may be: simple, hmac-simple, simple-b64
	 * we look for algoptr, filename, filedigest
	 * i.e. a line looks like
	 * algoptr (filename) = filedigest
	 */

	while (fgets (buf, sizeof(buf), listfile)) {
		lines++;
		memset (&use, 0, sizeof (use));
		memset (printbuf, 0, sizeof (printbuf));
		memset (tempbuf, 0, sizeof (printbuf));
		// delete trailing newline
		if (buf[strlen(buf)-1] == '\n') buf[strlen(buf)-1] = '\0';
		foundalgo=foundleftp=foundrightp=foundfilename=founddigest=0;
		if ((length = strlen (buf)) == (sizeof(buf) -1)) {
			fprintf (stderr, "input too long, exiting.\n");
			exit (1);
		}
		filename = NULL;
		filedigest = NULL;
		algoptr = buf;		// no leading white space allowed
		for (ptr=buf, i=0; i<length; i++, ptr++) {
			if (isspace (*ptr)) {	// find terminating white space or '('
				*ptr++ = '\0';
				break;
			} else if (*ptr == '('){	// no blank after algo
				*ptr++ = '\0';
				filename = ptr++;
				foundleftp=1;
				break;
			}
		}
		foundalgo = strlen (algoptr);
		if (!foundalgo) continue;		// try next line
		if (!foundleftp) {				// look for opening parenthesis
			for (i=ptr-buf; i<length; i++, ptr++) {
				if (*ptr == '('){
					filename = ++ptr;	// filename starts right after opening par
					foundleftp=1;
					break;
				}
			}
		}
		if (!foundleftp) continue;		// try next line
		for (i=ptr-buf; i<length; i++, ptr++) {
			if (*ptr == ')'){		// right parenthesis ends filename
				*ptr++ = '\0';
				foundrightp=1;
				break;
			}
		}
		if (!foundrightp) continue;
		for (i=ptr-buf; i<length; i++, ptr++) {
			if (!isspace (*ptr) && *ptr != '='){	// skip ' = '
				filedigest = ptr;	// filedigest starts here
				break;
			}
		}
		// find end of filedigest
		for (i=ptr-buf; i<length; i++, ptr++) {
			if (isspace(*ptr)) {	// space, newline end the digest
				*ptr = '\0';
				break;
			}
		}

		if (!algoptr || !filename || !filedigest) {
			fprintf (stderr, "Incomplete, input line, skipping.\n");
			continue;
		}

		/* lowercase algorithm, just in case */
		for (ptr=algoptr; *ptr; ptr++)
			*ptr = tolower (*ptr);

		// correct line found, count it
		total++;

		// special record for xofshakexxx: length (xof) = nnn

		if (!strcmp (algoptr, "length")) {
			// length key found
			if (!strcmp (filename, "xof")) {
				// length (xof) = found
				xofflag++;
				xoffound++;
				xoflength = atoll (filedigest);
			} else if (!strcmp (filename, "kmac")) { // length (kmac) = nnn
				keylength = atoi (filedigest);
				keylengthfound++;
			} else {
				fprintf (stderr, "value \"%s\" for length not known.\n", filename);
				algonotfound++;
			}
			continue;
		}

		// special record for HMAC, KMAC: key (hmac) = ... -and- hexkey (hmac) = ...

		if (!strcmp (algoptr, "key") || !strcmp (algoptr, "hexkey")) {
			if (!strcmp (filename, "hmac")) {
				// hmac key found, count it
				hmacfound++;
				hmacprefix = strdup (filename);
				hmacflag = 1;
				hmacprintflag = 0;
			}
			if (!strcmp (filename, "kmac")) {
				// kmac key found, count it
				kmacfound++;
				kmacprefix = strdup (filename);
				kmacflag = 1;
				kmacprintflag = 0;
			}
			keystring = hexkeystring = strdup (filedigest);
			keyflag = !strcmp (algoptr, "key");
			if (keyflag) keylength = 0;	// ASCII keys for KMAC do not support keylength
			hexkeyflag = !strcmp (algoptr, "hexkey");
			continue;
		}

		/* algoptr might be the alorithm incl pre- and postfix, save it	*/
		displayname = strsave (algoptr);

		// remove hmacprefix- (hmac-) from algoptr if present
		if (hmacflag) {
			if (!strncmp (algoptr, hmacprefix, strlen (hmacprefix))) {
				algoptr += strlen (hmacprefix);
				if (*algoptr == '-') 
					algoptr++;
				do_hmac = 1;
				use.hmacflag = 1;
			}
			else {
				do_hmac = 0;
				use.hmacflag = 0;
			}
		}
		// remove kmacprefix- (kmac-) from algoptr if present
		if (kmacflag) {
			if (!strncmp (algoptr, kmacprefix, strlen (kmacprefix))) {
				algoptr += strlen (kmacprefix);
				if (*algoptr == '-') 
					algoptr++;
				do_kmac = 1;
				use.kmacflag = 1;
			}
			else {
				do_kmac = 0;
				use.kmacflag = 0;
			}
		}

		// remove base64 suffix (-b64)
		int	myb64 = 0;
        char *p; 
        if ((p = strstr (algoptr, "-b64"))) { // trailing -b64
            myb64 = 1; 
            *p = '\0'; /* delete trailing -b64 */ 
        } 

		// now look for the right algorithm
		
		for (a=NULL, j=0; j<HashTableSize; j++) {
			if (!strcmp (algoptr, HashTable[j].name)){
				a = HashTable + j;
				algofound++;
				break;
			}
		}
		if (!a) {
			fprintf (stderr, "Algorithm \"%s\" not found, skipping.\n", algoptr);
			algonotfound++;
			continue;
		}
		use.a = a;
		use.extra.xofflag = xofflag;
		// we limit the xoflength here, but only if xof_OK_defaultLength is set
		if (a->xof_OK_defaultLength) {
			if (xoflength <= 0 || xoflength > a->xof_OK_defaultLength) xoflength = a->xof_OK_defaultLength;
			use.extra.xoflength = xoflength;
		}
		// we decode the base64 filedigest, so no extra encoding
		// use.extra.base64flag = myb64;
		use.extra.base64flag = 0;
		(*a->init)(&context, a->hash_length<<3, &use.extra);

		if (!(in = fopen (filename, "rb"))) {
			notfound++;
			perror (filename);
			continue;
		}
		found++;
		if (do_hmac) {
			HMAC_INIT ((&use), keyflag, hmacprintflag);
			HMAC_UPDATE ((&use), context);
			hmacprintflag = 0;	// once is enough
		}
		if (do_kmac) {
			KMAC_INIT ((&use), keyflag, kmacprintflag);
			KMAC_UPDATE ((&use), context);
			kmacprintflag = 0;	// once is enough
		}
		// digest file
		(*a->file)(context, in);
		// make sure out is large enough
		assert (sizeof(out) >= a->hash_length);
		(*a->hashtobyte)(context, out);
		if (do_hmac) {
			HMAC_FINAL ((&use), out);
		}

		// decompress base64 hash if required
		if (myb64) {
			// check if supported
			if (!a->base64_OK) {
				fprintf (stderr, "%s-b64 notsupported, check skipped.\n", a->name);
				continue;
			}

			// decompress base64 filedigest
			/* bool ok = base64_decode_alloc (in, inlen, &out, &outlen);
			 * if (!ok)
			 *   FAIL: input was not valid base64
			 * if (out == NULL)
			 *   FAIL: memory allocation error
			 * OK: data in OUT/OUTLEN
			 */
			char *unb64out;
			size_t unb64outlen = 0;
			bool ok = base64_decode_alloc (filedigest, strlen (filedigest), &unb64out, &unb64outlen);
			if (!ok) {
				fprintf (stderr, "readdigest: input is not a valid base64 string: %s\n",
						filedigest);
				exit (1);
			}
			if (unb64out == NULL) {
                fprintf (stderr, "base64  memory allocation error.\n");
                exit (1);
            }
			// ok, data is in unb64out
			for (i=0, j=0; i<unb64outlen && j<HASHBUFSIZ-3; i++) {
				j += snprintf (tempbuf+j, 3, "%2.2x", unb64out[i]&0xff);
			}
			// filedigest is now in tempbuf
			filedigest = tempbuf;
			if (unb64out) free (unb64out); unb64out = NULL;
		} 
			// normal hashes pass here
			if (!a->xof_OK_defaultLength) {
				for (i=0, j=0; i<a->hash_length && j<HASHBUFSIZ-3; i++) {
					j += snprintf (printbuf+j, 3, "%2.2x", out[i]&0xff);
				}
			} else {
				for (i=0, j=0; i<a->hash_length && j<a->xof_OK_defaultLength*2 && j<HASHBUFSIZ-3; i++) {
					j += snprintf (printbuf+j, 3, "%2.2x", out[i]&0xff);
				}
			}
#ifdef DEBUG
		printf ("%s calc: %s\n", displayname, printbuf);
		printf ("%s read: %s\n\n", displayname, filedigest);
		printf ("%s calc hash length: %ld\n", displayname, strlen (printbuf));
		printf ("%s read hash length: %ld\n", displayname, strlen (filedigest));
#endif
		size_t lenfile = strlen (filedigest);
		size_t lenprint = strlen (printbuf);
		if (strcmp (filedigest, printbuf) == 0) {
			//printf ("%s: OK\n", filename);
			printf ("%s: OK %s\n", filename, displayname);

			ok++;
		}
		
		/* interesting: the shortened string comparison applies to the 
		 * first parameter only, so we need to do two separate comparisons
		 * to cover both cases: digest shorter than calculated value, and
		 * calculated value shorter than digest
		 */
		else if (strncmp (filedigest, printbuf, lenfile) == 0) {	// digest is shorter
			printf ("%s: OK %s, match truncated to %ld bytes\n", filename, displayname, lenfile/2);
			ok++;
		}
		else if (strncmp (printbuf, filedigest, lenprint) == 0) {	// calculated is shorter
			printf ("%s: OK %s, match truncated to %ld bytes\n", filename, displayname, lenprint/2);
			ok++;
		}
		else { 
			printf ("%s: differ %s\n", filename, displayname);
			failed++;
		}
		(*a->free)(context); context = NULL;
		free (displayname); displayname = NULL;
	}
	fclose (listfile);
	if (hmacprefix) { free (hmacprefix); hmacprefix = NULL; }
	if (kmacprefix) { free (kmacprefix); kmacprefix = NULL; }
	if (keystring)  { free (keystring); keystring = hexkeystring = NULL; }
	/*
	 * we print only values different from zero to shorten output
	 * 17.05.2015
	 */
	printf ("\nSummary:\n");
	printf ("--------\n");
	if (lines>0) 			printf ("Lines read:         %5d\n", lines);
	if (total>0) 			printf ("Hash entries read:  %5d\n", total);
	if (hmacfound>0) 		printf ("HMAC keys found:    %5d\n", hmacfound);
	if (kmacfound>0) 		printf ("KMAC keys found:    %5d\n", kmacfound);
	if (keylengthfound>0) 	printf ("KMAC key lengths:   %5d\n", keylengthfound);
	if (xoffound>0) 		printf ("XOF lengths found:  %5d\n", xoffound);
	if (found>0) 			printf ("Files found:        %5d\n", found);
	if (notfound>0) 		printf ("Files not found:    %5d\n", notfound);
	// printf ("Algorithms found: %5d\n", algofound);
	if (algonotfound>0) 	printf ("Unknown Algorithms: %5d\n", algonotfound);
	if (ok>0) 				printf ("Files OK:           %5d\n", ok);
	if (failed>0) 			printf ("Files failed:       %5d\n", failed);
}

char *strsave (char *in) /* save a string and return its pointer */
						/* the pointer may be freed after use */
{
	char *buf = NULL;
	if (!in) return NULL;
	size_t len = strlen (in);
	buf = malloc (len+1);
	if (!buf) {
		perror ("strsave");
		exit (1);
	}
	memset (buf, 0, len+1);
	strncpy (buf, in, len+1);
	return buf;
}

