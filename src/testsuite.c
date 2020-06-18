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
#include	"fehashmac-macros.h"
#include	<stdio.h>
#include	<assert.h>

int TestSuite (struct use_algo *ua, struct test_results *t)	/* returns 0 for success */
{
	TestVector	*testvector;

	unsigned char out [HASHBUFSIZ];	/* long enough to keep the hash */
	int	i, j;
	int	passed = 0, failed = 0, totalfailed = 0;;

	struct hash_algo *a = ua->a;

	if (!a) return 1;
	if (!a->testvector) return 0;

	t->name = a->name;
	t->test_type = "Hash tests";
	t->tests_ok = 0;
	t->tests_failed = 0;
	
	testvector = a->testvector;
	printf ("%s Test Suite:\n", a->name);

    for (i=0; testvector->string && testvector->repeat > 0; i++, testvector++) {
        void *context = NULL;
		HashReturn retval = (*a->init)(&context, a->hash_length<<3, &ua->extra);
		if (retval) hash_error (retval);
		if (!context) {
			fprintf (stderr, "Testsuite: got no context for %s Test %d\n",
				a->name, i);
			exit (1);
		}
		int	 length = strlen (testvector->string);
		/* testvector in hex notation */
		if (testvector->keytype == IS_HEXSTRING) {
			/* convert testvector into a byte array, may have blanks etc */
			/* allocate temp buffer to hold string without illegal chars */
			char *temp = (char *) malloc (length);
			int k, ktemp;
			for (k=0, ktemp=0; k<length; k++) {
				/* skip non-hex characters */
				int c = testvector->string[k];
				if (!isxdigit(c)) continue;	/* skip non-hex, like blanks */
				temp[ktemp++] = c;
			}
			/* temp is now pure hex, check that length is even */
			if (length%2) {
				fprintf (stderr, "%s (\"%s\") is hex string, but length %d is not even.\n",
					a->name, testvector->string, ktemp);
				exit (1);
			}
			/* allocate hexbuf buffer to hold BYTE values */
			BYTE *hexbuf = (BYTE *) malloc (ktemp/2);
			int khex = 0;
			/* now convert temp into BYTE array hexbuf */
			for (k=0; k<ktemp; k +=2) {
				unsigned int c;
				sscanf (temp+k, "%2x", &c);
				hexbuf[khex++] = c;
			}
			free (temp);
		
			/* digest the testvector 1 or repeat times	*/
			for (j=0; j<testvector->repeat; j++)
				(*a->update)(context, hexbuf, khex<<3);
			free (hexbuf);
			printf ("%s (\"hexstring=%s, bits=%d\")", a->name, 
				testvector->string, khex<<3);
		}
		else {	/* normal string */
			for (j=0; j<testvector->repeat; j++)
				(*a->update)(context, (BYTE *) testvector->string, length<<3);
			printf ("%s (\"%s\") ", a->name, testvector->string);
        }
        // final processing for both hex and ASCII
		(*a->final)(context, NULL);
		// make sure out is large enough
		assert (sizeof(out) >= a->hash_length);
       	(*a->hashtobyte) (context, out);
		//printf ("%s (\"%s\") ", a->name, testvector->string);
		
		if (testvector->repeat>1)
			printf ("(repeated %d times)", testvector->repeat);
		printf (" = ");
		for (j=0; j<a->hash_length; j++)
			printf ("%2.2x", out[j]);
		if (verify_hash (out, testvector->digest, a->hash_length)) {
			passed++; printf ("  OK\n");
		} else {
			failed++; printf ("  failed.\n");
			printf ("The description %s expects the result: %s\n",
				a->reference, testvector->digest);
		}
        (*a->free) (context);
    }
	totalfailed = failed;
	printf ("Tests passed: %d, tests failed: %d.\n", passed, failed);
	t->tests_ok += passed;
	t->tests_failed += failed;

	return (totalfailed);
}
	
int TestSuiteBitwise (struct use_algo *ua, struct test_results *t)	
	/* returns 0 for success */
	/* bitwise test vectors if available */
{
	unsigned char out [HASHBUFSIZ];	/* long enough to keep the hash */
	int	i;
	int	passed = 0, failed = 0, totalfailed = 0;

	struct hash_algo *a = ua->a;

	if (!a) return 1;
	if (!a->testvector_b) return (0);

	t->name = a->name;
	t->test_type = "Bitwise hash tests";
	t->tests_ok = 0;
	t->tests_failed = 0;
	
	TestVectorBitwise	*tvb = a->testvector_b;
	printf ("\n%s Bitwise Test Suite:\n", a->name);
	passed = failed = 0;

    for (i=0; tvb->type; i++, tvb++) {
        void *context = NULL;
		HashReturn retval = (*a->init)(&context, a->hash_length<<3, &ua->extra);
		if (retval) hash_error (retval);
		if (!context) {
			fprintf (stderr, "Bitwise Testsuite: got no context for %s Test %d\n",
				a->name, i);
			exit (1);
		}
		/* Gillogly input is only tested for SHA1
	 	 * however, it should work on SHA224, SHA256, SHA384, SHA512
		 * but has not been tested (no test vectors available)
		 */
		if (tvb->type == IS_BITSTRING) {
			do_BitStringGillogly (a, context, tvb->bitstring);

			// make sure out is large enough
			assert (sizeof(out) >= a->hash_length);
			(*a->hashtobyte) (context, (unsigned char *) out);
			printf ("%s (\"bitstring=%s\") = ", a->name, tvb->bitstring);
			for (i=0; i<a->hash_length; i++)
	   				printf ("%2.2x", out[i]&0xff);
			if (verify_hash (out, tvb->digest, a->hash_length)) {
				passed++; printf ("  OK\n");
			} else {
				failed++; printf ("  failed.\n");
				printf ("The description %s expects the result: %s\n",
					tvb->bitreference, tvb->digest);
			}
			(*a->free) (context);
		}
		if (tvb->type == IS_HEXSTRING) {
			do_HexString (a, context, tvb->hexstring, (uint64) tvb->bitsize, 1);

			// make sure out is large enough
			assert (sizeof(out) >= a->hash_length);
			(*a->hashtobyte) (context, (unsigned char *) out);
			printf ("%s (\"hexstring=%s, bits=%d\") = ", a->name, 
					tvb->hexstring, tvb->bitsize);
			for (i=0; i<a->hash_length; i++)
	   				printf ("%2.2x", out[i]&0xff);
			if (verify_hash (out, tvb->digest, a->hash_length)) {
				passed++; printf ("  OK\n");
			} else {
				failed++; printf ("  failed.\n");
				printf ("The description %s expects the result: %s\n",
					tvb->bitreference, tvb->digest);
			}
			(*a->free) (context);
		}
    }
	totalfailed += failed;
	printf ("Tests passed: %d, tests failed: %d.\n", passed, failed);
	t->tests_ok += passed;
	t->tests_failed += failed;
	return (totalfailed);
}

// int TestSuiteHMAC (struct hash_algo *a, struct test_results *t)	
int TestSuiteHMAC (struct use_algo *ua, struct test_results *t)	
		/* returns 0 for success */
{
	HMACTestVector	*testvector;

	unsigned char out [HASHBUFSIZ];	/* long enough to keep the hash */
	int	i, j;
	int	passed = 0, failed = 0, totalfailed = 0;;
	struct	use_algo	use;

	struct hash_algo *a = ua->a;
	
	if (!a) return 1;
	if (!a->hmactestvector) return (0);

	t->name = a->name;
	t->test_type = "HMAC tests";
	t->tests_ok = 0;
	t->tests_failed = 0;

	testvector = a->hmactestvector;
	printf ("\n%s HMAC Test Suite:\n", a->name);

    for (i=0; testvector->keytype && testvector->stringtype; i++, testvector++) {
        void *context;
		HashReturn retval = (*a->init)(&context, a->hash_length<<3, &ua->extra);
		if (retval) hash_error (retval);
		if (!context) {
			fprintf (stderr, "TestsuiteHMAC: got no context for %s Test %d\n",
				a->name, i);
			exit (1);
		}
		keystring = testvector->key;
		hexkeystring = testvector->hexkey;
		memset (&use, 0, sizeof (use));
		use.a = a;
		use.hmacflag = 1;
		HMAC_INIT ((&use), testvector->keytype == IS_ASCIISTRING, 1);
		HMAC_UPDATE ((&use), context);
		if (testvector->stringtype == IS_ASCIISTRING) {
			(*a->update)(context, (BYTE *) testvector->string, 
						strlen (testvector->string)<<3);
			(*a->final)(context, NULL);
		}
		else {
			// do_HexString (a, context, testvector->hexstring, 0LL);
			do_HexString (a, context, testvector->hexstring, strlen(testvector->hexstring)*4, 1);
		}
		// make sure out is large enough
		assert (sizeof(out) >= a->hash_length);
        (*a->hashtobyte) (context, out);
        (*a->free) (context);
		HMAC_FINAL ((&use), out);
		printf ("hmac-%s (\"%s\") ", a->name, 
			testvector->stringtype == IS_ASCIISTRING ? testvector->string : 
			testvector->hexstring);
		printf (" = ");
		for (j=0; j<a->hash_length; j++)
			printf ("%2.2x", out[j]);
		if (verify_hash (out, testvector->digest, a->hash_length)) {
			passed++; printf ("  OK\n\n");
		} else {
			failed++; printf ("  failed.\n");
			printf ("The description %s expects the result: %s\n\n",
				testvector->hmacreference, testvector->digest);
		}
    }
	totalfailed = failed;
	printf ("Tests passed: %d, tests failed: %d.\n", passed, failed);
	t->tests_ok += passed;
	t->tests_failed += failed;

	return (totalfailed);
}
