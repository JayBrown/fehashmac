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

/* generic hash driver routine
 *
 * hvf 23.1.2000
 * hvf 13.2.01
 * hvf 10.8.01
 * hvf 31.01.2007 add Whirlpool
 * hvf 02.02.2007 add GOST
 * hvf 11.02.2007 debug GOST
 * hvf 12.02.2007 add RMD256
 * hvf 12.02.2007 add RMD320
 * hvf 16.02.2007 add bitwise processing for SHAVS (SHA only)
 * hvf 25.02.2007 add large file support for Linux on i386 
 * hvf 06.03.2007 correct bitwise padding for SHAVS (SHA only)
 * hvf 19.10.2008 add LASH160
 * hvf 20.10.2008 add LASH256, 384, 512
 * hvf 14.11.2008 add Tiger2
 * hvf 18.12.2008 correctly implement bitwise processing for SHA1,
 *                use Gillogly SHA-1 bitwise test vectors
 * hvf 20.12.2008 implement bitwise processing for SHA224 SHA256 SHA384 SHA512
 * hvf 29.12.2008 add bitwise test vectors for sha1, sha224
 * hvf 30.12.2008 add bitwise test vectors for sha256, sha384, sha512
 *                digest may now contain white space
 *                add --list option
 * hvf 02.01.2009 corrected shaxxx_final for bitwise operation
 *                hexstrings are now processed correctly
 *                SHA1-Vectors test suites 1 and 2 run now correctly.
 * hvf 07.01.2009 add HMAC functionality (RFC 2104)               
 * hvf 26.01.2009 update SHA, whirlpool reference
 * hvf 15.02.2009 align all algorithms with SHA3-C-API
 * hvf 17.08.2009 create version 1.0.4, correct a SHA384 glitch
 * hvf 29.03.2011 create version 1.1.0, include SHA512/224 and SHA512/256
 * hvf 05.04.2011 add BLAKE; testvectors can be hex input
 * hvf 09.04.2011 add GROESTL
 * hvf 10.04.2011 add JH
 * hvf 11.04.2011 add KECCAK
 * hvf 11.04.2011 add SKEIN
 * hvf 14.04.2011 add more HMAC testvectors, sort list of algorithms
 * hvf 01.09.2011 correct an error in SKEIN_Final
 * hvf 26.01.2012 put HashTable into a separate header file
 *                allow for several algorithms in parallel, 
 *                files are read only once.
 * hvf 28.01.2012 version 1.2.0
 * hvf 01.02.2012 chop up fehashmac.c into smaller pieces
 * hvf 30.12.2014 add SHA3-{224,256,384,512}, SHAKE{128,256} from FIPS 202 draft
 * hvf 30.12.2014 version 1.3.0
 * hvf 18.01.2015 version 1.3.1 use more efficient SHA3 implementation
 * hvf 27.02.2015 version 1.4.0 support base64 output for SHAKE{128,256}
 * hvf 13.05 2015 version 1.4.2 KMAC implementation
 * hvf 29.02.2016 version 1.5.0 remove xofshake{128,256}, use shake128, shake256
 * hvf 08.03.2016 version 1.5.1 add MD6
 * hvf 01.08.2016 version 2.0   cleanup
 * hvf 07.09.2016 version 2.1   replace keccak, sha3 with new code base from
 *                              https://github.com/gvanas/KeccakCodePackage,
 *                              add patch for partial byte treatment in sha3
 */

#include	"fehashmac.h"
#include	<stdio.h>
#include	<stdlib.h>
#include 	<string.h>
#include 	<ctype.h>
#include 	<sys/time.h>
#include 	<sys/resource.h>
#include 	<unistd.h>

/* all algorithms are now in a header file */
#include	"fehashmac-algos.h"

/* Main driver. */

char *Version = "\
Generic Hash and HMAC Program fehashmac V2.1 07.09.2016"
"\nHarald von Fellenberg (hvf at hvf dot ch)""\n\
Supports HMAC (RFC 2104, FIPS PUB 198-1) for all hash algorithms.""\n\
Supports SHA3 and SHAKE (FIPS PUB 202, August 2015).""\n\
Supports base64 encoded output for SHAKE.""\n\
Supports arbitrary extendable output lengths for SHAKE128, SHAKE256.""\n\
Supports KMAC (http://keyak.noekeon.org/Keyak-1.2.pdf) for SHA3 algorithms.""\n\
The previous algos XOFSHAKE are now integrated in SHAKE and are obsolete.""\n\
Multiple hashes can be calculated simultaneously, files are read only once.";

char *description = "\
Options and arguments:\n\
  -a algo[,algo,...]    - choose algorithm(s), see list below\n\
  --algorithm=algo[,algo,...]  - choose algorithm(s), see list below\n\
                          these two arguments can be specified multiple times\n\
                          the files to be hashed are only read once.\n\
  -a hmac-algo[,...]    - choose HMAC algorithm with hash algo.\n\
                          Hash and HMAC algos may be freely mixed.\n\
  -a kmac-algo[,...]    - choose KMAC algorithm with hash algo.\n\
  -a algo-b64[,...]     - choose base64 encoding for hash algo.\n\
  -a all                - choose all hash algorithms\n\
  -a hmac-all           - choose all HMAC algorithms\n\
  -a kmac-all           - choose all KMAC algorithms\n\
  -a all-b64            - choose all algorithms that support base64 encoding\n\
  -a kmac-all-b64       - choose all algorithms that support KMAC and base64 encoding\n\
  -s string             - digests string for one algorithm\n\
  --string=string       - digests string for one algorithm\n\
  --bitstring=bitstring - digests bitstring (Jim Gillogly format, bbb#nnn|bb..)\n\
  --hexstring=hexstring - digests hexstring (like -M, --M=)\n\
  -t                    - runs time trial for all algorithms\n\
  --time                - runs time trial for all algorithms\n\
  -x                    - runs test script for one algorithm\n\
  --test                - runs test script for one algorithm\n\
  file ...              - digests file(s) for one algorithm\n\
  (none)                - digests standard input for one algorithm\n\
  -c [file]             - checks digests read from file or stdin\n\
  --check[=file]        - checks digests read from file or stdin\n\
  --bits=nn             - message length in number of bits (for SHA only)\n\
  -M hexstring          - message in hexadecimal\n\
  --M=hexstring         - message in hexadecimal\n\
  -h                    - print this text\n\
  --help                - print this text\n\
  --list                - print list of algorithms, one per line\n\
\n\
  HMAC options:\n\
  -K keystring          - HMAC key as ASCII string\n\
  --K=keystring         - HMAC key as ASCII string\n\
  --key=keystring       - HMAC key as ASCII string\n\
  --hexkey=hexkeystring - HMAC key in hexadecimal\n\
\n\
  KMAC options:\n\
  -K keystring          - KMAC key as ASCII string\n\
  --K=keystring         - KMAC key as ASCII string\n\
  --key=keystring       - KMAC key as ASCII string\n\
  --hexkey=hexkeystring - KMAC key in hexadecimal\n\
  --keylength=nnn       - length of KMAC key in bits (only for hexkey!)\n\
\n\
  Base64 options:\n\
  --b64                 - produce digest in base64 format (if supported)\n\
  --base64              - produce digest in base64 format (if supported)\n\
\n\
 XOF options:\n\
  --xoflength=longint   - length for extendable length output in bytes\n\
  --xoflength=0         - default length, 512 bytes\n\
  --xoflength=-1        - indefinite length\n\
                          length goes up to 9223372036854775807 (2**63-1) bytes\n\
\n\
";

int		help_OK = 0;	// set if $$ -h or $0 --help 

void Usage(char *name)
{
	int j, len = 0, hmacs = 0, kmacs = 0, b64s = 0, kmac_b64 = 0, xofs = 0;
	FILE *outfile = (help_OK ? stdout : stderr);
	fprintf (outfile, "Usage: %s [ options ] [ file ..]\n", name);
	fprintf (outfile, " -or-  %s -c [file]\n", name);
	fprintf (outfile, " -or-  %s -t\n", name);
	fprintf (outfile, "%s\n\n", Version);
	len = fprintf (outfile, "The supported hash algorithms are (%d): ", 
		HashTableSize);
	for (j=0; j<HashTableSize; j++) {
		len += fprintf (outfile, "%s ", HashTable[j].name);
		if (len > 60) {
			fprintf (outfile, "\n"); len = 0;
		}
		if (hmac_OK(HashTable[j].mac_OK)) hmacs++;
		if (kmac_OK(HashTable[j].mac_OK)) kmacs++;
		if (HashTable[j].base64_OK) b64s++;
		if (kmac_OK(HashTable[j].mac_OK) && HashTable[j].base64_OK) kmac_b64++;
		if (HashTable[j].xof_OK_defaultLength) xofs++;
	}
	fprintf (outfile, "\n\n");
	len = fprintf (outfile, "The supported HMAC algorithms are (%d): ", 
		hmacs);
	for (j=0; j<HashTableSize; j++) {
		if (!hmac_OK(HashTable[j].mac_OK)) continue;
		len += fprintf (outfile, "hmac-%s ", HashTable[j].name);
		if (len > 60) {
			fprintf (outfile, "\n"); len = 0;
		}
	}
	fprintf (outfile, "\n\n");
	len = fprintf (outfile, "The supported KMAC algorithms are (%d): ", 
		kmacs);
	for (j=0; j<HashTableSize; j++) {
		if (!kmac_OK(HashTable[j].mac_OK)) continue;
		len += fprintf (outfile, "kmac-%s ", HashTable[j].name);
		if (len > 60) {
			fprintf (outfile, "\n"); len = 0;
		}
	}
	fprintf (outfile, "\n\n");
	len = fprintf (outfile, "The supported algorithms with base64 encoding are (%d): ", 
		kmac_b64);
	for (j=0; j<HashTableSize; j++) {
		if (!(HashTable[j].base64_OK)) continue;
		len += fprintf (outfile, "%s-b64 ", HashTable[j].name);
		if (len > 60) {
			fprintf (outfile, "\n"); len = 0;
		}
	}
	fprintf (outfile, "\n\n");
	len = fprintf (outfile, "The supported KMAC algorithms with base64 encoding are (%d): ", 
		kmac_b64);
	for (j=0; j<HashTableSize; j++) {
		if (!(kmac_OK(HashTable[j].mac_OK) && HashTable[j].base64_OK)) continue;
		len += fprintf (outfile, "kmac-%s-b64 ", HashTable[j].name);
		if (len > 60) {
			fprintf (outfile, "\n"); len = 0;
		}
	}
	fprintf (outfile, "\n\n");
	len = fprintf (outfile, "The supported algorithms with extendable output length (XOF) are (%d): ", 
		xofs);
	for (j=0; j<HashTableSize; j++) {
		if (!HashTable[j].xof_OK_defaultLength) continue;
		len += fprintf (outfile, "%s ", HashTable[j].name);
		if (len > 60) {
			fprintf (outfile, "\n"); len = 0;
		}
	}
	fprintf (outfile, "\n\n");
	fprintf (outfile, "%s\n", description);
	fprintf (outfile, "Algorithm   Hash Size  Block Size  Bitwise    HMAC test  Base64\n");
	fprintf (outfile, "            (bits)     (bytes)     Operation  Vectors\n");
	for (j=0; j<HashTableSize; j++) {
		fprintf (outfile, "%-11s %4d %10d        %s        %s  %s\n", 
			HashTable[j].name,
			HashTable[j].hash_length<<3, HashTable[j].inputbuffer_length,
			HashTable[j].bitwise_support == 0 ? "no " :
			HashTable[j].bitwise_support == 1 ? "yes" :
                   "yes, no testvectors", 
			hmac_OK(HashTable[j].mac_OK)? (HashTable[j].hmactestvector ?  "yes" : "") :
					"no support",
			HashTable[j].base64_OK? "yes" : "");
	}
	fprintf (outfile, "\nReferences:\n");
	for (j=0; j<HashTableSize; j++)
		fprintf (outfile, "%-10.10s: %s\n", HashTable[j].name,
			HashTable[j].reference);
	exit (1);
}

int qsort_compare_hashtable (const void *, const void *);

char	filebuffer[LARGEBUFSIZ];	// file read buffer, big 

// global variables for HMAC and KMAC operation, we can then use macros to
// simplify quality assurance

int		hmacflag = 0;		// HMAC request: key and algo required
int		kmacflag = 0;		// KMAC request: key and algo required
int		keyflag = 0;		// xMAC key supplied as ascii string:
							// -K, --K=, --key=
int		hexkeyflag = 0;		// xMAC key supplied as hex string:
							// --hexkey=
char	*keystring = NULL;		// ASCII key string (for xMAC)
char	*hexkeystring = NULL;	// key string in hex (for xMAC)
int		keylength = 0;		// length of hexkeystring in bits for KMAC
int		hmacprintflag = 0;	// once is enough
int		kmacprintflag = 0;	// once is enough

int		base64flag = 0;		// base64 request: algo required

// XOF (extendable output functions) parameters
int		xofflag = 0;		// extendable output length request
long long	xoflength = 0;	// extendable output length 

int		binoutflag = 0;		// generate binary (unformatted) output, xof only

// some macros for HMAC and for building up the algo list

#include	"fehashmac-macros.h"

int main (int argc, char *argv[])
{
	int i;
	char	*algo = NULL;		// algorithm parameter, unparsed
	struct	use_algo	Use_algo;	// linked list of algorithms
	struct	use_algo	*this_algo = NULL;	// ptr to current algorithm
	struct	use_algo 	*algoptr;	// used as loop variable
	int		nalgo = 0;			// number of algorithms that we calculate
	char	*progname;
	int		sflag = 0;			// string input: -s, --string=
	char	*sptr = NULL;
	int		tflag = 0;			// timing request: -t, --time
	int		xflag = 0;			// test suite request: -x, --test
	int		cflag = 0;			// check request: -c, --check=
	char	*cptr = NULL;
	int		bitstringflag = 0;
	int		flags = 0;
	unsigned long long bitcount = 0;
	int		bitflag = 0;
	char	*hexmessageptr = NULL;	// message string in hex
	int		hexmessageflag = 0;
	char 	*bitstringgillogly = NULL;	// message string in Gollogly notation
	int		retval = 0;		/* return value from TestSuite, used as exit code */

	/* sort HashTable before we start work */
	qsort (HashTable, HashTableSize, 
		sizeof(HashTable[0]), qsort_compare_hashtable);

	/* print command line unless output is a tty	*/
	if (!isatty(1)) {
		printf ("# ");
		for (i=0; i<argc; i++) {
			printf ("%s ", argv[i]);
		}
		printf ("\n");
	}
	/* how are we called? Our name can be the algorithm */
	progname = strrchr (argv[0], '/');		// basename
	if (progname && strlen (progname) > 1) {
		algo = ++progname;
	}
	else {
		algo = argv[0];
	}
	// progname may be the algorithm 
	ADD_TO_ALGOLIST (algo, Use_algo, nalgo, this_algo);

	for (i = 1; i < argc; i++){
    	if (strcmp (argv[i], "-s") == 0) {
			sflag++; flags++;
			if (++i<argc) {
				sptr = argv[i];
			}
		}
    	else if (strncmp (argv[i], "--string=", strlen ("--string=")) == 0) {
			sflag++; flags++;
       		sptr = (argv[i] + strlen("--string="));
		}
    	else if (strncmp (argv[i], "--bitstring=", 
			strlen ("--bitstring=")) == 0) {
			bitstringflag++; flags++;
       		bitstringgillogly = (argv[i] + strlen("--bitstring="));
		}
    	else if (strcmp (argv[i], "-t") == 0) {
       		tflag++; flags++;
		}
    	else if (strcmp (argv[i], "--time") == 0) {
       		tflag++; flags++;
		}
    	else if (strcmp (argv[i], "-x") == 0) {
       		xflag++; flags++;
		}
    	else if (strcmp (argv[i], "--test") == 0) {
       		xflag++; flags++;
		}
    	else if (strcmp (argv[i], "-a") == 0) {
			if (++i<argc) {
				algo = argv[i];
				ADD_TO_ALGOLIST (algo, Use_algo, nalgo, this_algo);
			}
			else {					// required algo argument is missing
				Usage (argv[0]);
			}
		}
    	else if (strncmp (argv[i], "--algorithm=", 
					strlen ("--algorithm=")) == 0) {
       		algo = (argv[i] + strlen("--algorithm="));
			ADD_TO_ALGOLIST (algo, Use_algo, nalgo, this_algo);
		}
    	else if (strcmp (argv[i], "-c") == 0) {
       		cflag++; flags++;
			if (++i<argc) {
				cptr = argv[i];
			}
		}
    	else if (strncmp (argv[i], "--check=", strlen ("--check=")) == 0) {
       		cflag++; flags++;
       		cptr = (argv[i] + strlen("--check="));
		}
    	else if (strcmp (argv[i], "--check") == 0) {
       		cflag++; flags++;
       		cptr = NULL;
		}
    	else if (strncmp ("--bits=", argv[i], strlen ("--bits=")) == 0) {
       		bitflag++; 
       		bitcount = atoll (argv[i] + strlen("--bits="));
		}
    	else if (strcmp (argv[i], "-M") == 0) {
			hexmessageflag++; flags++;
			if (++i<argc) 
				hexmessageptr = argv[i];
			else
				hexmessageptr = "";
		}
    	else if (strncmp (argv[i], "--M=", strlen ("--M=")) == 0) {
			hexmessageflag++; flags++;
       		hexmessageptr = (argv[i] + strlen("--M="));
		}
    	else if (strncmp (argv[i], "--hexstring=", 
			strlen ("--hexstring=")) == 0) {
			hexmessageflag++; flags++;
       		hexmessageptr = (argv[i] + strlen("--hexstring="));
		}
    	else if (strcmp (argv[i], "-K") == 0) {
			keyflag++;
			if (++i<argc) 
				keystring = argv[i];
			else
				keystring = "";
		}
    	else if (strncmp (argv[i], "--K=", strlen ("--K=")) == 0) {
			keyflag++;
       		keystring = (argv[i] + strlen("--K="));
		}
    	else if (strncmp (argv[i], "--key=", strlen ("--key=")) == 0) {
			keyflag++;
       		keystring = (argv[i] + strlen("--key="));
		}
    	else if (strncmp (argv[i], "--hexkey=", 
			strlen ("--hexkey=")) == 0) {
			hexkeyflag++;
       		hexkeystring = (argv[i] + strlen("--hexkey="));
		}
    	else if (strncmp (argv[i], "--keylength=", strlen ("--keylength=")) == 0) {
       		keylength = atoi ((argv[i] + strlen("--keylength=")));
		}
    	else if (strcmp (argv[i], "--b64") == 0) {
			base64flag = 1;
		}
    	else if (strcmp (argv[i], "--base64") == 0) {
			base64flag = 1;
		}
    	else if (strncmp (argv[i], "--xoflength=", 
			strlen ("--xoflength=")) == 0) {
			xofflag++;
       		xoflength = atoll (argv[i] + strlen("--xoflength="));
		}
    	else if (strcmp (argv[i], "--binout") == 0) {	// not yet supported
			binoutflag = 1;
		}
    	else if (strcmp (argv[i], "-h") == 0) {
			help_OK = 1;
			Usage (argv[0]);
		}
    	else if (strcmp  (argv[i], "--help") == 0) {
			help_OK = 1;
			Usage (argv[0]);
		}
    	else if (strcmp (argv[i], "--list") == 0) {
			int j;
			for (j=0; j<HashTableSize; j++) {
				printf ("%s\n", HashTable[j].name);
			}
			exit (0);
		}
		else if (argv[i][0] == '-') {
			Usage (argv[0]);
		}
    	else 
       		break;
	}

	if (!nalgo && !cflag && !tflag) Usage(argv[0]);
	if (flags>1) Usage(argv[0]);

	if (cflag) {
		ReadDigest (cptr);
		return (0);
	} else if (tflag) {
		TimeTrial ();
		return (0);
	}

	if (!nalgo) Usage(argv[0]);

	if ((hmacflag || kmacflag) && !xflag) {
		if ((keyflag && hexkeyflag) || (!keyflag && !hexkeyflag)) {
			fprintf (stderr, "HMAC, KMAC requires key or hexkey, but not both.\n");
			exit (1);
		}
		if ((!keyflag && hexkeyflag > 1) || (!hexkeyflag && keyflag > 1)) {
			fprintf (stderr, "HMAC, KMAC requires exactly one key or hexkey.\n");
			exit (1);
		}
		// print HMAC key as a special entry
		// format: key (hmac) = Jefe
		// format: hexkey (hmac) = 01020304
		if (hmacflag) printf ("%s (hmac) = %s\n", hexkeyflag ? "hexkey" : "key", 
			hexkeyflag ? hexkeystring : keystring);

		// print KMAC key as a special entry
		// format: key (kmac) = Jefe
		// format: hexkey (kmac) = 01020304
		if (kmacflag) {
			printf ("%s (kmac) = %s\n", hexkeyflag ? "hexkey" : "key", 
			hexkeyflag ? hexkeystring : keystring);
			// keylength only for hexkeystring allowed
			if (!hexkeyflag && keylength) {	// ASCII key
				fprintf (stderr, "KMAC keylength only allowed for hexkey, ignored.\n");
				keylength = 0;
			} else {	// hexkey
				if (keylength) printf ("length (%s) = %d\n", "kmac", keylength);
			}
		}
	}

	// apply global base64flag, xofflag (xoflength), binoutflag to all algos that apply
	// algo specific flags will be applied in the ADD_TO_ALGOLIST macro
	for (algoptr = &Use_algo; algoptr; algoptr = algoptr->next) {
		struct	hash_algo	*a = algoptr->a;
		if (a->base64_OK && base64flag>0) algoptr->extra.base64flag = base64flag;
		if (a->xof_OK_defaultLength && xofflag>0) { 
			algoptr->extra.xofflag = xofflag;
			algoptr->extra.xoflength = xoflength;
			// algoptr->extra.binoutflag = binoutflag;
		}
	}

	if (flags) {
		// work our way through all algorithms */
		struct test_results *Res = NULL, *this_Res = NULL;

		for (algoptr = &Use_algo; algoptr; algoptr = algoptr->next) {
			struct	hash_algo	*a = algoptr->a;

			if (sflag) {
				DigestString (algoptr, sptr);
			}
			if (xflag) {		// self tests
				// we will call TestSuite(), TestSuiteBitwise(), TestSuiteHMAC()
				// and later on summarize the results
				struct test_results *tmpres;
				tmpres = (struct test_results *) 
						malloc (sizeof (struct test_results));
				memset (tmpres, 0, sizeof (struct test_results));
				if (!Res) {
					Res = tmpres;
					this_Res = tmpres;
				}
				else {
					this_Res->next = tmpres;
					this_Res = tmpres;
				}
				// retval = TestSuite	(a, tmpres);
				retval = TestSuite	(algoptr, tmpres);
					
				tmpres = (struct test_results *) 
						malloc (sizeof (struct test_results));
				memset (tmpres, 0, sizeof (struct test_results));
				this_Res->next = tmpres;
				this_Res = tmpres;
				// retval += TestSuiteBitwise (a, tmpres);
				retval += TestSuiteBitwise (algoptr, tmpres);
					
				tmpres = (struct test_results *) 
						malloc (sizeof (struct test_results));
				memset (tmpres, 0, sizeof (struct test_results));
				this_Res->next = tmpres;
				this_Res = tmpres;
				// retval += TestSuiteHMAC (a, tmpres);
				retval += TestSuiteHMAC (algoptr, tmpres);

			}
			if (hexmessageflag) {
				DigestHexString (algoptr, hexmessageptr, bitflag, bitcount);
			}
			if (bitstringflag) DigestBitStringGillogly (a, bitstringgillogly);
		}
		/* print tests results summary */
		if (Res) {
			struct	test_results	*t;
			printf ("\nSummary of Test Results\n");
			printf (  "-----------------------\n\n");
			int ntests = 0, npass = 0, nfail = 0;
			for (t=Res; t; t=t->next) {
				if (t->tests_ok + t->tests_failed == 0) continue;
				printf ("%-10s  %-20s: passed %2d, failed %d\n",
					t->name, t->test_type, t->tests_ok, t->tests_failed);
				ntests++;
				npass += t->tests_ok;
				nfail += t->tests_failed;
			} 
			printf ("\nCategories: %d, Tests: %d, passed %d, failed %d.\n",
				ntests, npass+nfail, npass, nfail);
		}
	}
	else if (i<argc) {
		// the remaining parameters are file names. We read each file
		// only once and process chunks in parallel for each algorithm
		// we use memory mapping 
		// in the future me may possible use threads for parallel execution
		// a missing file name means we read from stdin
		for (; i<argc; i++) {
			hash_one_file (argv[i], &Use_algo);
		}
	}
	else {	// no files , read stdin
			hash_one_file (NULL, &Use_algo);
	}

	return (retval);
}
/*  end of main */

/* comparison function for sorting the HashTable entries alphabetically */

int qsort_compare_hashtable (const void *a, const void *b)
{
	struct hash_algo *aptr = (struct hash_algo *) a;
	struct hash_algo *bptr = (struct hash_algo *) b;
	return strcmp ((aptr)->name, (bptr)->name);
}
