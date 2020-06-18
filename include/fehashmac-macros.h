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

/* 27.02.2015 add base64 support	*/
/* 02.09.2016 convert algorithm to lower case */

#ifndef	_FEHASHMAC_MACROS_H_
#define	_FEHASHMAC_MACROS_H_

#include <ctype.h>

// global variables for HMAC operation, we can then use macros to
// simplify quality assurance

extern int     hmacflag;       // HMAC request: key and algo required
extern int     keyflag;        // HMAC key supplied as ascii string:
                               // -K, --K=, --key=
extern int     hexkeyflag;     // HMAC key supplied as hex string:
                               // --hexkey=
extern char    *keystring;     // ASCII key string (for HMAC)
extern char    *hexkeystring;  // key string in hex (for HMAC)
extern int     keylength;      // length of keystring in bits for KMAC
extern int     hmacprintflag;  // once is enough
extern int     kmacprintflag;  // once is enough


// HMAC macros: HMAC_INIT, HMAC_UPDATE, HMAC_FINAL

/* ualgo: struct use_algo *
 * kflag = 1: HMAC key is ASCII string 
 * kflag = 0: HMAC key is hex string 
 * printflag: print HMAC key
 *
 * external variables:
 * keystring:		HMAC ASCII key string (used if kflag is set)
 * hexkeystring:	HMAC hex key string (used if kflag is cleared)
 *
 * Note: SHA3 functions incl. SHAKEnnn do not support HMAC but KMAC
 */
#define HMAC_INIT(ualgo,kflag,printflag) do { \
	int j; \
	if (printflag) printf ("%s (hmac) = ", kflag? "key" : "hexkey"); \
	/* prepare key buffers */ \
	ualgo->ipad = (BYTE *) malloc (ualgo->a->inputbuffer_length); \
	ualgo->opad = (BYTE *) malloc (ualgo->a->inputbuffer_length); \
	memset (ualgo->ipad, 0, ualgo->a->inputbuffer_length); \
	memset (ualgo->opad, 0, ualgo->a->inputbuffer_length); \
	BYTE *tempbuf = NULL; \
	int len = 0; \
	/* FIPS PUB 198-1: hash key if key is longer than algo->inputbuffer_length */ \
	/* normalize key first if hex string */ \
	if (kflag) { /* HMAC key is ASCII string */ \
		if (printflag) printf ("%s\n", keystring); \
		tempbuf = (BYTE *) keystring; \
		len = strlen (keystring); \
	} else { /* HMAC key is hex string */ \
		tempbuf = (BYTE *) malloc (strlen(hexkeystring)); \
		memset (tempbuf, 0, strlen(hexkeystring)); \
		len = copyhextobin (tempbuf, strlen(hexkeystring), hexkeystring, \
					strlen (hexkeystring)); /* len is number of nibbles */ \
		len = (len+1)/2;	/* length of tempbuf in bytes */ \
		if (printflag) { \
			for (j=0; j<len; j++)  \
				printf ("%2.2x", tempbuf[j]&0xff); \
			printf ("\n"); \
		} \
	} \
	if (len > ualgo->a->inputbuffer_length) { /* have to hash first */ \
		(*ualgo->a->hash)(ualgo->a->hash_length, tempbuf, len<<3, ualgo->ipad); \
		memcpy (ualgo->opad, ualgo->ipad, ualgo->a->hash_length); \
	} else { /* key is short enough for direct use */ \
		strncpy ((char *)ualgo->ipad, (char *)tempbuf, len); \
		strncpy ((char *)ualgo->opad, (char *)tempbuf, len); \
	} \
	if (!kflag) { free (tempbuf); tempbuf = NULL; } \
	/* XOR ipad and opad, see RFC 2104 and FIPS PUB 198-1 */ \
	for (j=0; j<ualgo->a->inputbuffer_length; j++) { \
		ualgo->ipad[j] ^= 0x36; \
		ualgo->opad[j] ^= 0x5C; \
	} \
} while (0)
			
/* HMAC_UPDATE feeds the padded and XOR'ed HMAC key (in ipad) to the 
 * hash algorithm; later, the actual text is fed to the algorithm
 *
 * ualgo: struct use_algo *
 * context: properly initialized algorithm context
 */
#define HMAC_UPDATE(ualgo,context) do { \
	(*ualgo->a->update)(context, ualgo->ipad, ualgo->a->inputbuffer_length<<3); \
} while (0)

#define HMAC_FINAL(ualgo,out) do { \
	void *context2; \
	(*ualgo->a->init)(&context2, ualgo->a->hash_length<<3, NULL); \
	(*ualgo->a->update)(context2, ualgo->opad, ualgo->a->inputbuffer_length<<3); \
	(*ualgo->a->update) (context2, out, ualgo->a->hash_length<<3); \
	(*ualgo->a->final) (context2, NULL); \
	(*ualgo->a->hashtobyte)(context2, out); \
	(*ualgo->a->free)(context2); context2 = NULL; \
    free (ualgo->ipad); free (ualgo->opad); ualgo->ipad = ualgo->opad = NULL; \
} while (0)

// Macro ADD_TO_ALGOLIST parses the algo parameter and builds up a 
// linked list of algorithms
// Parameters:
//	inputstring		the string to be parsed, comma-separated values
//	uselist			the list of algorithms that is being built
//	nused			number of algorithms found in uselist
//	lastinlist		pointer to last algorithm in list
// External variables:
//	hmacflag		set if one or more HMAC's are requested
//	kmacflag		set if one or more KMAC's are requested
// non-existing algos are silently skipped

#define ADD_TO_ALGOLIST(inputstring,uselist,nused,lastinlist) { \
	char	*ptr = inputstring; \
	char	*endptr = inputstring + strlen (inputstring); \
	while (ptr < endptr) { \
		*ptr = tolower(*ptr);	/* convert algo to lower case */ \
		ptr++; \
	} \
	ptr = inputstring; \
	while (ptr < endptr) { \
		char	*end = strchr (ptr, ','); \
		char	*myalgo = ptr; \
		if (end) {		/* comma found, separate here */ \
			*end = '\0';	/* terminate string at comma */ \
			ptr = end + 1;	/* after comma */ \
		} \
		else {			/* no more comma found, last entry in list */ \
			ptr = endptr; \
		} \
		/* verify algo, add to uselist */ \
		/* check for HMAC and KMAC	*/ \
		int	myhmac = 0;	 \
		if (strncmp (myalgo, "hmac-", strlen ("hmac-")) == 0) { \
			myhmac = 1; \
			hmacflag++;		/* global hmac counter */ \
			myalgo += strlen ("hmac-"); /* jump over leading "hmac-"	*/ \
		} \
		int	mykmac = 0;	 \
		if (strncmp (myalgo, "kmac-", strlen ("kmac-")) == 0) { \
			mykmac = 1; \
			kmacflag++;		/* global kmac counter */ \
			myalgo += strlen ("kmac-"); /* jump over leading "kmac-"	*/ \
		} \
		/* check for trailing -b64 for base64 support */ \
		int myb64 = 0; \
		char *p; \
		if ((p = strstr (myalgo, "-b64"))) { \
			myb64 = 1; \
			*p = '\0'; /* delete trailing -b64 */ \
		} \
		int j; \
		for (j=0; j<sizeof(HashTable)/sizeof(HashTable[0]); j++) { \
			if ((strcmp (myalgo, HashTable[j].name) == 0) || \
				(strcmp (myalgo, "all") == 0)) { \
				/* algorithm found: add to list */ \
				/* if hmac, kmac and/or base64 requested but not supported, then skip silently */ \
				/* this means no fallback to unsupported std algo (e.g. md5 instead of m5-b64) */ \
				if (myhmac && !hmac_OK(HashTable[j].mac_OK)) continue; \
				if (mykmac && !kmac_OK(HashTable[j].mac_OK)) continue; \
				if (myb64 && !HashTable[j].base64_OK) continue; \
				/* first entry */ \
				if (nused++ == 0) { \
					memset (&uselist, 0, sizeof (struct use_algo)); \
					uselist.name = HashTable[j].name; \
					uselist.a = HashTable + j; \
					uselist.hmacflag = myhmac; \
					uselist.kmacflag = mykmac; \
					uselist.extra.base64flag = myb64; \
					uselist.next = NULL; \
					lastinlist = &uselist; \
				} \
				else { \
					/* allocate space, link into end of list */ \
					struct use_algo *use = (struct use_algo *) malloc (sizeof (struct use_algo)); \
					memset (use, 0, sizeof (struct use_algo)); \
					lastinlist->next = use; \
					use->name = HashTable[j].name; \
					use->a = HashTable + j; \
					use->next = NULL; \
					use->hmacflag = myhmac; \
					use->kmacflag = mykmac; \
					use->extra.base64flag = myb64; \
					lastinlist = use; \
				} \
			} \
		} \
	} \
} while (0)

// KMAC macros: KMAC_INIT, KMAC_UPDATE

/* ualgo: struct use_algo *
 * kflag = 1: KMAC key is ASCII string 
 * kflag = 0: KMAC key is hex string 
 * printflag: print KMAC key
 *
 * external variables:
 * keystring:		KMAC ASCII key string (used if kflag is set)
 * hexkeystring:	KMAC hex key string (used if kflag is cleared)
 * keylength:		length of hex key in bits (if not whole bytes)
 *
 * Note: SHA3 functions incl. XOFSHAKEnnn support KMAC
 */
#define KMAC_INIT(ualgo,kflag,printflag) do { \
	int j; \
	if (printflag) printf ("KMAC_INIT %s (kmac) = ", kflag? "key" : "hexkey"); \
	/* keypack: lenpack, key, padding, see http://keyak.noekeon.org/Keyak-1.2.pdf */ \
	BYTE *tempbuf = NULL; \
	int len = 0; \
	int lenpack; \
	if (kflag) { /* HMAC key is ASCII string */ \
		if (printflag) printf ("%s\n", keystring); \
		tempbuf = (BYTE *) keystring; \
		len = strlen (keystring); \
		lenpack = len + 2; \
	} else { /* KMAC key is hex string */ \
		tempbuf = (BYTE *) malloc (strlen(hexkeystring)); \
		memset (tempbuf, 0, strlen(hexkeystring)); \
		len = copyhextobin (tempbuf, strlen(hexkeystring), hexkeystring, \
					strlen (hexkeystring)); /* len is number of nibbles */ \
		/* if more nibbles than required, OK even if odd */ \
		if (keylength) { \
			if ((len/2) >= ((keylength+7)/8)) { \
				len = (keylength+7)/8; \
			} else { \
				fprintf (stderr, "kmax hexkeystring is too short: has %d bits, but expects %d, stop.\n", \
						len*4, keylength); \
				exit (1); \
			} \
		} else { \
			if (len&0x01) { fprintf (stderr, "kmac hexkeystring has odd number of nibbles %d, stop.\n", len); \
						printf ("\n"); \
						exit (1); \
			} \
			len = (len+1)/2;	/* length of tempbuf in bytes */ \
		} \
		if (printflag) { \
			for (j=0; j<len; j++)  \
				printf ("%2.2x", tempbuf[j]&0xff); \
			printf ("\n"); \
		} \
		if (keylength % 8) lenpack = len + 1; else lenpack = len + 2; \
	} \
	if (lenpack > 255) { fprintf (stderr, "KMAC: key is too long, only 253 bytes or 2031 bits are safe.\n"); exit (1); } \
	ualgo->keypacklen = lenpack; \
	/* copy to buf and pad */ \
	ualgo->keypack = (BYTE *) malloc (lenpack); \
	memset (ualgo->keypack, 0, lenpack); \
	ualgo->keypack[0] = lenpack & 0xff; \
	memcpy (ualgo->keypack+1, tempbuf, len); \
	if (!kflag) { free (tempbuf); tempbuf = NULL; } \
	if (keylength % 8) { int bit = 0x01 << (keylength%8); int mask = bit - 1; \
		ualgo->keypack[len] &= mask; ualgo->keypack[len] |= bit; } \
	else { ualgo->keypack[len+1] = 0x01; } \
	if (printflag) { \
		printf ("Keypack %d bytes: ", lenpack); \
		for (j=0; j<lenpack; j++) \
			printf ("%2.2x", ualgo->keypack[j] & 0xff); \
		printf ("\n"); \
	} \
} while (0)
			
/* KMAC_UPDATE feeds the padded KMAC key (in keypack) to the 
 * hash algorithm; later, the actual text is fed to the algorithm
 *
 * ualgo: struct use_algo *
 * context: properly initialized algorithm context
 */
#define KMAC_UPDATE(ualgo,context) do { \
	(*ualgo->a->update)(context, ualgo->keypack, ualgo->keypacklen<<3); \
	free (ualgo->keypack); ualgo->keypack = NULL; \
} while (0)

#endif
