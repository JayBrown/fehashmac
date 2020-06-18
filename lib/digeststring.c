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

/* 29.12.2014 hvf		do_HexString improved
 * 27.02.2015 hvf		base64 encoding added for strings
 * 13.05.2015 hvf		KMAC implemented
 */

#include	"fehashmac.h"
#include	"fehashmac-macros.h"
#include	<assert.h>
#include	"base64.h"

int	hextobin (int c)
{
	int x;
	if (c == 0) return -2;
	if ((c>='0') && (c<='9')) x = c-'0';
	else if ((c>='a') && (c<='f')) x = c-'a'+10;
	else if ((c>='A') && (c<='F')) x = c-'A'+10;
	else	x = -1;
	return x;
}

/* copies the hex string 'hexstring' into the BYTE array 'out'
 * out: BYTE array receiving the converted hex string
 * outlen: length of array out
 * hexstring: const char array containing the hexadecimal string
 *            non-hex characters (e.g. blanks) are silently skipped
 * hexlen: length of array hexstring (without trailing null byte if present)
 * returns number of nibbles that have been copied
 */
int	copyhextobin (BYTE out[], int outlen, char *hexstring, int hexlen)
{
	int i = 0, temp;
	int nibblecount = 0;
	BYTE *outptr = out;
	while ((nibblecount < outlen+outlen) && (i < hexlen)) {
		temp = hextobin (hexstring[i++]);
		if (temp == -1) {	// blank or other non-hex char: skip
			continue;
		}
		else if (temp == -2) {	// end of hexstring: done
			break;
		}
		else {
			nibblecount++;
			if (nibblecount & 0x1) {	// odd: shift nibble
				*outptr = temp << 4;
			}
			else {
				*outptr |= temp & 0x0f;
				outptr++;
			}
		}
	}
	return nibblecount;
}
	
		
/* compare (binary) hash in hash_out[] with the ASCII digest in digest */	
/* digest may contain white space */

int	verify_hash	(BYTE hash_out[], char *digest, int len)
{
	int	n, truth = 0, temp;

	while (len-- > 0) {
		while ((temp = hextobin (*digest++)) < 0) {
			// untimely EOF? 
			if (temp == -2) {
				fprintf (stderr, "verify_hash: ERROR: digest is too short\n");
				exit (1);
			}
		}

		n = temp << 4;

		while ((temp = hextobin (*digest++)) < 0)
			;
		// untimely EOF? 
		if (temp == -2) {
			fprintf (stderr, "verify_hash: ERROR: digest is too short\n");
			exit (1);
		}

		n += temp;
		if (!(truth = (n == (*hash_out++ & 0xff))))
			break;
	}
	return truth;
}


/* Digests a string and prints the result.
 */

void DigestString (struct use_algo *ua, char *string)
{
	unsigned int len;
	int	i;
    void *context;
	struct	hash_algo *a = ua->a;
	HashReturn retval = (*a->init)(&context, a->hash_length<<3, &ua->extra);
	if (retval) hash_error (retval);
	// BYTE	*out = (BYTE *) malloc (2*a->hash_length+1);
	// memset (out, 0, 2*a->hash_length+1);
	BYTE	out[HASHBUFSIZ];
	memset (out, 0, sizeof(out));
	if (!string) string = "";
	len = strlen (string);

	if (ua->hmacflag) {
		HMAC_INIT (ua, keyflag, hmacprintflag);
#ifdef DEBUG
		printf ("HMAC with string \"%s\"\n", string);
#endif
		HMAC_UPDATE (ua, context);
	}

	if (ua->kmacflag) {
		KMAC_INIT (ua, keyflag, kmacprintflag);
#ifdef DEBUG
		printf ("KMAC with string \"%s\"\n", string);
#endif
		KMAC_UPDATE (ua, context);
	}

	(*a->update) (context, (BYTE *) string, len<<3);
	(*a->final) (context, out);
	(*a->hashtobyte)(context, out);
	// (*a->free)(context); context = NULL;
	if (ua->hmacflag) {
		HMAC_FINAL (ua, out);
	}

	// base64 requested
	if (ua->extra.base64flag) {
		if (len < 256)
			printf ("%s-b64 (\"%s\") = ", a->name, string);
		else
			printf ("%s-b64 (\"%256.256s\"...) = ", a->name, string);
		// not xof
		if (!a->xof_OK_defaultLength) {
			print_b64 (out, a->hash_length);
		} else {
			SHA3_CTX *ctx = (SHA3_CTX *) context;
			print_b64 (out, ctx->this_chunk_size);
			// second and later chunks
            while (ctx->more_size) {    // either positive or -1
                (*a->final)(ctx, out);
				print_b64 (out, ctx->this_chunk_size);
			}
		}
		printf ("\n");
	}
	else {
		if (len < 256)
			printf ("%s%s (\"%s\") = ", ua->hmacflag? "hmac-" : "", 
				a->name, string);
		else
			printf ("%s%s (\"%256.256s\"...) = ", ua->hmacflag? "hmac-" : "", 
				a->name, string);
		// not xof
		if (!a->xof_OK_defaultLength) {
			for (i=0; i<a->hash_length; i++)
				printf ("%2.2x", out[i]&0xff);
		} else {
			SHA3_CTX *ctx = (SHA3_CTX *) context;
			for (i=0; i<ctx->this_chunk_size; i++)
				printf ("%2.2x", out[i]&0xff);
			// second and later chunks
            while (ctx->more_size) {    // either positive or -1
                (*a->final)(ctx, out);
				for (i=0; i<ctx->this_chunk_size; i++)
					printf ("%2.2x", out[i]&0xff);
			}
		}
		printf ("\n");
	}
	(*a->free)(context); context = NULL;
	// free (out);
}

void DigestHexString (struct use_algo *ua, char *hexstring, 
	int bitflag, uint64 bitcount)
{
	// prints only the digest, without any leading stuff like md5 (string) = digest
	struct	hash_algo	*a = ua->a;
	void *context;
	BYTE	out[HASHBUFSIZ];	/* output array */
	int i;
	HashReturn retval = (*a->init)(&context, a->hash_length<<3, &ua->extra);
	if (retval) hash_error (retval);

	if (bitflag && ua->hmacflag) {	// not supported!
		fprintf (stderr, "ERROR: HMAC not supported for bitwise operations.\n");
		exit (1);
	}

	// error message if trying bitcount and no support available
	if (bitflag && !a->bitwise_support) {
		fprintf (stderr, "WARNING: Algorithm %s does not support --bits option, bitcount is ignored!\n"
			"(Results may not be what you expect!)\n", a->name);
		bitcount = 0;
		bitflag = 0;
	}
	if (ua->hmacflag) {
#ifdef DEBUG
		printf ("HMAC with hexstring %s\n", hexstring);
#endif
		HMAC_INIT (ua, keyflag, hmacprintflag);
		HMAC_UPDATE (ua, context);
	}
	if (ua->kmacflag) {
		KMAC_INIT (ua, keyflag, kmacprintflag);
#ifdef DEBUG
		printf ("KMAC with hexstring \"%s\"\n", string);
#endif
		KMAC_UPDATE (ua, context);
	}

	do_HexString (a, context, hexstring, bitcount, bitflag && a->bitwise_support);
	// make sure out is large enough
	assert (sizeof(out) >= a->hash_length);
	(*a->hashtobyte)(context, out);

	if (ua->hmacflag) {
		HMAC_FINAL (ua, out);
	}

	// base64 requested
	if (ua->extra.base64flag) {
		// not xof
		if (!a->xof_OK_defaultLength) {
			print_b64 (out, a->hash_length);
		} else {	/* NOTE: ONLY sha3 honors the xof flag */
			SHA3_CTX *ctx = (SHA3_CTX *) context;
			print_b64 (out, ctx->this_chunk_size);
			// second and later chunks
            while (ctx->more_size) {    // either positive or -1
                (*a->final)(ctx, out);
				print_b64 (out, ctx->this_chunk_size);
			}
		}
		printf ("\n");
	}
	else {
		// not xof
		if (!a->xof_OK_defaultLength) {
			for (i=0; i<a->hash_length; i++)
				printf ("%2.2x", out[i]&0xff);
		} else {
			SHA3_CTX *ctx = (SHA3_CTX *) context;
			for (i=0; i<ctx->this_chunk_size; i++)
				printf ("%2.2x", out[i]&0xff);
			// second and later chunks
            while (ctx->more_size) {    // either positive or -1
                (*a->final)(ctx, out);
				for (i=0; i<ctx->this_chunk_size; i++)
					printf ("%2.2x", out[i]&0xff);
			}
		}
		printf ("\n");
	}
	(*a->free)(context); context = NULL;
	return;
}

void do_HexString (struct hash_algo *a, void *context, char *hexstring, 
	DataLength bitcount, int bitwise_OK)
	// bitcount is honored iff bitwise_OK is set
{
	int hexlen = strlen (hexstring);
	int outlen;
	if (bitwise_OK && (bitcount >= 0)) {
		outlen = (bitcount+15)/8;	// one too much, I know
	} else {
		outlen = (hexlen + 3)/2;	// also on the safe side
	}
	BYTE *out = (BYTE *) malloc (outlen);
	memset (out, 0, outlen);
	if (!out) {
		perror ("DigestHexString malloc");
		exit (1);
	}
	int nibbles;
	nibbles = copyhextobin (out, outlen, hexstring, hexlen);
	if (nibbles & 0x01) {
		fprintf (stderr, "do_HexString: read odd number of hex values: %d, last bits may have wrong alignment\n",
					nibbles);
	}
	if (nibbles*4 < bitcount) {
		fprintf (stderr, "do_Hexstring: want %lld bits but got only %d, terminate.\n", bitcount, nibbles*4);
		exit (1);
	}
	// calculate bitcount from nibbles unless bitwise_OK
	if (!bitwise_OK) bitcount = 4 * nibbles;
	(*a->update)(context, out, bitcount);
	(*a->final) (context, NULL);
	free (out);
}
	
void DigestBitStringGillogly (struct hash_algo *a, char *bitstringgillogly)
{
	/* bitstringgillogly has this format:
	 * bbb#nnn|bb	where bbb are bits (0 or 1), nnn is the decimal 
	 * repetition factor, and | means concatenation
	 * Jim Gillogly (jim at acm.org), 23.02.1999: SHA-1 bitwise test vectors
	 */

	if (!a->bitwise_support){
		fprintf (stderr, "Bitwise operation not supported for %s.\n",
			a->name);
		exit (1);
	}
	char    *out = (char *) malloc (2*a->hash_length+1);
	memset (out, 0, 2*a->hash_length+1);
	int i;

    void *context;
	HashReturn retval = (*a->init)(&context, a->hash_length<<3, NULL);
	if (retval) hash_error (retval);

	do_BitStringGillogly (a, context, bitstringgillogly);

	(*a->hashtobyte) (context, (unsigned char *) out);
	printf ("%s (\"bitstring=%s\") = ", a->name, bitstringgillogly);
	for (i=0; i<a->hash_length; i++)
	   printf ("%2.2x", out[i]&0xff);
	printf ("\n");
	free (out);
	(*a->free) (context);
}

void do_BitStringGillogly (struct hash_algo *a, void *context, 
		char *bitstringgillogly)
{
	unsigned int bits = 0;
	unsigned long long repetitions = 0;
	int	nbits = 0;
	BitSequence datum = 0;
	unsigned long long Totalbits = 0;

	char *savedbitstring = strdup (bitstringgillogly);

	maketokens (savedbitstring);
	struct token *token;
	
	token = getnexttoken ();
	if (!token || token->token != ISHEXNUMBER) {
		fprintf (stderr, "bitstring does not start with bits: %d\n",
			token->token);
		exit (1);
	}
	// bitstring
	char *p = token->text;
	do {
		int c = *p;
		if (c == '0') {
			bits <<= 1; 
			nbits++;
		} else if (c == '1') {
			bits = (bits<<1) | 0x01;
			nbits++;
		} else {
			fprintf (stderr, 
				"bitstring contains illegal characters: %s %c\n",
				token->text, c);
			exit (1);
		}
	} while (*++p);
	// hash
	// fill bits into datum, left adjusted
	datum = bits << (BITSPERBYTE - nbits);
	repetitions = 1;
	token = getnexttoken ();
	if (token && token->token == ISHASH) {
		token = getnexttoken ();
		repetitions = atoll (token->text);
	}
	Totalbits += nbits * repetitions;
	while (repetitions-- > 0)
		(*a->update)(context, &datum, nbits);

	// pipe or nothing
	token = getnexttoken ();
	if (token && token->token == ISPIPE) {
		token = getnexttoken ();
		if (token && token->token == ISHEXNUMBER) {
			// bitstring
			char *p = token->text;
			bits = 0; nbits = 0;
			do {
				int c = *p;
				if (c == '0') {
					bits <<= 1; 
					nbits++;
				} else if (c == '1') {
					bits = (bits<<1) | 0x01;
					nbits++;
				} else {
					fprintf (stderr, 
						"bitstring contains illegal characters: %s %c\n",
						token->text, c);
					exit (1);
				}
			} while (*++p);
			Totalbits += nbits;
			datum = bits << (BITSPERBYTE - nbits);
			(*a->update)(context, &datum, nbits);
		}
	}
	
#ifdef DEBUG
	printf ("do_BitStringGillogly: seen %lld bits\n", Totalbits);
#endif
	(*a->final)(context, NULL);
	free (savedbitstring);
}

static struct token *Tokens;
static int Tokenindex, Maxtokenindex;
	
void maketokens (char *buf)
{
	/* reserve enough space for tokens */
	int buflen = strlen (buf) + 1;

	if (Tokens) free (Tokens);
	Tokens = (struct token *) malloc (buflen * sizeof (struct token));
	memset (Tokens, 0, buflen * sizeof (struct token));
	Tokenindex = Maxtokenindex = 0;

	char *cptr = buf;
	int c;
	enum Token currentToken = ISEMPTY;

	/* analyze buf */

	while ((c = *cptr)) {
		if (isspace(c)) {
			currentToken = ISSPACE;
			Tokens[Maxtokenindex++].token =  currentToken;
			*cptr = '\0';	// set to null byte
		} else if (c == '#') {
			currentToken = ISHASH;
			Tokens[Maxtokenindex++].token =  currentToken;
			*cptr = '\0';	// set to null byte
		} else if (c == '|') {
			currentToken = ISPIPE;
			Tokens[Maxtokenindex++].token =  currentToken;
			*cptr = '\0';	// set to null byte
		} else if (c == '^') {
			currentToken = ISCIRCUMFLEX;
			Tokens[Maxtokenindex++].token =  currentToken;
			*cptr = '\0';	// set to null byte
		} else if (isxdigit(c)) {
			// start of one or more digits: consume 'em all
			char *auxptr = cptr;
			int c1;
			Tokens[Maxtokenindex].text = cptr; 
			Tokens[Maxtokenindex++].token = ISHEXNUMBER; 
			currentToken = ISHEXNUMBER;
			while (isxdigit (c1=*auxptr++))
				;
			// we have gone one too far
			cptr = auxptr-2;
		} else {
			Tokens[Maxtokenindex++].token = ISOTHER;
			*cptr = '\0';	// set to null byte
		}
		cptr++;
	}
	// end of parsing
	Tokens[Maxtokenindex++].token = ISEMPTY;
}

struct token *getnexttoken ()
{
#ifdef DEBUG
	printf ("getnexttoken %s %d\n",
		Tokens[Tokenindex].text? Tokens[Tokenindex].text : "(null)",
		Tokens[Tokenindex].token);
#endif
	return (Tokenindex < Maxtokenindex) ? Tokens+Tokenindex++ : NULL;
}

