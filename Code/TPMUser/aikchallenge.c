/* Challenge a claimed AIK public key and EK certificate */
/* This encrypts a specified string to the Endorsement Key, which will only
 * decrypt it if the corresponding AIK is legitimate. */
/* Also checks that EK cert is valid and rooted at trusted Verisign cert */

/*
 * Copyright (c) 2009 Hal Finney
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <stdio.h>
#include <string.h>
#include <memory.h>
#include <openssl/x509.h>

#define TPM_ALG_AES				0x00000006
#define TPM_ES_SYM_CBC_PKCS5PAD	((UINT16)0x00ff)
#define TPM_SS_NONE				((UINT16)0x0001)




#ifndef BYTE
#define BYTE unsigned char
#endif

#ifndef UINT16
#define UINT16 unsigned short
#endif

#ifndef UINT32
#define UINT32 unsigned
#endif

/* VeriSign Trusted Platform Module Root CA modulus */
/* (defined at end of file) */
static BYTE trustedRoot[256];

static int verifyCertChain (BYTE *rootMod, UINT32 rootModLen, UINT32 nCerts, BYTE *certs);


int
main (int ac, char **av)
{
	FILE		*f_in;
	FILE		*f_out;
	UINT32		proofLen;
	BYTE		*proof;
	BYTE		*pub;
	UINT32		pubLen;
	BYTE		*certs;
	UINT32		certsLen;
	UINT32		certLen;
	BYTE		key[128/8];
	BYTE		iv[16];
	BYTE		asymPlain[8 + sizeof(key) + SHA_DIGEST_LENGTH];
	const unsigned char oaepPad[4] = "TCPA";
	BYTE		*asymPadded;
	UINT32		asymPaddedLength;
	BYTE		*asymEnc;
	UINT32		asymEncLength;
	BYTE		*chal;
	UINT32		chalLen;
	BYTE		*symEnc;
	UINT32		symEncLength;
	BYTE		*symAttest;
	UINT32		symAttestLength;
	EVP_CIPHER_CTX ctx;
	X509		*ekX509;
	X509_NAME	*ekSubj;
	EVP_PKEY	*ekPkey;
	RSA			*ekRsa;
	RSA			*aikRsa;
	UINT32		tt[1];
	int			trousersIVMode = 1;
	int			out1, out2;
	int			nCerts;
	int			result;

	if (ac != 5) {
		fprintf (stderr, "Usage: %s secretfile aikprooffile outchallengefile outrsafile\n", av[0]);
		exit (1);
	}

	/* Read challenge */
	if ((f_in = fopen (av[1], "rb")) == NULL) {
		fprintf (stderr, "Unable to open file %s\n", av[1]);
		exit (1);
	}
	fseek (f_in, 0, SEEK_END);
	chalLen = ftell (f_in);
	fseek (f_in, 0, SEEK_SET);
	chal = malloc (chalLen);
	if (fread (chal, 1, chalLen, f_in) != chalLen) {
		fprintf (stderr, "Unable to read file %s\n", av[1]);
		exit (1);
	}
	fclose (f_in);

	/* Read AIK proof */
	if ((f_in = fopen (av[2], "rb")) == NULL) {
		fprintf (stderr, "Unable to open file %s\n", av[2]);
		exit (1);
	}
	fseek (f_in, 0, SEEK_END);
	proofLen = ftell (f_in);
	fseek (f_in, 0, SEEK_SET);
	proof = malloc (proofLen);
	if (fread (proof, 1, proofLen, f_in) != proofLen) {
		fprintf (stderr, "Unable to read file %s\n", av[2]);
		exit (1);
	}
	fclose (f_in);

	if (proofLen < 3)
		goto badproof;
	pubLen = ntohl (*(UINT32*)proof);
	if (pubLen + 4 + 4 > proofLen)
		goto badproof;
	pub = proof + 4;
	proof += pubLen+4;
	proofLen -= pubLen+4;

	certsLen = ntohl (*(UINT32*)proof);
	if (certsLen + 4 != proofLen)
		goto badproof;
	proof += 4;
	certs = proof;

	nCerts = 0;
	for ( ; ; ) {
		++nCerts;
		if (certsLen < 3)
			goto badproof;
		certLen = (proof[0]<<16) | (proof[1]<<8) | proof[2];
		if (certLen + 3 > certsLen)
			goto badproof;
		proof += certLen + 3;
		certsLen -= certLen + 3;
		if (certsLen == 0)
			break;
	}

	if (verifyCertChain (trustedRoot, sizeof(trustedRoot), nCerts, certs) != 0) {
		fprintf (stderr, "Unable to validate certificate chain in proof file\n");
		exit (1);
	}

	/* Pull endorsement key from 1st cert */
	certLen = (certs[0]<<16) | (certs[1]<<8) | certs[2];
	certs += 3;
	if ((ekX509 = d2i_X509 (NULL, (unsigned char const **)&certs, certLen)) == NULL)
		goto badproof;
	/* One last check: EK certs must have empty subject fields */
	if ((ekSubj = X509_get_subject_name (ekX509)) == NULL)
		goto badproof;
	if (X509_NAME_entry_count (ekSubj) != 0)
		goto badproof;
	/* OpenSSL can't parse EK key due to OAEP OID - fix it */
	{
		X509_PUBKEY *pk = X509_get_X509_PUBKEY(ekX509);
		int algbufLen = i2d_X509_ALGOR(pk->algor, NULL);
		unsigned char *algbuf = malloc(algbufLen);
		unsigned char *algbufPtr = algbuf;
		i2d_X509_ALGOR(pk->algor, &algbufPtr);
		if (algbuf[12] == 7)
			algbuf[12] = 1;
		algbufPtr = algbuf;
		d2i_X509_ALGOR(&pk->algor, (void *)&algbufPtr, algbufLen);
		free (algbuf);
	}
	if ((ekPkey = X509_get_pubkey (ekX509)) == NULL)
		goto badproof;
	if ((ekRsa = EVP_PKEY_get1_RSA (ekPkey)) == NULL)
		goto badproof;

	/* Construct encrypted output challenge */
	RAND_bytes (key, sizeof(key));
	RAND_bytes (iv, sizeof(iv));

	/* Prepare buffer to be RSA encrypted to endorsement key */
	((UINT32 *)asymPlain)[0] = htonl(TPM_ALG_AES);
	((UINT16 *)asymPlain)[2] = htons(TPM_ES_SYM_CBC_PKCS5PAD);
	((UINT16 *)asymPlain)[3] = htons(sizeof(key));
	memcpy (asymPlain+8, key, sizeof(key));
	SHA1 (pub, pubLen, asymPlain + 8 + sizeof(key));

	/* Encrypt to EK */
	/* Must use custom padding for TPM to decrypt it */
	asymPaddedLength = asymEncLength = RSA_size (ekRsa);
	asymPadded = malloc (asymPaddedLength);
	asymEnc = malloc (asymEncLength);
	RSA_padding_add_PKCS1_OAEP(asymPadded, asymPaddedLength, asymPlain,
					sizeof(asymPlain), oaepPad, sizeof(oaepPad));
	RSA_public_encrypt (asymPaddedLength, asymPadded, asymEnc, ekRsa, RSA_NO_PADDING);
	free (asymPadded);
	asymPadded = NULL;

	/* Encrypt challenge with key */
	symEnc = malloc (chalLen + sizeof(iv));
	EVP_CIPHER_CTX_init (&ctx);
	EVP_EncryptInit(&ctx, EVP_aes_128_cbc(), key, iv);
	EVP_EncryptUpdate (&ctx, symEnc, &out1, chal, chalLen);
	EVP_EncryptFinal_ex (&ctx, symEnc+out1, &out2);
	EVP_CIPHER_CTX_cleanup(&ctx);
	symEncLength = out1 + out2;

	/* Create TPM_SYM_CA_ATTESTATION struct to hold encrypted cert */
	symAttestLength = 28 + sizeof(iv) + symEncLength;
	symAttest = malloc (symAttestLength);
	((UINT32 *)symAttest)[0] = htonl(symEncLength);
	((UINT32 *)symAttest)[1] = htonl(TPM_ALG_AES);
	((UINT16 *)symAttest)[4] = htons(TPM_ES_SYM_CBC_PKCS5PAD);
	((UINT16 *)symAttest)[5] = htons(TPM_SS_NONE);
	((UINT32 *)symAttest)[3] = htonl(12+sizeof(iv));
	((UINT32 *)symAttest)[4] = htonl(128);		/* Key length in bits */
	((UINT32 *)symAttest)[5] = htonl(sizeof(iv));	/* Block size in bytes */
	((UINT32 *)symAttest)[6] = htonl(sizeof(iv));	/* IV size in bytes */
	memcpy (symAttest+28, iv, sizeof(iv));
	memcpy (symAttest+28+sizeof(iv), symEnc, symEncLength);
	if (trousersIVMode) {
		((UINT32 *)symAttest)[0] = htonl(symEncLength + sizeof(iv));
		((UINT32 *)symAttest)[3] = htonl(12);		/* Take IV to be start of symEnc */
		((UINT32 *)symAttest)[6] = htonl(0);		/* IV size in bytes */
	}
	free (symEnc);
	symEnc = NULL;

	if ((f_out = fopen (av[3], "wb")) == NULL) {
		fprintf (stderr, "Unable to open file %s for output\n", av[3]);
		exit (1);
	}
	/* Precede the two blocks with 4-byte lengths */
	tt[0] = htonl (asymEncLength);
	fwrite (tt, 1, sizeof(UINT32), f_out);
	fwrite (asymEnc, 1, asymEncLength, f_out);
	tt[0] = htonl (symAttestLength);
	fwrite (tt, 1, sizeof(UINT32), f_out);
	if (fwrite (symAttest, 1, symAttestLength, f_out) != symAttestLength) {
		fprintf (stderr, "Unable to write to file %s\n", av[3]);
		exit (1);
	}
	fclose (f_out);

	/* Output RSA key representing the AIK for future use */
	if ((f_out = fopen (av[4], "wb")) == NULL) {
		fprintf (stderr, "Unable to open file %s for output\n", av[4]);
		exit (1);
	}
	aikRsa = RSA_new();
	aikRsa->n = BN_bin2bn (pub+pubLen-256, 256, NULL);
	aikRsa->e = BN_new();
	BN_set_word (aikRsa->e, 0x10001);
	if (PEM_write_RSA_PUBKEY(f_out, aikRsa) < 0) {
		fprintf (stderr, "Unable to write to file %s\n", av[3]);
		exit (1);
	}
	fclose (f_out);

	printf ("Success!\n");
	return 0;

badproof:
	fprintf (stderr, "Input AIK proof file incorrect format\n");
	return 1;
}



/* Check a certificate chain based on a trusted modulus from some root. */
/* The trusted root should sign the last extra cert; that should sign */
/* the previous one, and so on. */
/* Each cert is preceded by a 3-byte length in big-endian format */
/* We don't need to check the BasicConstraints field, for 2 reasons. */
/* First, we have to trust TPM vendor certifications anyway. */
/* And second, the last cert is an EK cert, and the TPM won't let EKs sign */
/* Return 0 if OK, -1 otherwise */
static int
verifyCertChain (BYTE *rootMod, UINT32 rootModLen, UINT32 nCerts, BYTE *certs)
{
	X509		*tbsX509 = NULL;
	EVP_PKEY	*pkey = NULL;
	RSA			*rsa;
	BYTE		*pCert;
	UINT32		certLen;
	int			rslt = -1;
	int			i, j;

	EVP_add_digest(EVP_sha1());
	pkey = EVP_PKEY_new ();
	rsa = RSA_new ();
	rsa->n = BN_bin2bn (rootMod, rootModLen, rsa->n);
	rsa->e = BN_new();
	BN_set_word (rsa->e, 0x10001);
	EVP_PKEY_assign_RSA (pkey, rsa);

	for (i=nCerts-1; i>=0; i--) {
		pCert = certs;
		for (j=0; j<i; j++) {
			certLen = (pCert[0]<<16) | (pCert[1]<<8) | pCert[2];
			pCert += 3 + certLen;
		}
		certLen = (pCert[0]<<16) | (pCert[1]<<8) | pCert[2];
		pCert += 3;
		tbsX509 = d2i_X509 (NULL, (unsigned char const **)&pCert, certLen);
		if (!tbsX509)
			goto done;
		if (X509_verify (tbsX509, pkey) != 1)
			goto done;
		if (i > 0) {
			EVP_PKEY_free (pkey);
			pkey = X509_get_pubkey(tbsX509);
			if (pkey == NULL)
				goto done;
		}
		X509_free (tbsX509);
		tbsX509 = NULL;
	}
	/* Success */
	rslt = 0;
done:
	if (pkey)
		EVP_PKEY_free (pkey);
	if (tbsX509)
		X509_free (tbsX509);
	return rslt;
}


/* VeriSign Trusted Platform Module Root CA modulus */
static BYTE trustedRoot[256] = {
	0xD9, 0x50, 0x6B, 0x40, 0xE8, 0x7B, 0x63, 0x55,
	0x87, 0x73, 0x3C, 0x6D, 0xD4, 0x81, 0xA7, 0xAE,
	0x50, 0x4A, 0x2A, 0xBD, 0x0A, 0xE8, 0xE6, 0x57,
	0x56, 0x59, 0x6B, 0xE8, 0x5E, 0x6F, 0xB8, 0x5D,
	0x25, 0x9D, 0xE6, 0xA3, 0x09, 0x1A, 0x71, 0x64,
	0x95, 0x27, 0x7B, 0xBB, 0xFB, 0xFD, 0xAA, 0x71,
	0x7A, 0xCA, 0xF9, 0xF4, 0xBA, 0xD0, 0x70, 0x36,
	0xCE, 0x92, 0xD9, 0x6B, 0x19, 0x75, 0xF3, 0x39,
	0x78, 0xCA, 0x05, 0xA5, 0xD9, 0x06, 0x42, 0x8E,
	0x3B, 0xC4, 0x4E, 0x20, 0x4D, 0x80, 0x7B, 0xAA,
	0xEC, 0x94, 0xE3, 0x32, 0x9E, 0x53, 0xC7, 0x58,
	0xFE, 0x07, 0x29, 0xDA, 0x20, 0x65, 0xED, 0xCB,
	0x3C, 0xF5, 0x62, 0xB8, 0x2D, 0x78, 0xBA, 0x18,
	0x33, 0xE6, 0x25, 0xC9, 0xF2, 0x91, 0x5F, 0x51,
	0x07, 0x4A, 0xC4, 0x27, 0x4A, 0x59, 0x3C, 0xC8,
	0x0A, 0x0D, 0x01, 0xFA, 0x5E, 0x3A, 0xA6, 0x9E,
	0x36, 0x17, 0x1A, 0xFC, 0xDD, 0xE4, 0x7B, 0xD8,
	0xEF, 0x64, 0x4B, 0x31, 0x2A, 0x8A, 0x39, 0x1A,
	0x61, 0xDA, 0x03, 0xC7, 0x4E, 0xB2, 0xC5, 0x60,
	0x0B, 0x82, 0xE5, 0x06, 0xCD, 0x2E, 0xC7, 0xE6,
	0xCC, 0x9C, 0x9E, 0xED, 0xAD, 0x00, 0x60, 0xC6,
	0x16, 0xB9, 0xAC, 0x42, 0x88, 0x7C, 0x98, 0xAE,
	0x05, 0x52, 0x2E, 0x6F, 0x71, 0xEF, 0x09, 0xB9,
	0x6B, 0xA1, 0x8A, 0xB0, 0x97, 0x67, 0x39, 0x8F,
	0xFD, 0xF5, 0x78, 0xB5, 0x89, 0xDD, 0xC3, 0xE1,
	0xC9, 0x4B, 0xF0, 0xFB, 0x5E, 0xE5, 0xA4, 0x05,
	0x67, 0x1B, 0x9B, 0x47, 0x25, 0x2D, 0x36, 0xE6,
	0x61, 0x9E, 0xC0, 0x7B, 0x5A, 0xE5, 0xD5, 0x74,
	0xCF, 0xE6, 0x97, 0x7C, 0x43, 0x77, 0x07, 0x18,
	0x1E, 0x91, 0xD0, 0x77, 0x17, 0xC8, 0x00, 0xB2,
	0x13, 0x85, 0x63, 0xA7, 0xF8, 0x34, 0x27, 0x71,
	0xC9, 0x8C, 0x77, 0x77, 0x2F, 0xA4, 0xEB, 0xC3,
};
