/*
 * aikpublish.c
 *
 * Publish a data file containing AIK public key, EK certificate
 * and supporting certificates.
 *
 * Format of output file is 4 bytes of AIK public key blob length,
 * big-endian, followed by AIK public key blob;
 * 4 bytes of certs-length, big-endian, meaning the length of all
 * of the following certificates in the file, followed by the
 * certificates.
 * Each certificate is preceded by its 3-byte length.
 * Certs should be in order from EK cert, to cert signing the EK
 * cert, to cert signing that one, and so on.
 * Last cert should be signed by the VeriSign Trusted Platform Module
 * Root CA. (The self-signed Verisign certificate should not be
 * included.)
 * Note that this certificate format and ordering is analogous to that
 * used for SSL/TLS.
 *
 * Also outputs a second file containing the TPM_KEY blob for the
 * newly generated AIK.
 */

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
#include <trousers/tss.h>
#include <openssl/x509.h>

/* Uncomment this if you don't want to use POPUP to get owner secret */
#define OWNER_SECRET	"UCBMath73"

#define CKERR	if (result != TSS_SUCCESS) goto error

/* VeriSign Trusted Platform Module Root CA modulus */
/* (defined at end of file) */
static BYTE trustedRoot[256];

static int verifyCertChain (BYTE *rootMod, UINT32 rootModLen, UINT32 nCerts, BYTE *certs);

int
main (int ac, char **av)
{
	TSS_HCONTEXT	hContext;
	TSS_HTPM	hTPM;
	TSS_HKEY	hSRK;
	TSS_HKEY	hAIK;
	TSS_HKEY	hPCA;
	TSS_HPOLICY	hTPMPolicy;
	TSS_HPOLICY	hSrkPolicy;
	TSS_HPOLICY	hAIKPolicy;
	TSS_UUID	SRK_UUID = TSS_UUID_SRK;
	BYTE		srkSecret[] = TSS_WELL_KNOWN_SECRET;
	BYTE		n[2048/8];
	FILE		*f_in;
	FILE		*f_out;
	char		*pass = NULL;
	UINT32		initFlags;
	BYTE		*blob;
	UINT32		blobLen;
	BYTE		*certBuf;
	UINT32		certBufLen;
	UINT32		certLen;
	UINT32		tt[1];
	int		nCerts;
	int		i;
	int		result;

	if ((ac<2) || ((0==strcmp(av[1],"-p")) ? (ac<6) : (ac<4))) {
		fprintf (stderr, "Usage: %s [-p password] ekcertfile [certfiles ...] outpubfile outaikblobfile\n", av[0]);
		exit (1);
	}

	if (0 == strcmp(av[1], "-p")) {
		pass = av[2];
		for (i=3; i<ac; i++)
			av[i-2] = av[i];
		ac -= 2;
	}

#ifdef JLM1
	/* Read certificates into buffer, precede each by 3 byte length */
	nCerts = ac - 3;
	certBufLen = 0;
	certBuf = malloc (1);
	for (i=0; i<nCerts; i++) {
		if ((f_in = fopen (av[i+1], "rb")) == NULL) {
			fprintf (stderr, "Unable to open file %s for input\n", av[i+1]);
			exit (1);
		}
		fseek (f_in, 0, SEEK_END);
		certLen = ftell (f_in);
		fseek (f_in, 0, SEEK_SET);
		certBuf = realloc (certBuf, certBufLen + 3 + certLen);
		certBuf[certBufLen] = certLen >> 16;
		certBuf[certBufLen+1] = certLen >> 8;
		certBuf[certBufLen+2] = certLen;
		if (fread (certBuf+certBufLen+3, 1, certLen, f_in) != certLen) {
			fprintf (stderr, "Failed to read file %s\n", av[i+1]);
			exit (1);
		}
		if (certBuf[certBufLen+3] != 0x30) {
			fprintf (stderr, "Certificate file %s not in binary format\n", av[i+1]);
			exit (1);
		}
		fclose (f_in);
		certBufLen += 3 + certLen;
	}

	if (verifyCertChain (trustedRoot, sizeof(trustedRoot), nCerts, certBuf) < 0) {
		fprintf (stderr, "Certificate chain is incorrect\n");
		exit (1);
	}
#else
	certBuf= NULL;
	certBufLen= 0;
#endif

	result = Tspi_Context_Create(&hContext); CKERR;
	result = Tspi_Context_Connect(hContext, NULL); CKERR;
	result = Tspi_Context_LoadKeyByUUID(hContext,
			TSS_PS_TYPE_SYSTEM, SRK_UUID, &hSRK); CKERR;
	result = Tspi_GetPolicyObject (hSRK, TSS_POLICY_USAGE, &hSrkPolicy); CKERR;
	result = Tspi_Policy_SetSecret(hSrkPolicy, TSS_SECRET_MODE_SHA1,
			sizeof(srkSecret), srkSecret); CKERR;
	result = Tspi_Context_GetTpmObject (hContext, &hTPM); CKERR;
	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_POLICY,
			TSS_POLICY_USAGE, &hTPMPolicy); CKERR;
	result = Tspi_Policy_AssignToObject(hTPMPolicy, hTPM);
#ifdef OWNER_SECRET
	result = Tspi_Policy_SetSecret (hTPMPolicy, TSS_SECRET_MODE_PLAIN,
			strlen(OWNER_SECRET)+1, OWNER_SECRET); CKERR;
#else
	result = Tspi_Policy_SetSecret (hTPMPolicy, TSS_SECRET_MODE_POPUP, 0, NULL); CKERR;
#endif

	/* Create dummy PCA key */
	result = Tspi_Context_CreateObject(hContext,
					   TSS_OBJECT_TYPE_RSAKEY,
					   TSS_KEY_TYPE_LEGACY|TSS_KEY_SIZE_2048,
					   &hPCA); CKERR;
	memset (n, 0xff, sizeof(n));
	result = Tspi_SetAttribData (hPCA, TSS_TSPATTRIB_RSAKEY_INFO,
		TSS_TSPATTRIB_KEYINFO_RSA_MODULUS, sizeof(n), n); CKERR;

	/* Create AIK object */
	initFlags = TSS_KEY_TYPE_IDENTITY | TSS_KEY_SIZE_2048;
	if (pass)
		initFlags |= TSS_KEY_AUTHORIZATION;
	result = Tspi_Context_CreateObject(hContext,
					   TSS_OBJECT_TYPE_RSAKEY,
					   initFlags, &hAIK); CKERR;
	if (pass) {
		result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_POLICY,
				TSS_POLICY_USAGE, &hAIKPolicy); CKERR;
		result = Tspi_Policy_AssignToObject(hAIKPolicy, hAIK);
		result = Tspi_Policy_SetSecret (hAIKPolicy, TSS_SECRET_MODE_PLAIN,
				strlen(pass)+1, pass); CKERR;
	}

	/* Generate new AIK */
#ifndef OWNER_SECRET
	{
	/* Work around a bug in Trousers 0.3.1 - remove this block when fixed */
	/* Force POPUP to activate, it is being ignored */
		BYTE *dummyblob1; UINT32 dummylen1;
		if (Tspi_TPM_OwnerGetSRKPubKey(hTPM, &dummylen1, &dummyblob1)
				== TSS_SUCCESS) {
			Tspi_Context_FreeMemory (hContext, dummyblob1);
		}
	}
#endif

	result = Tspi_TPM_CollateIdentityRequest(hTPM, hSRK, hPCA, 0, "",
						 hAIK, TSS_ALG_AES,
						 &blobLen,
						 &blob); CKERR;
	Tspi_Context_FreeMemory (hContext, blob);

	/* Output file with AIK pub key and certs, preceded by 4-byte lengths */
	result = Tspi_GetAttribData (hAIK, TSS_TSPATTRIB_KEY_BLOB,
		TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY, &blobLen, &blob); CKERR;
	
	if ((f_out = fopen (av[ac-2], "wb")) == NULL) {
		fprintf (stderr, "Unable to open %s for output\n", av[ac-2]);
		exit (1);
	}
	tt[0] = htonl (blobLen);
	fwrite (tt, 1, sizeof(UINT32), f_out);
	fwrite (blob, 1, blobLen, f_out);
	Tspi_Context_FreeMemory (hContext, blob);

	tt[0] = htonl (certBufLen);
	fwrite (tt, 1, sizeof(UINT32), f_out);
	if (fwrite (certBuf, 1, certBufLen, f_out) != certBufLen) {
		fprintf (stderr, "Unable to write to %s\n", av[ac-2]);
		exit (1);
	}
	free (certBuf);
	fclose (f_out);

	/* Output file with AIK blob for future use */
	result = Tspi_GetAttribData (hAIK, TSS_TSPATTRIB_KEY_BLOB,
		TSS_TSPATTRIB_KEYBLOB_BLOB, &blobLen, &blob); CKERR;
	
	if ((f_out = fopen (av[ac-1], "wb")) == NULL) {
		fprintf (stderr, "Unable to open %s for output\n", av[ac-1]);
		exit (1);
	}
	if (fwrite (blob, 1, blobLen, f_out) != blobLen) {
		fprintf (stderr, "Unable to write to %s\n", av[ac-1]);
		exit (1);
	}
	fclose (f_out);
	Tspi_Context_FreeMemory (hContext, blob);

	printf ("Success!\n");
	return 0;

error:
	printf ("Failure, error code: 0x%x\n", result);
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
