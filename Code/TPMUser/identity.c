/* Create an attestation identity key using privacyca.com */
/* This version uses the dummy EK cert and level 0 CA */
/* Build with REALEK defined to use built-in EK cert and level 1 CA */
/* Retrieves cert from CA automatically */
/* Assumes TPM owner secret can be read from popup, implying it is unicode */
/* Assumes SRK secret is 20 bytes of zeros */
/* Changelog: */
/* Fri Oct  3 11:59:04 PDT 2008 - Add Pragma: no-cache to POST */
/* Mon Dec  7 14:19:07 PST 2009 - Add MIT copyright notice */
/* Mon Dec  7 14:19:07 PST 2009 - Output AIK as a blob rather than in database */

/*
 * Copyright (c) 2008 Hal Finney
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

#include <openssl/rsa.h>
#include <openssl/pem.h>

#include <curl/curl.h>

#include <trousers/tss.h>
#include <trousers/trousers.h>


/* Size of endorsement key in bytes */
#define	EKSIZE		(2048/8)
/* URL of Privacy CA */
#define CAURL		"http://www.privacyca.com/"
#define CERTURL		CAURL "api/pca/level%d?ResponseFormat=PEM"
#define REQURL		CAURL "api/pca/level%d?ResponseFormat=Binary"
/* Prompt for TPM popup */
#define POPUPSTRING	"TPM owner secret"


#ifndef REALEK

/* Create a fake EK cert for talking to PCA */
/* Not a valid signature, just a holder for the Endorsement Key */

/* Forward declaration, data at end */
static BYTE fakeEKCert[0x41a];

/* Create a fake endorsement key cert using system's actual EK */
static TSS_RESULT
makeEKCert(TSS_HCONTEXT hContext, TSS_HTPM hTPM, UINT32 *pCertLen, BYTE **pCert)
{
	TSS_RESULT	result;
	TSS_HKEY	hPubek;
	UINT32		modulusLen;
	BYTE		*modulus;

	result = Tspi_TPM_GetPubEndorsementKey (hTPM, TRUE, NULL, &hPubek);
	if (result != TSS_SUCCESS)
		return result;
	result = Tspi_GetAttribData (hPubek, TSS_TSPATTRIB_RSAKEY_INFO,
		TSS_TSPATTRIB_KEYINFO_RSA_MODULUS, &modulusLen, &modulus);
	Tspi_Context_CloseObject (hContext, hPubek);
	if (result != TSS_SUCCESS)
		return result;
	if (modulusLen != 256) {
		Tspi_Context_FreeMemory (hContext, modulus);
		return TSS_E_FAIL;
	}
	*pCertLen = sizeof(fakeEKCert);
	*pCert = malloc (*pCertLen);
	memcpy (*pCert, fakeEKCert, *pCertLen);
	memcpy (*pCert + 0xc6, modulus, modulusLen);
	Tspi_Context_FreeMemory (hContext, modulus);

	return TSS_SUCCESS;
}

#endif /* undef REALEK */



/* Read the level N CA from privacyca.com */
/* Assume Curl library has been initialized */
static X509*
readPCAcert (int level)
{
	CURL		*hCurl;
	char		url[128];
	FILE		*f_tmp = tmpfile();
	X509		*x509;
	int		result;

	hCurl = curl_easy_init ();
//curl_easy_setopt (hCurl, CURLOPT_VERBOSE, 1);
	sprintf (url, CERTURL, level);
	curl_easy_setopt (hCurl, CURLOPT_URL, url);
	curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, (BYTE **)f_tmp);

	if ((result = curl_easy_perform(hCurl))) {
		printf ("Unable to connect to Privacy CA, curl library result code %d\n", result);
		fclose(f_tmp);
		return NULL;
	}

	rewind (f_tmp);
	x509 = PEM_read_X509 (f_tmp, NULL, NULL, NULL);
	fclose(f_tmp);

	return x509;
}


int
main (int argc, char **argv)
{
	TSS_HCONTEXT	hContext;
	TSS_HTPM	hTPM;
	TSS_HKEY	hSRK;
	TSS_HKEY	hPCAKey;
	TSS_HKEY	hIdentKey;
	TSS_HPOLICY	hSrkPolicy;
	TSS_HPOLICY	hTPMPolicy;
	TSS_HPOLICY	hIdentKeyPolicy;
	TSS_UUID	SRK_UUID = TSS_UUID_SRK;
	BYTE		secret[] = TSS_WELL_KNOWN_SECRET;
	X509		*x509;
	EVP_PKEY	*pcaKey;
	RSA		*rsa = NULL;
	CURL		*hCurl;
	struct curl_slist *slist=NULL;
	BYTE		n[16384/8];
	int		size_n;
	FILE		*f_out;
	FILE		*f_blob;
	FILE		*f_tmp;
	char		*aikpass = NULL;
	char		*outfilename;
	char		*outblobfilename;
	BYTE		*rgbIdentityLabelData;
	BYTE		*labelString;
	UINT32		labelLen;
	BYTE		*popupString;
	UINT32		popupLen;
	BYTE		*rgbTCPAIdentityReq;
	UINT32		ulTCPAIdentityReqLength;
	UINT32		initFlags	= TSS_KEY_TYPE_IDENTITY | TSS_KEY_SIZE_2048  |
					TSS_KEY_VOLATILE | TSS_KEY_NOT_MIGRATABLE;
	BYTE		asymBuf[EKSIZE];
	BYTE		*symBuf;
	BYTE		*credBuf;
	BYTE		*tbuf;
	UINT32		asymBufSize;
	UINT32		symBufSize;
	UINT32		credBufSize;
	BYTE		*blob;
	UINT32		blobLen;
	int		keynum;
#ifdef REALEK
	const int	level = 1;
#else
	const int	level = 0;
	BYTE		*ekCert;
	UINT32		ekCertLen;
#endif
	char		url[128];
	int		i;
	int		result;

	if (argc > 3 && 0 == strcmp(argv[1], "-p"))
	{
		aikpass = argv[2];
		for (i=1; i<argc-2; i++)
			argv[i] = argv[i+2];
		argc -= 2;
	}
	if (argc != 4)
	{
		fprintf (stderr,
			"Usage: %s [-p password] label outkeyblobfile outcertfile\n",
			argv[0]);
		exit (1);
	}

	curl_global_init (CURL_GLOBAL_ALL);

	labelString = (BYTE *) argv[1];
	labelLen = strlen((char *)labelString) + 1;

	outblobfilename = argv[2];
	if ((f_blob = fopen (outblobfilename, "wb")) == NULL) {
		printf ("Unable to open %s for output\n", outblobfilename);
		exit (1);
	}

	outfilename = argv[3];
	if ((f_out = fopen (outfilename, "wb")) == NULL) {
		printf ("Unable to open %s for output\n", outfilename);
		exit (1);
	}

	printf ("Retrieving PCA certificate...\n");

	x509 = readPCAcert (level);
	if (x509 == NULL) {
		fprintf (stderr, "Error reading PCA key\n");
		exit (1);
	}
	pcaKey = X509_get_pubkey(x509);
	rsa = EVP_PKEY_get1_RSA(pcaKey);
	if (rsa == NULL) {
		fprintf (stderr, "Error reading RSA key from PCA\n");
		exit (1);
	}
	X509_free (x509);

	result = Tspi_Context_Create(&hContext);
	if (result != TSS_SUCCESS) {
		printf ("Error 0x%x on Tspi_Context_Create\n", result);
		exit(result);
	}
	result = Tspi_Context_Connect(hContext, NULL);
	if (result != TSS_SUCCESS) {
		printf ("Error 0x%x on Tspi_Context_Connect\n", result);
		exit(result);
	}
	result = Tspi_Context_GetTpmObject (hContext, &hTPM);
	if (result != TSS_SUCCESS) {
		printf ("Error 0x%x on Tspi_Context_GetTpmObject\n", result);
		exit(result);
	}
	result = Tspi_Context_LoadKeyByUUID(hContext,
			TSS_PS_TYPE_SYSTEM, SRK_UUID, &hSRK);
        if (result != TSS_SUCCESS) {
		printf ("Error 0x%x on Tspi_Context_LoadKeyByUUID for SRK\n", result);
		exit(result);
	}
	result = Tspi_GetPolicyObject(hSRK, TSS_POLICY_USAGE, &hSrkPolicy);
	if (result != TSS_SUCCESS) {
		printf ("Error 0x%x on Tspi_GetPolicyObject for SRK\n", result);
		exit(result);
	}
	result = Tspi_Policy_SetSecret(hSrkPolicy, TSS_SECRET_MODE_SHA1, 20, secret);
	if (result != TSS_SUCCESS) {
		printf ("Error 0x%x on Tspi_Policy_SetSecret for SRK\n", result);
		exit(result);
	}
	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_POLICY,
			TSS_POLICY_USAGE, &hTPMPolicy);
	if (result != TSS_SUCCESS) {
		printf ("Error 0x%x on Tspi_CreateObject for TPM policy\n", result);
		exit(result);
	}
	result = Tspi_Policy_AssignToObject(hTPMPolicy, hTPM);
	if (result != TSS_SUCCESS) {
		printf ("Error 0x%x on Tspi_Policy_AssignToObject for TPM\n", result);
		exit(result);
	}
	popupString = (BYTE *)Trspi_Native_To_UNICODE((BYTE *)POPUPSTRING, &popupLen);
	result = Tspi_SetAttribData(hTPMPolicy, TSS_TSPATTRIB_POLICY_POPUPSTRING, 0,
		popupLen, popupString);
	if (result != TSS_SUCCESS) {
		printf ("Error 0x%x on Tspi_SetAttribData for TPM password prompt\n", result);
		exit(result);
	}
	result = Tspi_Policy_SetSecret(hTPMPolicy, TSS_SECRET_MODE_POPUP, 0, NULL);
	if (result != TSS_SUCCESS) {
		printf ("Error 0x%x on Tspi_Policy_SetSecret for TPM\n", result);
		exit(result);
	}

	if (aikpass)
		initFlags |= TSS_KEY_AUTHORIZATION;

	result = Tspi_Context_CreateObject(hContext,
					   TSS_OBJECT_TYPE_RSAKEY,
					   initFlags, &hIdentKey);
	if (result != TSS_SUCCESS) {
		printf ("Error 0x%x on Tspi_Context_CreateObject for key\n", result);
		exit(result);
	}

	if (aikpass)
	{
		result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_POLICY, TSS_POLICY_USAGE,
						&hIdentKeyPolicy);
		if (result != TSS_SUCCESS) {
			printf ("Error 0x%x on Tspi_CreateObject for AIK policy\n", result);
			exit(result);
		}
		result = Tspi_Policy_AssignToObject(hIdentKeyPolicy, hIdentKey);
		if (result != TSS_SUCCESS) {
			printf ("Error 0x%x on Tspi_Policy_AssignToObject for AIK\n", result);
			exit(result);
		}
		result = Tspi_Policy_SetSecret(hIdentKeyPolicy, TSS_SECRET_MODE_PLAIN,
						strlen(aikpass), (BYTE *)aikpass);
		if (result != TSS_SUCCESS) {
			printf ("Error 0x%x on Tspi_Policy_SetSecret for AIK\n", result);
			exit(result);
		}
	}

	result = Tspi_Context_CreateObject(hContext,
					   TSS_OBJECT_TYPE_RSAKEY,
					   TSS_KEY_TYPE_LEGACY|TSS_KEY_SIZE_2048,
					   &hPCAKey);
	if (result != TSS_SUCCESS) {
		printf ("Error 0x%x on Tspi_Context_CreateObject for PCA\n", result);
		exit(result);
	}
	if ((size_n = BN_bn2bin(rsa->n, n)) <= 0) {
		printf("BN_bn2bin failed\n");
                exit(1);
        }
	result = Tspi_SetAttribData (hPCAKey, TSS_TSPATTRIB_RSAKEY_INFO,
		TSS_TSPATTRIB_KEYINFO_RSA_MODULUS, size_n, n);
	if (result != TSS_SUCCESS) {
		printf ("Error 0x%x on Tspi_SetAttribData for PCA modulus\n", result);
		exit(result);
	}
	result = Tspi_SetAttribUint32(hPCAKey, TSS_TSPATTRIB_KEY_INFO,
				      TSS_TSPATTRIB_KEYINFO_ENCSCHEME,
				      TSS_ES_RSAESPKCSV15);
	if (result != TSS_SUCCESS) {
		printf ("Error 0x%x on Tspi_SetAttribUint32 for PCA encscheme\n", result);
		exit(result);
	}

#ifndef REALEK
	result = makeEKCert(hContext, hTPM, &ekCertLen, &ekCert);
	if (result != TSS_SUCCESS) {
		printf ("Error 0x%x on makeEKCert\n", result);
		exit(result);
	}

	result = Tspi_SetAttribData(hTPM, TSS_TSPATTRIB_TPM_CREDENTIAL,
			TSS_TPMATTRIB_EKCERT, ekCertLen, ekCert);
	if (result != TSS_SUCCESS) {
		printf ("Error 0x%x on SetAttribData for EKCert\n", result);
		exit(result);
	}
#endif

	rgbIdentityLabelData = (BYTE *)Trspi_Native_To_UNICODE(labelString, &labelLen);
	if (rgbIdentityLabelData == NULL) {
		printf("Trspi_Native_To_UNICODE failed\n");
                exit(1);
	}

	{
	/* Work around a bug in Trousers 0.3.1 - remove this block when fixed */
	/* Force POPUP to activate, it is being ignored */
		BYTE *dummyblob1; UINT32 dummylen1;
		if (Tspi_TPM_OwnerGetSRKPubKey(hTPM, &dummylen1, &dummyblob1)
				== TSS_SUCCESS) {
			Tspi_Context_FreeMemory (hContext, dummyblob1);
		}
	}

	printf ("Generating identity key...\n");
	result = Tspi_TPM_CollateIdentityRequest(hTPM, hSRK, hPCAKey, labelLen,
						 rgbIdentityLabelData,
						 hIdentKey, TSS_ALG_AES,
						 &ulTCPAIdentityReqLength,
						 &rgbTCPAIdentityReq);
	if (result != TSS_SUCCESS){
		printf ("Error 0x%x on Tspi_TPM_CollateIdentityRequest\n", result);
		exit(result);
	}

	printf ("Sending request to PrivacyCA.com...\n");

	/* Send to server */
	f_tmp = tmpfile();
	hCurl = curl_easy_init ();
//curl_easy_setopt (hCurl, CURLOPT_VERBOSE, 1);
	sprintf (url, REQURL, level);
	curl_easy_setopt (hCurl, CURLOPT_URL, url);
	curl_easy_setopt (hCurl, CURLOPT_POSTFIELDS, rgbTCPAIdentityReq);
	curl_easy_setopt (hCurl, CURLOPT_POSTFIELDSIZE, ulTCPAIdentityReqLength);
	curl_easy_setopt (hCurl, CURLOPT_WRITEDATA, (BYTE **)f_tmp);
	slist = curl_slist_append (slist, "Pragma: no-cache");
	slist = curl_slist_append (slist, "Content-Type: application/octet-stream");
	slist = curl_slist_append (slist, "Content-Transfer-Encoding: binary");
	curl_easy_setopt (hCurl, CURLOPT_HTTPHEADER, slist);
	if ((result = curl_easy_perform(hCurl))) {
		printf ("Unable to connect to Privacy CA, curl library result code %d\n", result);
		exit (result);
	}
	curl_slist_free_all(slist);

	printf ("Processing response...\n");

	fflush (f_tmp);
	symBufSize = ftell(f_tmp);
	symBuf = malloc(symBufSize);
	rewind(f_tmp);
	fread (symBuf, 1, symBufSize, f_tmp);
	fclose (f_tmp);

	asymBufSize = sizeof(asymBuf);
	if (symBufSize <= asymBufSize)
	{
		printf ("Bad response from PrivacyCA.com: %s\n", symBuf);
		exit (1);
	}

	memcpy (asymBuf, symBuf, asymBufSize);
	symBufSize -= asymBufSize;
	symBuf += asymBufSize;

	result = Tspi_Key_LoadKey (hIdentKey, hSRK);
	if (result != TSS_SUCCESS) {
		printf ("Error 0x%x on Tspi_Key_LoadKey for AIK\n", result);
		exit(result);
	}

	result = Tspi_TPM_ActivateIdentity (hTPM, hIdentKey, asymBufSize, asymBuf,
						symBufSize, symBuf,
						&credBufSize, &credBuf);
	if (result != TSS_SUCCESS) {
		printf ("Error 0x%x on Tspi_TPM_ActivateIdentity\n", result);
		exit(result);
	}

	/* Output key blob */
	result = Tspi_GetAttribData (hIdentKey, TSS_TSPATTRIB_KEY_BLOB,
		TSS_TSPATTRIB_KEYBLOB_BLOB, &blobLen, &blob);
	if (result != TSS_SUCCESS) {
		printf ("Error 0x%x on Tspi_GetAttribData for key blob\n", result);
		exit(result);
	}
	fwrite (blob, 1, blobLen, f_blob);
	fclose (f_blob);
	Tspi_Context_FreeMemory (hContext, blob);

	/* Output credential in PEM format */
	tbuf = credBuf;
	x509 = d2i_X509(NULL, (const BYTE **)&tbuf, credBufSize);
	if (x509 == NULL) {
		printf ("Unable to parse returned credential\n");
		exit(1);
	}
	if (tbuf-credBuf != credBufSize) {
		printf ("Note, not all data from privacy ca was parsed correctly\n");
	}

        PEM_write_X509 (f_out, x509);
	fclose (f_out);
	X509_free (x509);

	printf ("Success!\n");
	return 0;
}


#ifndef REALEK

static BYTE fakeEKCert[0x41a] = {
/* 00000000 */ 0x30, 0x82, 0x04, 0x16, 0x30, 0x82, 0x02, 0xfe,
		0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x10, 0x40, /* |0...0..........@| */
/* 00000010 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, /* |...............0| */
/* 00000020 */ 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
		0x0d, 0x01, 0x01, 0x05, 0x05, 0x00, 0x30, 0x3e, /* |...*.H........0>| */
/* 00000030 */ 0x31, 0x3c, 0x30, 0x3a, 0x06, 0x03, 0x55, 0x04,
		0x03, 0x13, 0x33, 0x49, 0x6e, 0x73, 0x65, 0x63, /* |1<0:..U...3Insec| */
/* 00000040 */ 0x75, 0x72, 0x65, 0x20, 0x44, 0x65, 0x6d, 0x6f,
		0x2f, 0x54, 0x65, 0x73, 0x74, 0x20, 0x45, 0x6e, /* |ure Demo/Test En| */
/* 00000050 */ 0x64, 0x6f, 0x72, 0x73, 0x65, 0x6d, 0x65, 0x6e,
		0x74, 0x20, 0x4b, 0x65, 0x79, 0x20, 0x52, 0x6f, /* |dorsement Key Ro| */
/* 00000060 */ 0x6f, 0x74, 0x20, 0x43, 0x65, 0x72, 0x74, 0x69,
		0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x30, 0x1e, /* |ot Certificate0.| */
/* 00000070 */ 0x17, 0x0d, 0x30, 0x31, 0x30, 0x31, 0x30, 0x31,
		0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x17, /* |..010101000000Z.| */
/* 00000080 */ 0x0d, 0x34, 0x39, 0x31, 0x32, 0x33, 0x31, 0x32,
		0x33, 0x35, 0x39, 0x35, 0x39, 0x5a, 0x30, 0x00, /* |.491231235959Z0.| */
/* 00000090 */ 0x30, 0x82, 0x01, 0x37, 0x30, 0x22, 0x06, 0x09,
		0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, /* |0..70"..*.H.....| */
/* 000000a0 */ 0x07, 0x30, 0x15, 0xa2, 0x13, 0x30, 0x11, 0x06,
		0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, /* |.0...0...*.H....| */
/* 000000b0 */ 0x01, 0x09, 0x04, 0x04, 0x54, 0x43, 0x50, 0x41,
		0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, /* |....TCPA.....0..| */
/* 000000c0 */ 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0x80, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* |................| */
/* 000000d0 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* |................| */
/* 000000e0 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* |................| */
/* 000000f0 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* |................| */
/* 00000100 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* |................| */
/* 00000110 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* |................| */
/* 00000120 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* |................| */
/* 00000130 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* |................| */
/* 00000140 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* |................| */
/* 00000150 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* |................| */
/* 00000160 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* |................| */
/* 00000170 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* |................| */
/* 00000180 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* |................| */
/* 00000190 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* |................| */
/* 000001a0 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* |................| */
/* 000001b0 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* |................| */
/* 000001c0 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03,
		0x01, 0x00, 0x01, 0xa3, 0x82, 0x01, 0x37, 0x30, /* |..............70| */
/* 000001d0 */ 0x82, 0x01, 0x33, 0x30, 0x37, 0x06, 0x03, 0x55,
		0x1d, 0x09, 0x04, 0x30, 0x30, 0x2e, 0x30, 0x16, /* |..307..U...00.0.| */
/* 000001e0 */ 0x06, 0x05, 0x67, 0x81, 0x05, 0x02, 0x10, 0x31,
		0x0d, 0x30, 0x0b, 0x0c, 0x03, 0x31, 0x2e, 0x31, /* |..g....1.0...1.1| */
/* 000001f0 */ 0x02, 0x01, 0x02, 0x02, 0x01, 0x01, 0x30, 0x14,
		0x06, 0x05, 0x67, 0x81, 0x05, 0x02, 0x12, 0x31, /* |......0...g....1| */
/* 00000200 */ 0x0b, 0x30, 0x09, 0x80, 0x01, 0x00, 0x81, 0x01,
		0x00, 0x82, 0x01, 0x02, 0x30, 0x50, 0x06, 0x03, /* |.0..........0P..| */
/* 00000210 */ 0x55, 0x1d, 0x11, 0x01, 0x01, 0xff, 0x04, 0x46,
		0x30, 0x44, 0xa4, 0x42, 0x30, 0x40, 0x31, 0x16, /* |U......F0D.B0@1.| */
/* 00000220 */ 0x30, 0x14, 0x06, 0x05, 0x67, 0x81, 0x05, 0x02,
		0x01, 0x0c, 0x0b, 0x69, 0x64, 0x3a, 0x30, 0x30, /* |0...g......id:00| */
/* 00000230 */ 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x31, 0x12,
		0x30, 0x10, 0x06, 0x05, 0x67, 0x81, 0x05, 0x02, /* |0000001.0...g...| */
/* 00000240 */ 0x02, 0x0c, 0x07, 0x55, 0x6e, 0x6b, 0x6e, 0x6f,
		0x77, 0x6e, 0x31, 0x12, 0x30, 0x10, 0x06, 0x05, /* |...Unknown1.0...| */
/* 00000250 */ 0x67, 0x81, 0x05, 0x02, 0x03, 0x0c, 0x07, 0x69,
		0x64, 0x3a, 0x30, 0x30, 0x30, 0x30, 0x30, 0x0c, /* |g......id:00000.| */
/* 00000260 */ 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff,
		0x04, 0x02, 0x30, 0x00, 0x30, 0x75, 0x06, 0x03, /* |..U.......0.0u..| */
/* 00000270 */ 0x55, 0x1d, 0x20, 0x01, 0x01, 0xff, 0x04, 0x6b,
		0x30, 0x69, 0x30, 0x67, 0x06, 0x04, 0x55, 0x1d, /* |U. ....k0i0g..U.| */
/* 00000280 */ 0x20, 0x00, 0x30, 0x5f, 0x30, 0x25, 0x06, 0x08,
		0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x02, 0x01, /* | .0_0%..+.......| */
/* 00000290 */ 0x16, 0x19, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f,
		0x2f, 0x77, 0x77, 0x77, 0x2e, 0x70, 0x72, 0x69, /* |..http://www.pri| */
/* 000002a0 */ 0x76, 0x61, 0x63, 0x79, 0x63, 0x61, 0x2e, 0x63,
		0x6f, 0x6d, 0x2f, 0x30, 0x36, 0x06, 0x08, 0x2b, /* |vacyca.com/06..+| */
/* 000002b0 */ 0x06, 0x01, 0x05, 0x05, 0x07, 0x02, 0x02, 0x30,
		0x2a, 0x0c, 0x28, 0x54, 0x43, 0x50, 0x41, 0x20, /* |.......0*.(TCPA | */
/* 000002c0 */ 0x54, 0x72, 0x75, 0x73, 0x74, 0x65, 0x64, 0x20,
		0x50, 0x6c, 0x61, 0x74, 0x66, 0x6f, 0x72, 0x6d, /* |Trusted Platform| */
/* 000002d0 */ 0x20, 0x4d, 0x6f, 0x64, 0x75, 0x6c, 0x65, 0x20,
		0x45, 0x6e, 0x64, 0x6f, 0x72, 0x73, 0x65, 0x6d, /* | Module Endorsem| */
/* 000002e0 */ 0x65, 0x6e, 0x74, 0x30, 0x21, 0x06, 0x03, 0x55,
		0x1d, 0x23, 0x04, 0x1a, 0x30, 0x18, 0x80, 0x16, /* |ent0!..U.#..0...| */
/* 000002f0 */ 0x04, 0x14, 0x34, 0xa8, 0x8c, 0x24, 0x7a, 0x97,
		0xf8, 0xcc, 0xc7, 0x56, 0x6d, 0xfb, 0x44, 0xa8, /* |..4..$z....Vm.D.| */
/* 00000300 */ 0xd4, 0x41, 0xaa, 0x5f, 0x4f, 0x1d, 0x30, 0x0d,
		0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, /* |.A._O.0...*.H...| */
/* 00000310 */ 0x01, 0x01, 0x05, 0x05, 0x00, 0x03, 0x82, 0x01,
		0x01, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, /* |................| */
/* 00000320 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* |................| */
/* 00000330 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* |................| */
/* 00000340 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* |................| */
/* 00000350 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* |................| */
/* 00000360 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* |................| */
/* 00000370 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* |................| */
/* 00000380 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* |................| */
/* 00000390 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* |................| */
/* 000003a0 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* |................| */
/* 000003b0 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* |................| */
/* 000003c0 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* |................| */
/* 000003d0 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* |................| */
/* 000003e0 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* |................| */
/* 000003f0 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* |................| */
/* 00000400 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* |................| */
/* 00000410 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x01                                      /* |..........|       */
};

#endif /* undef REALEK */
