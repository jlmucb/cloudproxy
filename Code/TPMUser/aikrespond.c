/*
 * aikrespond.c
 *
 * Third step in proving an AIK is valid without using a Privacy CA.
 *
 * Reads AIK blob file and challenge file from challenger. Decrypts
 * encrypted data and outputs to a file, which should be sent back to
 * challenger. Successful decryption proves that it is a real AIK.
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

/* Uncomment this if you don't want to use POPUP to get owner secret */
//#define OWNER_SECRET	"mysecret"

#define CKERR	if (result != TSS_SUCCESS) goto error

int
main (int ac, char **av)
{
	TSS_HCONTEXT	hContext;
	TSS_HTPM	hTPM;
	TSS_HKEY	hSRK;
	TSS_HKEY	hAIK;
	TSS_HPOLICY	hTPMPolicy;
	TSS_HPOLICY	hSrkPolicy;
	TSS_HPOLICY	hAIKPolicy;
	TSS_UUID	SRK_UUID = TSS_UUID_SRK;
	BYTE		srkSecret[] = TSS_WELL_KNOWN_SECRET;
	FILE		*f_in;
	FILE		*f_out;
	char		*pass = NULL;
	BYTE		*response;
	UINT32		responseLen;
	BYTE		*buf;
	UINT32		bufLen;
	BYTE		*asym;
	UINT32		asymLen;
	BYTE		*sym;
	UINT32		symLen;
	int		i;
	int		result;

	if ((ac<2) || ((0==strcmp(av[1],"-p")) ? (ac!=6) : (ac!=4))) {
		fprintf (stderr, "Usage: %s [-p password] aikblobfile challengefile outresponsefile\n", av[0]);
		exit (1);
	}

	if (0 == strcmp(av[1], "-p")) {
		pass = av[2];
		for (i=3; i<ac; i++)
			av[i-2] = av[i];
		ac -= 2;
	}

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

	/* Read AIK blob */
	if ((f_in = fopen(av[1], "rb")) == NULL) {
		fprintf (stderr, "Unable to open file %s\n", av[1]);
		exit (1);
	}
	fseek (f_in, 0, SEEK_END);
	bufLen = ftell (f_in);
	fseek (f_in, 0, SEEK_SET);
	buf = malloc (bufLen);
	if (fread(buf, 1, bufLen, f_in) != bufLen) {
		fprintf (stderr, "Unable to readn file %s\n", av[1]);
		exit (1);
	}
	fclose (f_in);

	result = Tspi_Context_LoadKeyByBlob (hContext, hSRK, bufLen, buf, &hAIK); CKERR;
	free (buf);

	if (pass) {
		result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_POLICY,
				TSS_POLICY_USAGE, &hAIKPolicy); CKERR;
		result = Tspi_Policy_AssignToObject(hAIKPolicy, hAIK);
		result = Tspi_Policy_SetSecret (hAIKPolicy, TSS_SECRET_MODE_PLAIN,
				strlen(pass)+1, pass); CKERR;
	}

	/* Read challenge file */
	if ((f_in = fopen(av[2], "rb")) == NULL) {
		fprintf (stderr, "Unable to open file %s\n", av[2]);
		exit (1);
	}
	fseek (f_in, 0, SEEK_END);
	bufLen = ftell (f_in);
	fseek (f_in, 0, SEEK_SET);
	buf = malloc (bufLen);
	if (fread(buf, 1, bufLen, f_in) != bufLen) {
		fprintf (stderr, "Unable to readn file %s\n", av[2]);
		exit (1);
	}
	fclose (f_in);

	/* Parse challenge */
	if (bufLen < 8)
		goto badchal;
	asymLen = ntohl(*(UINT32*)buf);
	asym = buf + 4;
	buf += asymLen + 4;
	if (bufLen < asymLen+8)
		goto badchal;
	symLen = ntohl(*(UINT32*)buf);
	if (bufLen != asymLen + symLen + 8)
		goto badchal;
	sym = buf + 4;

	/* Decrypt challenge data */
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
	result = Tspi_TPM_ActivateIdentity (hTPM, hAIK, asymLen, asym,
						symLen, sym,
						&responseLen, &response); CKERR;

	/* Output response file */
	
	if ((f_out = fopen (av[3], "wb")) == NULL) {
		fprintf (stderr, "Unable to create file %s\n", av[3]);
		exit (1);
	}
	if (fwrite (response, 1, responseLen, f_out) != responseLen) {
		fprintf (stderr, "Unable to write to file %s\n", av[3]);
		exit (1);
	}
	fclose (f_out);

	printf ("Success!\n");
	return 0;

error:
	fprintf (stderr, "Failure, error code: 0x%x\n", result);
	return 1;

badchal:
	fprintf (stderr, "Challenge file format is wrong\n");
	return 1;
}
