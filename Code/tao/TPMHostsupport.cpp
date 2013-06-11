//  File: TPMHostsupport.cpp
//      John Manferdelli
//  Description:  TPM interface for trusted services
//
//  Copyright (c) 2012, John Manferdelli
//  Some contributions copyright (c) 2012, Intel Corporation
//
// Use, duplication and disclosure of this file and derived works of
// this file are subject to and licensed under the Apache License dated
// January, 2004, (the "License").  This License is contained in the
// top level directory originally provided with the CloudProxy Project.
// Your right to use or distribute this file, or derived works thereof,
// is subject to your being bound by those terms and your use indicates
// consent to those terms.
//
// If you distribute this file (or portions derived therefrom), you must
// include License in or with the file and, in the event you do not include
// the entire License in the file, the file must contain a reference
// to the location of the License.


// -------------------------------------------------------------------------


#ifdef TPMSUPPORT


#include "jlmTypes.h"
#include "logging.h"
#include "jlmcrypto.h"
#include "jlmUtility.h"
#include "modesandpadding.h"
#include "sha256.h"
#include "tao.h"
#include "bignum.h"
#include "mpFunctions.h"
#ifdef NEWANDREORGANIZED
#include "cryptoHelper.h"
#else
#include "rsaHelper.h"
#endif
#include "trustedKeyNego.h"
#include "hashprep.h"
#include "vTCIDirect.h"
#include "tcIO.h"

#include <string.h>
#include <time.h>


// -------------------------------------------------------------------------


//
//   Service support with TPM 
//

tpmStatus   g_oTpm;


bool initTPM(const char* aikblobfile, const char* szTPMPassword)
{
#ifdef TEST1
    if(szTPMPassword!=NULL)
        fprintf(g_logFile, "initTPM(%s,%s)\n", aikblobfile, szTPMPassword);
    else
        fprintf(g_logFile, "initTPM(%s, NULL)\n", aikblobfile);
        fflush(g_logFile);
#endif

    if(aikblobfile==NULL)
        return false;

    if(!g_oTpm.initTPM()) {
         if(szTPMPassword==NULL || !g_oTpm.setTPMauth(szTPMPassword))
            return false;
    }
#ifdef TEST1
        fprintf(g_logFile, "g_oTpm.initTPM succeeded\n");
        fflush(g_logFile);
#endif

    // AIK
    if(!g_oTpm.getAIKKey(aikblobfile, NULL)) {
        fprintf(g_logFile, "getAIKKey failed\n");
	return false;
    }

#ifdef TEST1
    fprintf(g_logFile, "getAIKKey succeeded\n");
    fflush(g_logFile);
#endif
    return true;
}


bool deinitTPM()
{
    return g_oTpm.closeTPM();
}


bool getAttestCertificateTPM(int size, byte* pKey)
{
    return false;
}


bool getEntropyTPM(int size, byte* pKey)
{
    return false;
}


bool getMeasurementTPM(int* pSize, byte* pHash)
// return TPM1.2 composite hash
{
    u32     size= SHA1DIGESTBYTESIZE*24; 
    byte    pcrs[SHA1DIGESTBYTESIZE*24];

    if(!g_oTpm.getCompositePCR(g_oTpm.m_locality, g_oTpm.m_rgpcrMask, &size, pcrs)) {
        fprintf(g_logFile, "getMeasurementTPM: getCompositePCR failed\n");
        return false;
    }

#ifndef QUOTE2_DEFINED
    // reconstruct PCR composite and composite hash
    if(!computeTPM12compositepcrDigest(g_oTpm.m_rgpcrMask, pcrs, pHash)) {
        fprintf(g_logFile, "getMeasurementTPM: can't compute composite digest\n");
        return false;
    }
#else
    // reconstruct PCR composite and composite hash
    if(!computeTPM12quote2compositepcrDigest(g_oTpm.m_rgpcrMask, pcrs, 
		    g_oTpm.m_locality, pHash)) {
        fprintf(g_logFile, "getMeasurementTPM: can't compute composite digest\n");
        return false;
    }
#endif

    *pSize= SHA1DIGESTBYTESIZE;
    return true;
}


bool sealwithTPM(int inSize, byte* inData, int* poutSize, byte* outData)
{
#ifdef TEST
    fprintf(g_logFile, "sealwithTPM\n");
#endif
    return g_oTpm.sealData(inSize, inData, (unsigned*) poutSize, outData);
}


bool unsealwithTPM(int inSize, byte* inData, int* poutSize, byte* outData)
{
    return g_oTpm.unsealData(inSize, inData, (unsigned*) poutSize, outData);
}


bool quotewithTPM(int inSize, byte* inData, int* poutSize, byte* outData)
{
    byte    newout[1024];
    bool    fRet= g_oTpm.quoteData(inSize, inData, (unsigned*) poutSize, newout);

    if(fRet) {
        revmemcpy(outData, newout, *poutSize);
        return true;
    }
    else {
        fprintf(g_logFile, "quotewithTPM failed\n");
        fflush(g_logFile);
    }
    return false;
}


// -------------------------------------------------------------------------


#endif


// -------------------------------------------------------------------------


