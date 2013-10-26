//
// File: vTCI.cpp 
// Description: virtual Trusted Computing Interface
//
//  Copyright (c) 2012 John Manferdelli.  All rights reserved.
//    Some contributions (c) 2012, Intel Corporation
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


//
//  TSS calls come from the presentation
//      An Introduction to programming the TPM,  TSS/Trousers basics
//      by David Challener, Johns Hopkins University Applied Physics Laboratory
//


//  TSS defines 
#include "tss/platform.h"
#include "tss/tspi.h"
#include "tss/tss_error.h"

#include "vTCI.h"
#include "jlmTypes.h"
#include "bignum.h"
#include "mpFunctions.h"
#include "algs.h"
#include "sha1.h"
#include "jlmUtility.h"
#include "hashprep.h"
#include "logging.h"

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>


struct tssError {
    int         errCode;
    const char* szMsg;
};


#define NERRORS     16
tssError  errCodes[NERRORS] = {
    TSS_SUCCESS, "success",
    TSS_E_FAIL, "E-FAIL",
    TSS_E_BAD_PARAMETER, "Bad parameter",
    TSS_E_KEY_ALREADY_REGISTERED, "KEY_ALREADY_REGISTERED",
    TSS_E_TSP_AUTHFAIL, "TPM authorization failure (1)",
    TPM_E_AUTH2FAIL,"TPM authorization failure (2)",
    TSS_E_INVALID_HANDLE, "Invalid handle",
    TSS_E_INTERNAL_ERROR, "TSS_E_INTERNAL_ERROR",
    TPM_E_BAD_DATASIZE, "TPM_E_BAD_DATASIZE",
    TSS_E_INVALID_ATTRIB_FLAG, "bad flag",
    TSS_E_INVALID_ATTRIB_SUBFLAG, "bad subflag",
    TSS_E_INVALID_ATTRIB_DATA, "bad attrib data",
    TSS_E_POLICY_NO_SECRET, "No Secret",
    TSS_E_SILENT_CONTEXT, "Silent context",
    TPM_E_INVALID_PCR_INFO,  "Invalid PCRs",
    TPM_E_INVALID_KEYUSAGE, "Invalid key usage",
};


void printErr(int code)
{
    int i;

#if 1
    for(i=0; i<NERRORS; i++) {
        if(errCodes[i].errCode==ERROR_CODE(code)) {
            fprintf(g_logFile, "%s\n", errCodes[i].szMsg);
            return;
        }
    }
    fprintf(g_logFile, "unknown error\n");
#else
    char* str= Trspi_Error_String(code);
    if(str!=NULL) 
        fprintf(g_logFile, "%s\n", str);
    else
        fprintf(g_logFile, "unknown error\n");
#endif
}


// --------------------------------------------------------------------------


tpmStatus::tpmStatus()
{
    m_hContext= 0;
    m_hTPM= 0;
    m_hTPMPolicy= 0;
    m_hSRK= 0;
    m_hSealingData= 0;
    m_hPCRs= 0;
#ifndef NOQUOTE2
    m_hPCR2= 0;
#endif
    m_hSigningKey= 0;
    m_hEk= 0;

    m_rgEKCert= NULL;
    m_rgAIKCert= NULL;
    m_fOwnerAuthSet= false;
    m_fTPMInitialized= false;
    m_fEKKeyValid= false;
    m_faikKeyValid= false;
    m_fPcr17Valid= false;
    m_fPcr18Valid= false;
    m_locality= 0;
}


tpmStatus::~tpmStatus()
{
    m_fOwnerAuthSet= false;
    m_fTPMInitialized= false;
    m_fEKKeyValid= false;
    m_faikKeyValid= false;
    m_fPcr17Valid= false;
    m_fPcr18Valid= false;
}


bool tpmStatus::initTPM()
{
    TSS_RESULT  ret;
    BYTE        wellKnownSecret[20];
    TSS_UUID    SRK_UUID= TSS_UUID_SRK;

    memset(wellKnownSecret,0,20);

    if(m_fTPMInitialized)
        return true;

    // Create Context
    ret= Tspi_Context_Create(&m_hContext);
    if(TSS_SUCCESS!=ret) {
        fprintf(g_logFile, "Context object create failed %08x\n", ret);
        printErr(ret);
        return false;
    }

    // Create to local (NULL)
    ret= Tspi_Context_Connect(m_hContext, NULL);
    if(TSS_SUCCESS!=ret) {
        fprintf(g_logFile, "Context Connect failed %08x\n", ret);
        printErr(ret);
        return false;
    }
    
    // Create TPM object
    ret= Tspi_Context_GetTpmObject(m_hContext, &m_hTPM);
    if(TSS_SUCCESS!=ret) {
        fprintf(g_logFile, "GetTpmObject failed %08x\n", ret);
        printErr(ret);
        return false;
    }
    
    // Load SRK key into TPM
    ret= Tspi_Context_LoadKeyByUUID(m_hContext, TSS_PS_TYPE_SYSTEM,
                                    SRK_UUID, &m_hSRK);
    if(TSS_SUCCESS!=ret) {
        fprintf(g_logFile, "Load SRK failed %08x\n", ret);
        printErr(ret);
        return false;
    }
#ifdef TPMTEST
    fprintf(g_logFile, "Load SRK succeeded, srk key: %08x\n", m_hSRK);
#endif

    // Policy
    ret= Tspi_GetPolicyObject(m_hSRK, TSS_POLICY_USAGE,
                                      &m_hSRKPolicy);
    if(TSS_SUCCESS!=ret) {
        fprintf(g_logFile, "GetPolicyObject failed %08x\n", ret);
        printErr(ret);
        return false;
    }
    ret= Tspi_Policy_SetSecret(m_hSRKPolicy, TSS_SECRET_MODE_SHA1, 20,
                                wellKnownSecret);
    if(TSS_SUCCESS!=ret) {
        fprintf(g_logFile, "SRK SetSecret failed %08x\n", ret);
        printErr(ret);
        return false;
    }

    // PCRs, TSS_PCRS_STRUCT_INFO_LONG
    ret= Tspi_Context_CreateObject(m_hContext, TSS_OBJECT_TYPE_PCRS, 
                                   0, &m_hPCRs);
#ifndef NOQUOTE2
    ret= Tspi_Context_CreateObject(m_hContext, TSS_OBJECT_TYPE_PCRS, 
                                   TSS_PCRS_STRUCT_INFO_SHORT, &m_hPCR2);
    if(TSS_SUCCESS!=ret) {
        fprintf(g_logFile, "Create PCR object for Quote2 failed %08x\n", ret);
        printErr(ret);
        return false;
    }
    ret= Tspi_PcrComposite_SelectPcrIndexEx(m_hPCR2,17,TSS_PCRS_DIRECTION_RELEASE);
    if(TSS_SUCCESS!=ret) {
        fprintf(g_logFile, "Tspi_PcrComposite_SelectPcrIndexEx failed for Quote2 PCR17 %08x\n", ret);
        printErr(ret);
        return false;
    }
#ifdef PCR18
    ret= Tspi_PcrComposite_SelectPcrIndexEx(m_hPCR2,18,TSS_PCRS_DIRECTION_RELEASE);
    if(TSS_SUCCESS!=ret) {
        fprintf(g_logFile, "Tspi_PcrComposite_SelectPcrIndexEx failed for Quote2 PCR18 %08x\n", ret);
        printErr(ret);
        return false;
    }
#endif
#endif

    // Read PCR register 17, store result
    unsigned    pcrLen= 0;
    BYTE*       pcrValue= NULL;

    ret= Tspi_TPM_PcrRead(m_hTPM, 17, &pcrLen, &pcrValue);
    if(TSS_SUCCESS!=ret) {
        fprintf(g_logFile, "PCR 17 read value failed %08x\n", ret);
        printErr(ret);
        return false;
    }
    if(pcrLen!=20) {
        fprintf(g_logFile, "PCR 17 wrong length %d\n", pcrLen);
        return false;
    }

    m_iPcr17Len= (int) pcrLen;
    memcpy(m_rgPcr17Value, pcrValue, pcrLen);
    m_fPcr17Valid= true;
    Tspi_Context_FreeMemory(m_hContext, pcrValue);
    pcrValue= NULL;

    // Read PCR register 18, store result
    ret= Tspi_TPM_PcrRead(m_hTPM, 18, &pcrLen, &pcrValue);
    if(TSS_SUCCESS!=ret) {
        fprintf(g_logFile, "PCR 18 read value failed %08x\n", ret);
        printErr(ret);
        return false;
    }
    if(pcrLen!=20) {
        fprintf(g_logFile, "PCR 18 wrong length %d\n", pcrLen);
        return false;
    }

    m_iPcr18Len= (int) pcrLen;
    memcpy(m_rgPcr18Value, pcrValue, pcrLen);
    m_fPcr18Valid= true;
    Tspi_Context_FreeMemory(m_hContext, pcrValue);
    pcrValue= NULL;

    ret= Tspi_PcrComposite_SetPcrValue(m_hPCRs, 17, m_iPcr17Len, m_rgPcr17Value);
    if(TSS_SUCCESS!=ret) {
        fprintf(g_logFile, "PcrComposite 17 set failed %08x\n", ret);
        printErr(ret);
        return false;
    }

#ifdef PCR18
    ret= Tspi_PcrComposite_SetPcrValue(m_hPCRs, 18, m_iPcr18Len, m_rgPcr18Value);
    if(TSS_SUCCESS!=ret) {
        fprintf(g_logFile, "PcrComposite 18 set failed %08x\n", ret);
        printErr(ret);
        return false;
    }
#endif

#ifdef TPMTEST
    fprintf(g_logFile, "\nTspi_TPM_PcrRead succeeded, len= %d\n", pcrLen); 
    PrintBytes("PCR 17: ", m_rgPcr17Value, m_iPcr17Len);
    PrintBytes("PCR 18: ", m_rgPcr18Value, m_iPcr18Len);
#endif

    // Create Sealing Encryption Object
    ret= Tspi_Context_CreateObject(m_hContext, TSS_OBJECT_TYPE_ENCDATA,
                                    TSS_ENCDATA_SEAL,  &m_hSealingData);
    if(TSS_SUCCESS!=ret) {
        fprintf(g_logFile, "Create sealing data object failed %08x\n", ret);
        printErr(ret);
        return false;
    }

    m_fTPMInitialized= true;
    return true;
}


bool tpmStatus::getCompositePCR(unsigned* pSize, u8* buf)
{
    TSS_RESULT  ret;
    unsigned    pcrLen= 0;
    BYTE*       pcrValue= NULL;

    ret= Tspi_PcrComposite_GetPcrValue(m_hPCRs, 17, &pcrLen, &pcrValue);
    if(TSS_SUCCESS!=ret)
        return false;
    if(pcrLen>*pSize) {
        Tspi_Context_FreeMemory(m_hContext, pcrValue);
        return false;
        }
    *pSize= pcrLen;
    memcpy(buf, pcrValue, pcrLen);
    Tspi_Context_FreeMemory(m_hContext, pcrValue);
    return true;
}


bool tpmStatus::setLocality(u32 in)
{
#ifndef NOQUOTE2
    TSS_RESULT      ret;

    ret= Tspi_PcrComposite_SetPcrLocality(m_hPCR2, in);
    if(TSS_SUCCESS!=ret) {
        fprintf(g_logFile, "%08x  ", ret); printErr(ret);
        return false;
    }
    m_locality= in;
    return true;
#else
    return false;
#endif
}


bool tpmStatus::getLocality(unsigned* pOut)
{
#ifndef NOQUOTE2
    TSS_RESULT      ret;

    ret= Tspi_PcrComposite_GetPcrLocality(m_hPCR2, pOut);
    if(TSS_SUCCESS!=ret) {
        fprintf(g_logFile, "%08x  ", ret); printErr(ret);
        return false;
    }
    return true;
#else
    return false;
#endif
}


bool tpmStatus::setOwnerauth(const char* ownerSecret)
{
    TSS_RESULT      ret;

    if(m_fOwnerAuthSet)
        return true;

    // TPM Policy
    ret= Tspi_Context_CreateObject(m_hContext, 
                TSS_OBJECT_TYPE_POLICY, TSS_POLICY_USAGE, &m_hTPMPolicy);
    if(TSS_SUCCESS!=ret) {
        fprintf(g_logFile, "TPM Policy object failed %08x\n", ret);
        printErr(ret);
        return false;
    }
    
    ret= Tspi_Policy_AssignToObject(m_hTPMPolicy, m_hTPM);
    if(TSS_SUCCESS!=ret) {
        fprintf(g_logFile, 
            "Tspi_Policy_AssignToObject failed %08x (Owner defined)\n", ret);
        printErr(ret);
        return false;
    }

    if(ownerSecret!=NULL) {
        ret= Tspi_Policy_SetSecret(m_hTPMPolicy, TSS_SECRET_MODE_PLAIN, 
                                   strlen(ownerSecret)+1, (BYTE*) ownerSecret);
        if(TSS_SUCCESS!=ret) {
            fprintf(g_logFile, 
                "Tspi_Policy_SetSecret failed %08x (Owner defined)\n", ret);
            printErr(ret);
            return false;
        }
    }
    else {
        BYTE wellKnownSecret[40];
        BYTE *dummyblob1; 
        UINT32 dummylen1;

        memset(wellKnownSecret,0,40);
        // Work around a bug in Trousers 0.3.1 - Force POPUP to activate
        if(Tspi_TPM_OwnerGetSRKPubKey(m_hTPM, &dummylen1, &dummyblob1)
                    ==TSS_SUCCESS) {
            Tspi_Context_FreeMemory(m_hContext, dummyblob1);
        }
        ret= Tspi_Policy_SetSecret(m_hTPMPolicy, TSS_SECRET_MODE_PLAIN, 0, NULL); 
        if(TSS_SUCCESS!=ret) {
            fprintf(g_logFile, "Tspi_Policy_SetSecret failed %08x\n", ret);
            printErr(ret);
            return false;
        }
    }

    m_fOwnerAuthSet= true;
    return true;
}


bool tpmStatus::sealData(unsigned sizetoSeal, byte* tosealData, 
                         unsigned* psizeSealed, byte* sealedData)
{
    TSS_RESULT  ret;
    BYTE*       pSealOut= NULL;
    UINT32      size= 0;

    // Sealing to PCR values
    if(sizetoSeal>1024)
       return false;

#ifdef TPMTEST
    fprintf(g_logFile, "\nsealData arguments: sealKey: %08x, srk: %08x, sizetoseal: %d\n",
            m_hSealingData, m_hSRK, sizetoSeal);
    fprintf(g_logFile, "\nsealData arguments: allocated size: %d, tpm handle: %08x\n",
            *psizeSealed, m_hTPM);
    PrintBytes("toseal\n", tosealData, sizetoSeal);
#endif

    // This seal does not do locality but does do PCRs
    ret= Tspi_Data_Seal(m_hSealingData, m_hSRK, sizetoSeal, (BYTE*) tosealData,
                        m_hPCRs);
    if(TSS_SUCCESS!=ret) {
        fprintf(g_logFile, "Data seal failed %08x\n", ret);
        printErr(ret);
        return false;
    }

    // copy sealed data
    ret= Tspi_GetAttribData(m_hSealingData, TSS_TSPATTRIB_ENCDATA_BLOB,
                    TSS_TSPATTRIB_ENCDATABLOB_BLOB, &size, &pSealOut);
    if(TSS_SUCCESS!=ret) {
        fprintf(g_logFile, "Sealed data GetAttribData failed %08x\n", ret);
        printErr(ret);
        return false;
    }
    if(*psizeSealed<size) {
        fprintf(g_logFile, "Sealed data buffer too small %d\n", size);
        return false;
    }
    *psizeSealed= size;
    memcpy(sealedData, pSealOut, size);
    Tspi_Context_FreeMemory(m_hContext, pSealOut);

    return true;
}


bool tpmStatus::unsealData(unsigned sealedSize, byte* sealedData,
                           unsigned* punsealedSize, byte* unSealed)
{
    TSS_RESULT      ret;
    BYTE*           pUnsealedOut= NULL;
    UINT32          size;

    // copy sealed data to object
    ret= Tspi_SetAttribData(m_hSealingData, TSS_TSPATTRIB_ENCDATA_BLOB,
                    TSS_TSPATTRIB_ENCDATABLOB_BLOB, sealedSize, (BYTE*)sealedData);
    if(TSS_SUCCESS!=ret) {
        fprintf(g_logFile, "Unseal data SetAttribData failed %08x\n", ret);
        printErr(ret);
        return false;
    }

    // Unseal
    ret= Tspi_Data_Unseal(m_hSealingData, m_hSRK, &size, &pUnsealedOut);
    if(TSS_SUCCESS!=ret) {
        fprintf(g_logFile, "Data unseal failed %08x\n", ret);
        printErr(ret);
        return false;
    }
    if(*punsealedSize<size) {
        fprintf(g_logFile, "Unsealed data buffer too small %d\n", size);
        return false;
    }
    *punsealedSize= size;
    memcpy(unSealed, pUnsealedOut, size);
    Tspi_Context_FreeMemory(m_hContext, pUnsealedOut);

    return true;
}


bool tpmStatus::quoteData(unsigned sizequoteData, byte* toquoteData,
                          unsigned* pquotedSize, byte* quotedData)
{
    TSS_RESULT        ret;
    TSS_VALIDATION    oValidation;
    UINT32 sizeversionInfo= 0;
    BYTE*  versionInfo= NULL;

    memset((void*)&oValidation,0,sizeof(TSS_VALIDATION));

    oValidation.ulExternalDataLength= (UINT32) sizequoteData,
    oValidation.rgbExternalData= (BYTE*)toquoteData;
    oValidation.rgbData= NULL;
    oValidation.ulDataLength= 0;

#ifdef NOQUOTE2
    ret= Tspi_TPM_Quote(m_hTPM, m_hSigningKey, m_hPCRs, &oValidation);
    if(TSS_SUCCESS!=ret) {
        fprintf(g_logFile, "Tspi_TPM_Quote failed %08x\n", ret);
        printErr(ret);
        return false;
    }
#else
    // Quote2
    ret= Tspi_TPM_Quote2(m_hTPM, m_hSigningKey, FALSE, m_hPCR2, &oValidation, 
                         &sizeversionInfo, &versionInfo);
    if(TSS_SUCCESS!=ret) {
        fprintf(g_logFile, "Tspi_TPM_Quote2 failed %08x\n", ret);
        printErr(ret);
        return false;
    }
#endif
    if(oValidation.ulValidationDataLength>*pquotedSize) {
        fprintf(g_logFile, "Quote buffer too small %d\n", oValidation.ulValidationDataLength); 
        return false;
    }
    *pquotedSize= oValidation.ulValidationDataLength;
    memcpy(quotedData, oValidation.rgbValidationData, *pquotedSize);

#ifdef TPMTEST
    UINT32  size;
    byte    pcrS[160];

#ifdef PCR18
    BYTE    pcrMask[3]= {0,0,0x6};  // pcr 17, 18
    memcpy(pcrS, m_rgPcr17Value, 20);
    PrintBytes("\nPCR17\n", m_rgPcr17Value, m_iPcr17Len);
    memcpy(&pcrS[20], m_rgPcr18Value, 20);
    PrintBytes("\nPCR17\n", m_rgPcr17Value, m_iPcr17Len);
#else
    BYTE    pcrMask[3]= {0,0,0x2};  // pcr 17
    memcpy(pcrS, m_rgPcr17Value, 20);
    PrintBytes("\nPCR17\n", m_rgPcr17Value, m_iPcr17Len);
#endif

#ifdef NOQUOTE2
    PrintBytes("TPM_QUOTE_INFO\n", (byte*)oValidation.rgbData, 
               (int)oValidation.ulDataLength);
#else
    printf("\nLocality: %d, sizeversionInfo: %d\n", m_locality, sizeversionInfo);
    PrintBytes("versionInfo: ", versionInfo, sizeversionInfo);
    PrintBytes("TPM_QUOTE_INFO2\n", (byte*)oValidation.rgbData, 
               (int)oValidation.ulDataLength);
#endif
    
    bool fR= verifyQuote(*pquotedSize, quotedData, pcrMask, pcrS, m_locality,
                        sizequoteData, toquoteData, false, sizeversionInfo, versionInfo);

    if(fR)
        fprintf(g_logFile, "verify returns true\n");
    else
        fprintf(g_logFile, "verify returns false\n");
#endif

    // free sig memory, close signing key object and context 
#ifndef NOQUOTE2
    if(versionInfo!=NULL)
        Tspi_Context_FreeMemory(m_hContext, versionInfo);
    versionInfo= NULL;
#endif
    Tspi_Context_FreeMemory(m_hContext, oValidation.rgbValidationData);

    return true;
}


bool tpmStatus::getRandom(unsigned size, byte* puData)
{
    TSS_RESULT  ret;
    BYTE*       pRandOut= NULL;

    memset(puData, 0, size);
    ret= Tspi_TPM_GetRandom(m_hTPM, size, &pRandOut);
    if(TSS_SUCCESS!=ret) {
        fprintf(g_logFile, "Tspi_TPM_GetRandom failed %08x\n", ret);
        printErr(ret);
        return false;
    }
    memcpy(puData, pRandOut, size);
    Tspi_Context_FreeMemory(m_hContext, pRandOut);
    return true;
}


bool tpmStatus::closeTPM()
{
    // Todo: Close and cleanup objects
    m_fTPMInitialized= false;
    m_fEKKeyValid= false;
    m_faikKeyValid= false;
    m_fPcr17Valid= false;
    m_fPcr18Valid= false;

    return true;
}


// --------------------------------------------------------------------------


//  Portions of code in this segment downloaded on 17 March 2012 from.
//  http://www.privacyca.com/code.html and is subject to the following license.
//  Modifications and additions subject to license at top of file.

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


// Size of endorsement key in bytes 
#define EKSIZE          (2048/8)


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


#ifdef CERTCHECK

// Check a certificate chain based on a trusted modulus from some root.
// The trusted root should sign the last extra cert; that should sign
// the previous one, and so on.
// Each cert is preceded by a 3-byte length in big-endian format
// We don't need to check the BasicConstraints field, for 2 reasons.
// First, we have to trust TPM vendor certifications anyway.
// And second, the last cert is an EK cert, and the TPM won't let EKs sign
// Return 0 if OK, -1 otherwise
static BYTE trustedRoot[];

static int
verifyCertChain (BYTE *rootMod, UINT32 rootModLen, UINT32 nCerts, BYTE *certs)
{
    X509            *tbsX509= NULL;
    EVP_PKEY        *pkey= NULL;
    RSA             *rsa;
    BYTE            *pCert;
    UINT32          certLen;
    int             rslt= -1;
    int             i, j;

    EVP_add_digest(EVP_sha1());
    pkey= EVP_PKEY_new();
    rsa= RSA_new();
    rsa->n= BN_bin2bn(rootMod, rootModLen, rsa->n);
    rsa->e= BN_new();
    BN_set_word(rsa->e, 0x10001);
    EVP_PKEY_assign_RSA(pkey, rsa);

    for(i=nCerts-1; i>=0; i--) {
        pCert= certs;
        for(j=0; j<i; j++) {
            certLen= (pCert[0]<<16)|(pCert[1]<<8)|pCert[2];
            pCert+= 3+certLen;
        }
        certLen= (pCert[0]<<16)|(pCert[1]<<8)|pCert[2];
        pCert+= 3;
        tbsX509= d2i_X509(NULL,(unsigned char const **)&pCert, certLen);
        if(!tbsX509)
            goto done;
        if(X509_verify(tbsX509, pkey)!=1)
            goto done;
        if(i>0) {
            EVP_PKEY_free(pkey);
            pkey= X509_get_pubkey(tbsX509);
            if(pkey==NULL)
                goto done;
        }
        X509_free(tbsX509);
        tbsX509= NULL;
    }
    /* Success */
    rslt= 0;
done:
    if(pkey)
        EVP_PKEY_free(pkey);
    if(tbsX509)
        X509_free(tbsX509);
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
#endif


// Create a fake endorsement key cert using system's actual EK 
TSS_RESULT makeEKCert(TSS_HCONTEXT hContext, TSS_HTPM hTPM, UINT32 *pCertLen, BYTE **pCert)
{
        TSS_RESULT      result;
        TSS_HKEY        hPubek;
        UINT32          modulusLen;
        BYTE            *modulus;

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
        *pCert = (BYTE*)malloc(*pCertLen);
        memcpy (*pCert, fakeEKCert, *pCertLen);
        memcpy (*pCert + 0xc6, modulus, modulusLen);
        Tspi_Context_FreeMemory (hContext, modulus);

        return TSS_SUCCESS;
}


bool tpmStatus::confirmAIK(const char* ownerSecret, const char* aikBlobFile, 
                           const char* challengeFile, const char* responseFile)
//
//  NOTE TESTED
//
{
    TSS_RESULT      ret;
    TSS_UUID        SRK_UUID= TSS_UUID_SRK;
    BYTE            *response;
    UINT32          responseLen;
    BYTE            *buf;
    UINT32          bufLen;
    BYTE            *asym;
    UINT32          asymLen;
    BYTE            *sym;
    UINT32          symLen;
    int             i;

    // TPM Policy
    if(ownerSecret!=NULL) {
        if(!setOwnerauth(ownerSecret))
            return false;
    }

    // Read AIK blob into buf
    if(!getAIKKey(aikBlobFile, NULL)) {
        fprintf(g_logFile, "Can't read AIK blob file\n");
        return false;
    }

    // Read challenge file into buf
    struct stat statBlock;
    if(stat(challengeFile, &statBlock)<0) {
        fprintf(g_logFile, "Can't stat input file\n");
        return false;
    }
    int bufSize= statBlock.st_size;
    buf= (BYTE*) malloc(bufSize);
    if(buf==NULL) {
        fprintf(g_logFile, "Can't allocate challenge buffer\n");
        return false;
    }
    if(!getBlobfromFile(challengeFile, buf, (int*)&bufLen)) {
        fprintf(g_logFile, "Can't read challenge file\n");
        return false;
    }

    // Parse challenge
    if(bufSize<8) {
        fprintf(g_logFile, "Challenge file format is wrong\n");
        return false;
    }
    asymLen= ntohl(*(UINT32*)buf);
    asym= buf+4;
    buf+= asymLen+4;
    if(bufLen<asymLen+8) {
        fprintf(g_logFile, "Challenge file format is wrong\n");
        return false;
    }
    symLen= ntohl(*(UINT32*)buf);
    if(bufLen!= asymLen+symLen+8) {
        fprintf(g_logFile, "Challenge file format is wrong\n");
        return false;
    }
    sym= buf+4;

    // Decrypt challenge data 
    ret= Tspi_TPM_ActivateIdentity(m_hTPM, m_hSigningKey, asymLen, asym,
                            symLen, sym, &responseLen, &response);
    if(TSS_SUCCESS!=ret) {
        fprintf(g_logFile, "Tspi_TPM_ActivateIdentity failed %08x\n", ret);
        printErr(ret);
        return false;
    }
    fprintf(g_logFile, "Tspi_TPM_ActivateIdentity succeeded\n");

    // Output response file 
    if(!saveBlobtoFile(responseFile, response, responseLen)) {
        fprintf(g_logFile, "Response file write failed\n");
        return false;
    }

    return true;
}


bool tpmStatus::makeAIK(int numCerts, byte** rgpCerts, 
                        const char* pcaFile, const char* reqFile, 
                        const char* aikBlobFile, const char* aikPKFile)
//
//  Note:  This function does not assume an inited tpmStatus object
//
{
    TSS_RESULT  ret;
    TSS_UUID    SRK_UUID= TSS_UUID_SRK;
    UINT32      initFlags= TSS_KEY_TYPE_IDENTITY|TSS_KEY_SIZE_2048|
                           TSS_KEY_VOLATILE|TSS_KEY_NOT_MIGRATABLE;
    TSS_HKEY    hPCAKey;
    TSS_HPOLICY hTPMPolicy;
    TSS_HPOLICY hSrkPolicy;

    BYTE*       rgbIdentityLabelData= NULL;
    const char*       labelString= "manferdelli.com AIK";

    UINT32      labelLen= (UINT32)strlen(labelString);
    BYTE*       rgbTCPAIdentityReq= NULL;
    UINT32      ulTCPAIdentityReqLength= 0;

    BYTE        *blob= NULL;
    UINT32      blobLen;
    UINT32      aikmodulusLen;
    BYTE*       aikmodulus= NULL;
    UINT32      pcamodulusLen;
    BYTE*       pcamodulus= NULL;

    ret= Tspi_Context_CreateObject(m_hContext, TSS_OBJECT_TYPE_RSAKEY,
                                     initFlags, &m_hSigningKey);
    if(TSS_SUCCESS!=ret) {
        fprintf(g_logFile, "Tspi_Context_CreateObject (AIK key) failed %08x\n", ret);
        printErr(ret);
        return false;
    }
    fprintf(g_logFile, "Tspi_Context_CreateObject (AIK key) succeeded\n");

    ret= Tspi_Context_CreateObject(m_hContext, TSS_OBJECT_TYPE_RSAKEY,
                     TSS_KEY_TYPE_LEGACY|TSS_KEY_SIZE_2048, &hPCAKey);
    if(TSS_SUCCESS!=ret) {
        fprintf(g_logFile, "Tspi_Context_CreateObject (PCA Key) failed %08x\n", ret);
        printErr(ret);
        return false;
    }
    fprintf(g_logFile, "Tspi_Context_CreateObject (PCAKEY) succeeded\n");

    ret= Tspi_SetAttribUint32(hPCAKey, TSS_TSPATTRIB_KEY_INFO,
            TSS_TSPATTRIB_KEYINFO_ENCSCHEME, TSS_ES_RSAESPKCSV15);
    if(TSS_SUCCESS!=ret) {
        fprintf(g_logFile, "Tspi_SetAttribUint32 failed %08x\n", ret);
        printErr(ret);
        return false;
    }
    fprintf(g_logFile, "Tspi_SetAttribUint32 succeeded\n");

#ifdef LABEL
   if (rgbIdentityLabelData == NULL) {
       fprintf(g_logFile, "Trspi_Native_To_UNICODE failed\n");
       return false;
   }
#endif

    // Get EK
    //if(!getEKInfo(NULL, true))
      //  return false;

    // fake PCAKey
    BYTE  fakePCA[2048/8];
    memset(fakePCA, 0xff, sizeof(fakePCA));
    ret= Tspi_SetAttribData(hPCAKey, TSS_TSPATTRIB_RSAKEY_INFO,
                TSS_TSPATTRIB_KEYINFO_RSA_MODULUS, sizeof(fakePCA), fakePCA);
    if(TSS_SUCCESS!=ret) {
        fprintf(g_logFile, "Tspi_SetAttribData failed fake PCA key %08x\n", ret);
        printErr(ret);
        return false;
    }
    ret= Tspi_GetAttribData(hPCAKey, TSS_TSPATTRIB_RSAKEY_INFO,
            TSS_TSPATTRIB_KEYINFO_RSA_MODULUS, &pcamodulusLen, &pcamodulus);
    if(TSS_SUCCESS!=ret) {
        fprintf(g_logFile, "Tspi_GetAttribData (PCAKEY mod) failed %08x\n", ret);
        printErr(ret);
        return false;
    }
    fprintf(g_logFile, "Tspi_GetAttribData (PCAKEY mod) succeeded\n");

    ret= Tspi_TPM_CollateIdentityRequest(m_hTPM, m_hSRK, hPCAKey, 0,
                    NULL, m_hSigningKey, TSS_ALG_AES,
                    &ulTCPAIdentityReqLength, &rgbTCPAIdentityReq);
    if(TSS_SUCCESS!=ret) {
        fprintf(g_logFile, "Tspi_TPM_CollateIdentityRequest failed %08x\n", ret);
        printErr(ret);
        return false;
    }
    fprintf(g_logFile, "Tspi_TPM_CollateIdentityRequest succeeded\n");

    ret= Tspi_Key_LoadKey(m_hSigningKey, m_hSRK);
    if(TSS_SUCCESS!=ret) {
        fprintf(g_logFile, "Tspi_Key_LoadKey failed %08x\n", ret);
        printErr(ret);
        return false;
    }
    fprintf(g_logFile, "Tspi_Key_LoadKey succeeded\n");

    // Get key blob
    ret= Tspi_GetAttribData(m_hSigningKey, TSS_TSPATTRIB_KEY_BLOB,
                TSS_TSPATTRIB_KEYBLOB_BLOB, &blobLen, &blob);
    if(TSS_SUCCESS!=ret) {
        fprintf(g_logFile, "Tspi_GetAttribData failed %08x\n", ret);
        printErr(ret);
        return false;
    }
    fprintf(g_logFile, "Tspi_GetAttribData succeeded\n");
    ret= Tspi_GetAttribData(m_hSigningKey, TSS_TSPATTRIB_RSAKEY_INFO,
            TSS_TSPATTRIB_KEYINFO_RSA_MODULUS, &aikmodulusLen, &aikmodulus);
    if(TSS_SUCCESS!=ret) {
        fprintf(g_logFile, "Tspi_GetAttribData failed getting AIK modulus %08x\n", ret);
        printErr(ret);
        return false;
    }

    // output identity request, key blob, modulus
    // Read certificates into buffer, precede each by 3 byte length
    if(!saveBlobtoFile(reqFile, rgbTCPAIdentityReq, ulTCPAIdentityReqLength)) {
        fprintf(g_logFile, "AIK request file write failed\n");
        return false;
    }
    if(!saveBlobtoFile(aikBlobFile, blob, blobLen)) {
        fprintf(g_logFile, "AIK Blob file write failed\n");
        return false;
    }
    if(!saveBlobtoFile(aikPKFile, aikmodulus, aikmodulusLen)) {
        fprintf(g_logFile, "AIK Key file write failed\n");
        return false;
    }
#ifdef TPMTEST
    PrintBytes("\naik\n", aikmodulus, aikmodulusLen);
    PrintBytes("\nTCPA req\n", rgbTCPAIdentityReq, ulTCPAIdentityReqLength);
    PrintBytes("\naik blob\n", blob, blobLen);
#endif

    Tspi_Context_FreeMemory(m_hContext, rgbTCPAIdentityReq);
    Tspi_Context_FreeMemory(m_hContext, pcamodulus);
    Tspi_Context_FreeMemory(m_hContext, aikmodulus);
    Tspi_Context_FreeMemory(m_hContext, blob);
    return true;
}


// --------------------------------------------------------------------------


bool tpmStatus::getAIKKey(const char* aikBlobFile, const char* aikCertFile)
{
    TSS_RESULT  ret;
    TSS_UUID    SRK_UUID= TSS_UUID_SRK;
    UINT32      initFlags= TSS_KEY_TYPE_IDENTITY|TSS_KEY_SIZE_2048|
                           TSS_KEY_VOLATILE|TSS_KEY_NOT_MIGRATABLE;
    u8      aikBuf[2048];
    int     aikSize= 2048;

    if(aikBlobFile==NULL) {
        fprintf(g_logFile, "No AIK Blob file\n");
        return false;
    }

    //  Key Blob in file
    if(!getBlobfromFile(aikBlobFile, aikBuf, &aikSize)) {
        fprintf(g_logFile, "Can't get AIK from file\n");
        return false;
    }

    ret= Tspi_Context_LoadKeyByBlob(m_hContext, m_hSRK, aikSize, aikBuf, &m_hSigningKey);
    if(TSS_SUCCESS!=ret) {
        fprintf(g_logFile, "AIK blob load failed %08x\n", ret);
        printErr(ret);
        return false;
    }

    UINT32  aikmodulusLength;
    BYTE*   aikmodulus;

    ret= Tspi_GetAttribData(m_hSigningKey, TSS_TSPATTRIB_RSAKEY_INFO,
            TSS_TSPATTRIB_KEYINFO_RSA_MODULUS, &aikmodulusLength, &aikmodulus);
    if(TSS_SUCCESS!=ret) {
        fprintf(g_logFile, "Tspi_GetAttribData failed getting AIK modulus %08x\n", ret);
        printErr(ret);
        return false;
    }
    m_iaikmodulusLen= (int) aikmodulusLength;
    memcpy(m_rgaikmodulus, aikmodulus, m_iaikmodulusLen);
    m_faikKeyValid= true;
#ifdef TPMTEST
    PrintBytes("AIK modulus\n", m_rgaikmodulus, m_iaikmodulusLen);
#endif
    Tspi_Context_FreeMemory(m_hContext, aikmodulus);

    if(aikCertFile!=NULL) {
        fprintf(g_logFile, "Loading AIK Cert file\n");
        m_rgAIKCert= readandstoreString(aikCertFile);
        if(m_rgAIKCert==NULL) {
            fprintf(g_logFile, "Cant read AIK key cert file\n");
            return false;
        }
    }

    return true;
}


bool tpmStatus::getEKInfo(const char* fileName, bool fgetKey)
{
    TSS_RESULT  ret;
    UINT32      ekmodulusLen; 
    BYTE*       ekmodulus;

    if(fileName!=NULL) {
        m_rgEKCert= readandstoreString(fileName);
        if(m_rgEKCert==NULL) {
            fprintf(g_logFile, "Cant read endorsement key cert file\n");
            return false;
        }
    }

    if(fgetKey) {
        // Get EK
        ret= Tspi_TPM_GetPubEndorsementKey(m_hTPM, FALSE, NULL, &m_hEk);
        if(TSS_SUCCESS!=ret) {
            fprintf(g_logFile, "Tspi_TPM_GetPubEndorsementKey failed %08x\n", ret);
            printErr(ret);
            return false;
        }
        ret= Tspi_GetAttribData(m_hEk, TSS_TSPATTRIB_RSAKEY_INFO,
                TSS_TSPATTRIB_KEYINFO_RSA_MODULUS, &ekmodulusLen, &ekmodulus);
        if(TSS_SUCCESS!=ret) {
            fprintf(g_logFile, "Tspi_GetAttribData failed getting Endorsement Key%08x\n", ret);
            printErr(ret);
            return false;
        }
        if(ekmodulusLen!=256) {
            fprintf(g_logFile, "Bad modulus size\n");
            return false;
        }
        m_iEkmodulusLen= (int) ekmodulusLen; 
        memcpy(m_rgekmodulus, ekmodulus, m_iEkmodulusLen);
        m_fEKKeyValid= true;
        Tspi_Context_FreeMemory(m_hContext, ekmodulus);
    }

    return true;
}

/*
 *
 * Signature generation
 *  EM encoded message, an octet string of length emLen
 *  Steps:
 *     1. Apply the hash function to the message M to produce a hash value
 *        H: H = Hash(M).
 *     2. Encode the algorithm ID for the hash function and the hash value
 *        into an ASN.1 value of type DigestInfo (see Appendix A.2.4)
 *     3. If emLen < tLen + 11, output "intended encoded message length too
 *      short" and stop.
 *     4. Generate an octet string PS consisting of emLen - tLen - 3 octets
 *        with hexadecimal value 0xff.  The length of PS will be at least 8
 *        octets.
 *     5. Concatenate PS, the DER encoding T, and other padding to form the
 *        encoded message EM as EM = 0x00 || 0x01 || PS || 0x00 || T.
 *     6. Output EM.
 *  
 *      SHA-1:   (0x)30 21 30 09 06 05 2b 0e 03 02 1a 05 00 04 14 || H.
 */


byte    sha1Header[]= {
    0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 
    0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14
};


bool tpmStatus::verifyQuote(int dataSize, byte* signedData,
                            byte pcrMask[3], byte* ppcrs, byte locality,
                            int externalSize, byte* pbExternal, bool addVer,
                            u32 sizeversion, byte* versionInfo)
{
    byte    pcrDigest[20];
    int     i;
    Sha1    oHash;
    byte    finalHash[20];
    byte*   quoteHash= NULL;

    extern void initBigNum();

    if(!m_faikKeyValid) {
        fprintf(g_logFile, "AIK not valid\n");
        return false;
    }

    // decrypt buffer and check PKCS header
    initBigNum();
    bnum  bnM(32);
    bnum  bnC(32);
    bnum  bnE(2);
    bnum  bnR(32);

    revmemcpy((u8*)bnM.m_pValue, m_rgaikmodulus, m_iaikmodulusLen);
    revmemcpy((u8*)bnC.m_pValue, (u8*) signedData, dataSize);
    bnE.m_pValue[0]= 0x10001ULL;

#ifdef TPMTEST
    fprintf(g_logFile, "\naikmodulus for verify\n");
    printNum(bnM); fprintf(g_logFile, "\n\n");
#endif

    if(!mpRSAENC(bnC, bnE, bnM, bnR)) {
        fprintf(g_logFile, "\nENC fails\n");
        return false;
    }

    u8  result[256];
    revmemcpy(result, (u8*)bnR.m_pValue, m_iaikmodulusLen);

#ifdef TPMTEST1
    PrintBytes("\nDecrypted\n", result, m_iaikmodulusLen);
#endif

    quoteHash= (byte*) result;
    quoteHash+= m_iaikmodulusLen-35;

    // header match?
    if(memcmp(sha1Header, quoteHash, sizeof(sha1Header))!=0) {
        fprintf(g_logFile, "verifyQuote: Bad PKCS header for quote signature\n");
        return false;
    }
    quoteHash+= sizeof(sha1Header);

#ifdef NOQUOTE2
    // reconstruct PCR composite and composite hash
    if(!computeTPM12compositepcrDigest(pcrMask, ppcrs, pcrDigest)) {
        fprintf(g_logFile, "verifyQuote: can't compute composite digest\n");
        return false;
    }
    // reconstruct TPM_QUOTE_INFO buffer
    if(!tpm12quoteHash(0, NULL, externalSize, pbExternal,
                       SHA1DIGESTBYTESIZE, pcrDigest, finalHash)) {
        fprintf(g_logFile, "verifyQuote: can't compute TPM_QUOTE_INFO hash\n");
        return false;
    }
#else
    // reconstruct PCR composite and composite hash
    if(!computeTPM12quote2compositepcrDigest(pcrMask, ppcrs, m_locality, pcrDigest)) {
        fprintf(g_logFile, "verifyQuote: can't compute composite digest\n");
        return false;
    }
    // reconstruct TPM_QUOTE_INFO buffer
    if(!tpm12quote2Hash(0, NULL, pcrMask, m_locality, externalSize, pbExternal,
                        SHA1DIGESTBYTESIZE, pcrDigest, addVer,
                        sizeversion, versionInfo, finalHash)) {
        fprintf(g_logFile, "verifyQuote: can't compute TPM_QUOTE_INFO hash\n");
        return false;
    }
#endif

#ifdef TPMTEST
    fprintf(g_logFile, "\nverifyQuote datasize: %d, keySize: %d, externalSize: %d\n",
            dataSize, m_iaikmodulusLen, externalSize);
    PrintBytes("Mask\n", pcrMask, 3);
    PrintBytes("External data\n", pbExternal, externalSize);
    PrintBytes("\nComputed TPM_QUOTE_INFO hash\n", finalHash, 20);
    PrintBytes("Quoted hash\n", quoteHash, 20);
#endif

    // compare calculated hash with quoted hash
    return (memcmp(finalHash, quoteHash, 20)==0);
}


// --------------------------------------------------------------------------


#ifdef TPMTEST

#define BUFSIZE  2048


int main(int an, char** av)
{
    tpmStatus       oTpm;
    unsigned        u, v;
    unsigned        locality;
    u8              rgtoSeal[BUFSIZE];
    u8              rgSealed[BUFSIZE];
    u8              rgunSealed[BUFSIZE];
    u8              rgtoSign[BUFSIZE];
    u8              rgSigned[BUFSIZE];
    u8              rgRandom[BUFSIZE];
    bool            fInitAIK= false;
    const char*     reqFile= "HW/requestFile";
    const char*     aikBlobFile= "HW/aikblob";
    const char*     pcaFile= "HW/pcaBlobFile";
    const char*     aikKeyFile= "HW/aikKeyFile.txt";
    char*           ownerSecret= NULL;
    const char*     aikCertFile= "HW/aikCert.xml";
    char*           ekCertFile= NULL;
    int             i;

    for(i=1;i<an;i++) {
        if(strcmp(av[i], "-initAIK")==0)
            fInitAIK= true;
        if(strcmp(av[i], "-ownerSecret")==0) {
            ownerSecret= av[++i];
        }
        if(strcmp(av[i], "-AIKBlob")==0) {
            aikBlobFile= av[++i];
        }
        if(strcmp(av[i], "-AIKCertFile")==0) {
            aikCertFile= av[++i];
        }
        if(strcmp(av[i], "-AIKeyFile")==0) {
            aikKeyFile= av[++i];
        }
        if(strcmp(av[i], "-ekCertFile")==0) {
            ekCertFile= av[++i];
        }
        if(strcmp(av[i], "-help")==0) {
                fprintf(g_logFile, "vTCI.exe -initAIK -ownerSecret secret -AIKBlob blobfile -AIKCertFile file -ekCertFile file\n");
        return 0;

        }
    }
    fprintf(g_logFile, "TPM test\n\n");
    memset(rgtoSeal, 0, BUFSIZE);
    memset(rgSealed, 0, BUFSIZE);
    memset(rgunSealed, 0, BUFSIZE);
    memset(rgtoSign, 0, BUFSIZE);
    memset(rgSigned, 0, BUFSIZE);
    memset(rgRandom, 0, BUFSIZE);

    if(!oTpm.initTPM()) {
        fprintf(g_logFile, "initTPM failed\n");
        return 1;
    }
    else {
        fprintf(g_logFile, "initTPM succeeded\n");
    }

    if(fInitAIK) {
        fprintf(g_logFile, "Initing AIK Key\n");
        if(ownerSecret && !oTpm.setOwnerauth(ownerSecret)) {
            fprintf(g_logFile, "can't set Owner auth\n");
            return false;
        }
        if(oTpm.makeAIK(0, NULL, pcaFile, reqFile, aikBlobFile, aikKeyFile)) {
            fprintf(g_logFile, "\nAIK Key successfully made\n");
        }
        else {
            fprintf(g_logFile, "\nAIK Key failed\n");
        }
        oTpm.closeTPM();
        return 0;
    }

    rgtoSeal[0]= 1;
    rgtoSeal[1]= 27;
    rgtoSeal[2]= 52;
    rgtoSign[0]= 1;
    rgtoSign[1]= 27;
    rgtoSign[2]= 52;

    // tested
    if(oTpm.getRandom(16, rgRandom)) {
        fprintf(g_logFile, "\ngetRandom succeeded\n");
        PrintBytes("Random bytes\n", rgRandom, 16);
    }
    else {
        fprintf(g_logFile, "\ngetRandom failed\n");
        return 1;
    }

    // Locality
    if(oTpm.getLocality(&locality)) {
        fprintf(g_logFile, "\ngetLocality succeeded %08x\n\n", locality);
    }
    else {
        fprintf(g_logFile, "\ngetLocality failed\n");
    }

    // tested
    v= BUFSIZE;
    if(oTpm.sealData(BUFSIZE/32, rgtoSeal, &v, rgSealed)) {
        fprintf(g_logFile, "sealData succeeded %d bytes\n", v);
        PrintBytes("Bytes to seal\n", rgtoSeal, BUFSIZE/32);
        PrintBytes("Sealed bytes\n", rgSealed, v);
    }
    else {
        fprintf(g_logFile, "\nsealData failed\n");
        return 1;
    }

time_t  start, finish;
double  elapsedseconds= 0.0;
int k;
time(&start);
for(k=0;k<50;k++) {
    // tested
    u= BUFSIZE;
    if(oTpm.unsealData(v, rgSealed, &u, rgunSealed)) {
        fprintf(g_logFile, "unsealData succeeded\n");
        PrintBytes("Bytes to unseal\n", rgSealed, v);
        PrintBytes("Unsealed bytes\n", rgunSealed, u);
    }
    else {
        fprintf(g_logFile, "\nunsealData failed\n");
        return 1;
    }
}
time(&finish);
elapsedseconds= difftime(finish, start);
fprintf(g_logFile, "\n%d unseals took %f seconds\n", k, elapsedseconds);
fprintf(g_logFile, "\n%f unseals per seconds\n", elapsedseconds/((double)k));

    // TPM Policy
    if(ownerSecret!=NULL) {
        if(!oTpm.setOwnerauth(ownerSecret))
            return false;
    }
    fprintf(g_logFile, "setOwnerauth succeeded\n");

    // ek Cert
    if(ekCertFile!=NULL) {
        if(!oTpm.getEKInfo(ekCertFile, false)) {
            fprintf(g_logFile, "getEKCert succeeded\n\n");
        }
        else {
            fprintf(g_logFile, "getEKCert failed\n\n");
        }
    }

    // AIK
    if(aikBlobFile!=NULL) {
        if(!oTpm.getAIKKey(aikBlobFile, aikCertFile)) {
            fprintf(g_logFile, "getAIKKey failed\n\n");
        }
        else
            fprintf(g_logFile, "getAIKKey succeeded\n");

        u= BUFSIZE;
        byte    nonce[20];
        memset(nonce,0,sizeof(nonce));

        if(oTpm.quoteData(sizeof(nonce), nonce, &u, rgSigned)) {
            fprintf(g_logFile, "\nquoteData succeeded\n");
            PrintBytes("\nData to quote\n", nonce, 20);
            PrintBytes("Quoted bytes\n", rgSigned, u);
        }
        else {
            fprintf(g_logFile, "\nquoteData failed\n");
        }
    }

    if(oTpm.closeTPM()) { 
        fprintf(g_logFile, "\ncloseTPM succeeded\n");
        return 1;
    }
    else {
        fprintf(g_logFile, "\ncloseTPM failed\n");
    }

    fprintf(g_logFile, "\n\nTPM test done\n");
    return 0;
}


#endif  // TEST


// --------------------------------------------------------------------------


