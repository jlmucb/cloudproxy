//
//  File: hashprep.cpp - hash prep for TPM
//
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

// --------------------------------------------------------------------------


#include "jlmTypes.h"
#include "logging.h"
#include "sha1.h"
#include "sha256.h"
#include "algs.h"
#include "hashprep.h"
#include "jlmUtility.h"

#include <stdio.h>
#include <string.h>


byte    g_pcr17Mask[3]= {0,0,0x02};
byte    g_pcr1718Mask[3]= {0,0,0x06};


// --------------------------------------------------------------------------


bool computeTPM12compositepcrDigest(byte pcrMask[3], byte* pcrs, byte* pcrDigest)
{
    byte                        cb= 0;
    int                         i;
    int                         sizeOfComposite;
    u32                         sizePCRs;
    int                         numPCRs= 0;
    Sha1                        oHash;
    byte                        composite[9+24*SHA1DIGESTBYTESIZE];
    struct TPM12COMPOSITEPCR*   pPro= (struct TPM12COMPOSITEPCR*)composite;

    // PCR's used
    for(i=0; i<24;i++) {
        if((i%8)==0)
            cb= pcrMask[i/8];
        if((cb&0x01)!=0) {
            numPCRs++;
        }
        cb>>= 1;
    }

    // Composite buffer in big Endian
    // TPM12COMPOSITEPCR doesn't pack so we do it this way
    memset(composite, 0, sizeof(composite));
    sizeOfComposite= 9+numPCRs*SHA1DIGESTBYTESIZE;
    pPro->m_sizeMap= 0x0300;
    memcpy(pPro->m_rgpcrMap, pcrMask, 3);
    sizePCRs=numPCRs*SHA1DIGESTBYTESIZE;
    revmemcpy(&composite[5], (byte*)&sizePCRs, sizeof(u32));
    memcpy(&composite[9], pcrs, SHA1DIGESTBYTESIZE*numPCRs);

    // Hash composite buffer
    oHash.Init();
    oHash.Update(composite, sizeOfComposite);
    oHash.Final();
    oHash.getDigest(pcrDigest);

#ifdef TEST
    PrintBytes("computeTPM12compositepcrDigest Mask\n", pcrMask, 3);
    PrintBytes("Input pcrs\n", pcrs, 20*numPCRs);
    PrintBytes("\nComposite buffer\n", composite, sizeOfComposite);
    PrintBytes("Composite buffer hash\n", pcrDigest, 20);
#endif
    return true;
}


bool tpm12quoteHash(int sizenonce, byte* nonce, 
                    int sizetobeSignedHash, byte* tobesignedHash,
                    int sizepcrDigest, byte* pcrDigest, byte* outputHash)
{
    Sha1                        oHash;
    struct TPM12QUOTEINFO       oTpmInfo;

    // initialize TPM12QUOTEINFO structure
    if(sizetobeSignedHash!=SHA1DIGESTBYTESIZE) {
        fprintf(g_logFile, "tpm12quoteHash: to be signed data should be sha-1 hash\n");
        return false;
    }
    u32* pU= (u32*) &oTpmInfo.m_version; 
    *pU= 0x00000101;                // version
    oTpmInfo.m_rgFixed[0]= 'Q'; oTpmInfo.m_rgFixed[1]= 'U';
    oTpmInfo.m_rgFixed[2]= 'O'; oTpmInfo.m_rgFixed[3]= 'T';
    memcpy(oTpmInfo.m_pcrcompositeDigest, pcrDigest, sizepcrDigest);
    memcpy(oTpmInfo.m_hashofQuotedData, tobesignedHash, sizetobeSignedHash);

    // hash TPM12QUOTEINFO buffer
    oHash.Init();
    oHash.Update((byte*)&oTpmInfo, sizeof(oTpmInfo));
    oHash.Final();
    oHash.getDigest(outputHash);

#ifdef TEST1
    PrintBytes("tpm12quoteHash composite buffer hash\n", 
                pcrDigest, 20);
    PrintBytes("\ntpm12quoteHash computed TPM12QUOTEINFO\n", 
                (byte*)&oTpmInfo, sizeof(oTpmInfo));
    PrintBytes("\ntpm12quoteHash computed TPM12QUOTEINFO hash\n", 
                outputHash, 20);
#endif
    return true;
}


// --------------------------------------------------------------------------


//  Quote2 computation
//      H1:= SHA1(sizeSelect||selectMask||valueSize||PCRs)
//      S1:= targetPCR||localityatRelease||H1
//      Q1:= TPM_QUOTE_INFO2(QUT2||S1||data to sign||version||versioninfo)
//      if addVer is true
//          Q1= Q1 || TPM_CAP_VERSION_INFO


u32  localityModifier(byte loc)
{
    if(loc>=((byte)0) && loc<=((byte)4))
        return ((u32)1)<<loc;
    return (u32)0xff;
}


bool computeTPM12quote2compositepcrDigest(byte pcrMask[3], byte* pcrs, 
                                          byte locality, byte* pcrDigest)
{
    return computeTPM12compositepcrDigest(pcrMask, pcrs, pcrDigest);
}


bool tpm12quote2Hash(int sizenonce, byte* nonce, byte pcrMask[3], 
                     byte locality, int sizetobeSignedHash, byte* tobesignedHash,
                     int sizepcrComposite, byte* pcrComposite, bool addVer,
                     u32 sizeversion, byte* versionInfo, byte* outputHash)
{
    Sha1            oHash;
    byte            rgBuf[128];  // TPM_PCR_INFO_SHORT
    byte*           pb= rgBuf;
    u16             tag= TPM12QUOTE2INFOTAG;
    byte            cb;
    int             i;
    u16             numPCRs= 0;
    u16             selectSize= 3;
    int             size= 0;
    byte            loc=  localityModifier(locality);

    if(sizetobeSignedHash!=SHA1DIGESTBYTESIZE) {
        fprintf(g_logFile, "tpm12quote2Hash: to be signed data should be sha-1 hash\n");
        return false;
    }
    // PCR's used
    for(i=0; i<24;i++) {
        if((i%8)==0)
            cb= pcrMask[i/8];
        if((cb&0x01)!=0) {
            numPCRs++;
        }
        cb>>= 1;
    }

    revmemcpy(pb, (byte*)&tag, sizeof(u16));
    pb+= sizeof(u16);
    size+= sizeof(u16);

    pb[0]= 'Q'; pb[1]= 'U'; pb[2]= 'T'; pb[3]= '2';
    pb+= 4;
    size+= 4;

    memcpy(pb, tobesignedHash, sizetobeSignedHash);
    size+= sizetobeSignedHash;
    pb+= sizetobeSignedHash;

    revmemcpy(pb, (byte*)&selectSize, sizeof(u16));
    pb+= sizeof(u16);
    size+= sizeof(u16);

    memcpy(pb, pcrMask, 3);
    pb+= 3;
    size+= 3;
   
    revmemcpy(pb, (byte*)&loc, sizeof(byte));
    pb+= sizeof(byte);
    size+= sizeof(byte);

    memcpy(pb, pcrComposite, sizepcrComposite);
    size+= sizepcrComposite;
    pb+= sizepcrComposite;

    if(addVer) {
        revmemcpy(pb, (byte*)&sizeversion, sizeof(u32));
        pb+= sizeof(u32);
        size+= sizeof(u32);
        memcpy(pb, versionInfo, sizeversion);
        size+= sizeversion;
    }

    oHash.Init();
    oHash.Update((byte*)&rgBuf, size);
    oHash.Final();
    oHash.getDigest(outputHash);

#ifdef TEST1
    PrintBytes("tpm12quote2Hash composite buffer\n", 
                    rgBuf, size);
    PrintBytes("\ntpm12quote2Hash computed TPM12QUOTEINFO hash\n", 
                outputHash, 20);
#endif
    return true;
}


// --------------------------------------------------------------------------


bool sha256quoteHash(int sizenonce, byte* nonce, 
                     int sizetobesignedHash, byte* tobesignedHash,
                     int sizedigest, byte* digest, byte* outputHash)
{
    Sha256      oHash;
    const char*       szProlog= "JLMQUOTE";

    oHash.Init();
    oHash.Update((byte*) szProlog, strlen(szProlog));
    oHash.Update(tobesignedHash, sizetobesignedHash);
    oHash.Update(digest, sizedigest);
    oHash.Final();
    oHash.GetDigest(outputHash);

#ifdef TEST
    PrintBytes("sha256quoteHash: to be quoted\n", tobesignedHash, sizetobesignedHash);
    PrintBytes("sha256quoteHash: code digest\n", digest, sizedigest);
    PrintBytes("sha256quoteHash: quote digest\n", outputHash, SHA256DIGESTBYTESIZE);
#endif
    return true;
}


// --------------------------------------------------------------------------


