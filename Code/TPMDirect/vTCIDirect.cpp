//
//  File: vTCIDirect.cpp 
//  Description: direct TPM interface.
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


#include "vTCIDirect.h"
#include "jlmTypes.h"
#include "algs.h"
#include "sha1.h"
#include "jlmUtility.h"
#include "hashprep.h"
#include "logging.h"
#include "bignum.h"
#include "mpFunctions.h"
#include "hmacsha1.h"

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>


byte tpmCapblob[22]= {
    0, 193,
    0,0,0,18,
    0,0,0,101,
    0,0,0,6,
    0,0,0,0
};


// --------------------------------------------------------------------------


bool submitTPMReq(int fd, int sizein, byte* in, int* psizeout, byte* out)
{
    int     sizebuf= *psizeout;

    ssize_t result = write(fd, in, sizein);
    UNUSEDVAR(result);  
    *psizeout= read(fd, out, sizebuf);
    if(*psizeout<=0)
        return false;
    return true;
}


inline void Unload(bool fRev, byte* buf, int* poff, byte* dest, int size)
{
    if(fRev)
        revmemcpy(dest, &buf[*poff], size);
    else
        memcpy(dest, &buf[*poff], size);
    *poff+= size;
}


inline void Load(bool fRev, byte* buf, int* poff, byte* src, int size)
{
    if(fRev)
        revmemcpy(&buf[*poff], src, size);
    else
        memcpy(&buf[*poff], src, size);
    *poff+= size;
}


void Loadpcrelection(byte* buf, int* poff, byte* src)
{
    Load(true, buf, poff, src, sizeof(u16));
    Load(false, buf, poff, src+2, 3);
}


void Unloadpcrselection(byte* buf, int* poff, byte* dest)
{
    Load(true, buf, poff, dest, sizeof(u16));
    Load(false, buf, poff, dest+2, 3);
}


void Loadpcrinfolong(byte* buf, int* poff, byte* src)
{
    int n= 0;

    Load(true, buf, poff, src+n, sizeof(u16));
    n+= sizeof(u16);

    Load(true, buf, poff, src+n, sizeof(byte));
    n+= sizeof(byte);
    Load(true, buf, poff, src+n, sizeof(byte));
    n+= sizeof(byte);

    Loadpcrelection(buf, poff, src+n);
    n+= sizeof(tpm_pcr_selection);
    Loadpcrelection(buf, poff, src+n);
    n+= sizeof(tpm_pcr_selection);

    Load(false, buf, poff, src+n, 20);
    n+= 20;
    Load(false, buf, poff, src+n, 20);
    n+= 20;
}


void Unloadpcrinfolong(byte* buf, int* poff, byte* dest)
{
    int n= 0;

    Unload(true, buf, poff, dest+n, sizeof(u16));
    n+= sizeof(u16);
    Unload(true, buf, poff, dest+n, sizeof(u16));
    n+= sizeof(byte);
    Unload(true, buf, poff, dest+n, sizeof(u16));
    n+= sizeof(byte);
    Unloadpcrselection(buf, poff, dest+n);
    n+= sizeof(tpm_pcr_selection);
    Unloadpcrselection(buf, poff, dest+n);
    n+= sizeof(tpm_pcr_selection);
    Unload(false, buf, poff, dest+n, 20);
    n+= 20;
    Unload(false, buf, poff, dest+n, 20);
    n+= 20;
}


inline void myXOR(int size, byte* out, byte* in1, byte* in2)
{
    int i;
    for(i=0; i<size; i++)
        out[i]= in1[i]^in2[i];
}


bool fetchpcrValues(int fd, byte* pM, byte* pcrValues)
{
    int     n= 0;
    int     m= 0;
    int     k= 20;
    byte    cb= 0;
    extern  bool TPMpcrRead(int fd, int pcr, int* psize, byte* out);

    // PCR's used
    for(int i=0; i<24;i++) {
        if((i%8)==0)
            cb= pM[i/8];
        if((cb&0x01)!=0) {
            n= (i/8)*8+(i%8);
            if(!TPMpcrRead(fd, n, &k, pcrValues+m)) {
                fprintf(g_logFile, "fetchpcrValues can't create composite\n");
                return false;
            }
            m+= 20;
        }
        cb>>= 1;
    }
    return true;
}


bool create_pcrinfo(u32 locality, tpm_pcr_selection& releaselocs, 
                    byte* rgreleasepcrs, tpm_pcrinfo_long* pcrlong)
{
    int     i;

    printf("create_pcrinfo\n");
    pcrlong->m_tag= TPM_TAG_PCR_INFO_LONG;
    pcrlong->m_locatcreation= ((byte)1)<<locality;
    pcrlong->m_locatrelease= ((byte)1)<<locality;

    pcrlong->m_pcratcreation.m_size= releaselocs.m_size;
    for(i=0;i<3;i++)
        pcrlong->m_pcratcreation.m_mask[i]= releaselocs.m_mask[i];

    pcrlong->m_pcratrelease.m_size= releaselocs.m_size;
    for(i=0;i<3;i++)
        pcrlong->m_pcratrelease.m_mask[i]= releaselocs.m_mask[i];

    printf("create_pcrinfo about to compute composite\n");
    PrintBytes("mask: ", releaselocs.m_mask, 3);
    PrintBytes("release pcr: ",  rgreleasepcrs, 20);
    printf("create_pcrinfo locality: %d\n", locality);
    if(!computeTPM12quote2compositepcrDigest(releaselocs.m_mask, rgreleasepcrs,
                                          locality, pcrlong->m_digestatcreation)) {
        fprintf(g_logFile, "create_pcrinfo can't create composite\n");
        return false;
    }
    printf("create_pcrinfo composite computed\n");
    memcpy(pcrlong->m_digestatrelease, pcrlong->m_digestatcreation, 20);
    return true;
}


// --------------------------------------------------------------------


bool TPMgetCapability(int fd)
{
    byte    ansblob[128];
    int     n= 128;

    if(!submitTPMReq(fd, sizeof(tpmCapblob), tpmCapblob, &n, ansblob)) {
        fprintf(g_logFile, "submitTPMReq failed\n");
        return false;
        }
    PrintBytes("TPM capability response: ", ansblob, n);
    int     offset= 0;
    u16     tag= 0;
    u32     paramsize= 0;
    u32     result= 0;
    u32     cmd= 0;
    byte*   pResp;
    
    Unload(true, ansblob, &offset, (byte*) &tag, sizeof(u16));
    Unload(true, ansblob, &offset, (byte*) &paramsize, sizeof(u32));
    Unload(true, ansblob, &offset, (byte*) &result, sizeof(u32));
    Unload(true, ansblob, &offset, (byte*) &cmd, sizeof(u32));
    pResp= &ansblob[offset];
    fprintf(g_logFile, "Getcapability tag: %04x, paramsize: %d, result: %d, cmd: %08x\n",
            tag, paramsize, result, cmd);
    PrintBytes("Capability response: ", pResp, paramsize-16);
    
    return true;
}


int TPMgetRandom(int fd, int size, byte* out)
{
    byte    cmdblob[TPMMAXBUF];
    int     cmdoffset= 0;
    byte    ansblob[TPMMAXBUF];
    int     ansoffset= 0;

    u16     tagin= TPM_TAG_RQU_COMMAND;
    u32     insize= 14;
    u32     cmdin= TPM_ORD_GET_RANDOM;
    u32     sizerandom= 16;

    u16     tagout= 0;
    int     outsize= TPMMAXBUF;
    u32     paramsize= 0;
    u32     result= 0;

    // check parameters
    if(size<16) {
        fprintf(g_logFile, "TPMgetRandom buffer too small %d\n", size);
        return false;
    }

    // build command
    Load(true, cmdblob, &cmdoffset, (byte*)&tagin, sizeof(u16));
    Load(true, cmdblob, &cmdoffset, (byte*)&insize, sizeof(u32));
    Load(true, cmdblob, &cmdoffset, (byte*)&cmdin, sizeof(u32));
    Load(true, cmdblob, &cmdoffset, (byte*)&sizerandom, sizeof(u32));

#ifdef TPMTEST
    PrintBytes("TPMRandom command: ", cmdblob, cmdoffset);
#endif

    // execute
    if(!submitTPMReq(fd, cmdoffset, cmdblob, &outsize, ansblob)) {
        fprintf(g_logFile, "submitTPMReq failed in TPMgetRandom\n");
        return false;
        }

#ifdef TPMTEST
    PrintBytes("TPMRandom response: ", ansblob, outsize);
#endif

    // decode response
    Unload(true, ansblob, &ansoffset, (byte*) &tagout, sizeof(u16));
    Unload(true, ansblob, &ansoffset, (byte*) &paramsize, sizeof(u32));
    Unload(true, ansblob, &ansoffset, (byte*) &result, sizeof(u32));
    Unload(true, ansblob, &ansoffset, (byte*) &sizerandom, sizeof(u32));
    if(result!=TPM_SUCCESS) {
        fprintf(g_logFile, "TPMgetRandom request failed %d\n", result);
        return -1;
    }
    if(sizerandom>16) {
        fprintf(g_logFile, "sizerandom response in getTPM random too large %d\n", 
                sizerandom);
        fprintf(g_logFile, "tag out: %04x, paramsize: %d, result: %d\n",
                tagout, paramsize, result);
        return -1;
    }
    memcpy(out, &ansblob[ansoffset], sizerandom);
    ansoffset+= sizerandom;
    
    return (int) sizerandom;
}


bool TPMpcrRead(int fd, int pcr, int* psize, byte* out)
{
    byte    cmdblob[TPMMAXBUF];
    int     cmdoffset= 0;
    byte    ansblob[TPMMAXBUF];
    int     ansoffset= 0;

    u16     tagin= TPM_TAG_RQU_COMMAND;
    u32     insize= 14;
    u32     cmdin= TPM_ORD_PCR_READ;

    u16     tagout= 0;
    int     outsize= TPMMAXBUF;
    u32     paramsize= 0;
    u32     result= 0;

    // check parameters
    if(*psize<20) {
        fprintf(g_logFile, "TPMpcrRead buffer too small %d\n", *psize);
        return false;
    }

    // build command
    Load(true, cmdblob, &cmdoffset, (byte*)&tagin, sizeof(u16));
    Load(true, cmdblob, &cmdoffset, (byte*)&insize, sizeof(u32));
    Load(true, cmdblob, &cmdoffset, (byte*)&cmdin, sizeof(u32));
    Load(true, cmdblob, &cmdoffset, (byte*)&pcr, sizeof(u32));

#ifdef TPMTEST
    PrintBytes("TPMpcrReadcommand: ", cmdblob, cmdoffset);
#endif

    // execute
    if(!submitTPMReq(fd, cmdoffset, cmdblob, &outsize, ansblob)) {
        fprintf(g_logFile, "submitTPMReq failed in TPMgetRandom\n");
        return false;
        }

#ifdef TPMTEST
    PrintBytes("TPMpcrRead response: ", ansblob, outsize);
#endif

    // decode response
    Unload(true, ansblob, &ansoffset, (byte*) &tagout, sizeof(u16));
    Unload(true, ansblob, &ansoffset, (byte*) &paramsize, sizeof(u32));
    Unload(true, ansblob, &ansoffset, (byte*) &result, sizeof(u32));
    if(result!=TPM_SUCCESS) {
        fprintf(g_logFile, "TPMpcrRead request failed %d\n", result);
        return false;
    }

    memcpy(out, &ansblob[ansoffset], 20);
    ansoffset+= 20;
    *psize= 20;
    
    return true;
}


bool TPMpcrReset(int fd, int pcr, int* psize, byte* out)
{
    return true;
}


bool TPMnvRead(int fd, int pcr, int* psize, byte* out)
{
    return true;
}


bool TPMnvWrite(int fd, int pcr, int* psize, byte* out)
{
    return true;
}


bool TPMgetVersion(int fd, int pcr, int* psize, byte* out)
{
    return true;
}

bool TPMoiap(int fd, u32 locality, u32* ph, byte* nonce_even2)
{
    byte    cmdblob[TPMMAXBUF];
    int     cmdoffset= 0;
    byte    ansblob[TPMMAXBUF];
    int     ansoffset= 0;

    u16     tagin= TPM_TAG_RQU_COMMAND;
    u32     insize= 10;
    u32     cmdin= TPM_ORD_OIAP;

    u16     tagout= 0;
    int     outsize= TPMMAXBUF;
    u32     paramsize= 0;
    u32     result= 0;

    // check parameters

    // build command
    Load(true, cmdblob, &cmdoffset, (byte*)&tagin, sizeof(u16));
    Load(true, cmdblob, &cmdoffset, (byte*)&insize, sizeof(u32));
    Load(true, cmdblob, &cmdoffset, (byte*)&cmdin, sizeof(u32));

#ifdef TPMTEST
    PrintBytes("\nTPMoiap command: ", cmdblob, cmdoffset);
#endif

    // execute
    if(!submitTPMReq(fd, cmdoffset, cmdblob, &outsize, ansblob)) {
        fprintf(g_logFile, "submitTPMReq failed in TPMoiap\n");
        return false;
        }

#ifdef TPMTEST
    PrintBytes("TPMoiap response: ", ansblob, outsize);
#endif

    // decode response
    Unload(true, ansblob, &ansoffset, (byte*) &tagout, sizeof(u16));
    Unload(true, ansblob, &ansoffset, (byte*) &paramsize, sizeof(u32));
    Unload(true, ansblob, &ansoffset, (byte*) &result, sizeof(u32));
    if(result!=TPM_SUCCESS) {
        fprintf(g_logFile, "TPMoiap request failed %d\n", result);
        return false;
    }
    //  hauth, nonceeven
    Unload(true, ansblob, &ansoffset, (byte*) ph, sizeof(u32));
    Unload(false, ansblob, &ansoffset, (byte*) nonce_even2, 20);
    return true;
}


bool TPMosap(int fd, u32 locality, u16 enttype, u32 entvalue,
             byte* odd_osap, u32* phauth, byte* nonce_even,
             byte* even_osap)
{
    byte    cmdblob[TPMMAXBUF];
    int     cmdoffset= 0;
    byte    ansblob[TPMMAXBUF];
    int     ansoffset= 0;

    u16     tagin= TPM_TAG_RQU_COMMAND;
    u32     insize= 36;
    u32     cmdin= TPM_ORD_OSAP;

    u16     tagout= 0;
    int     outsize= TPMMAXBUF;
    u32     paramsize= 0;
    u32     result= 0;

    // check parameters

    // build command
    Load(true, cmdblob, &cmdoffset, (byte*)&tagin, sizeof(u16));
    Load(true, cmdblob, &cmdoffset, (byte*)&insize, sizeof(u32));
    Load(true, cmdblob, &cmdoffset, (byte*)&cmdin, sizeof(u32));
    Load(true, cmdblob, &cmdoffset, (byte*)&enttype, sizeof(u16));
    Load(true, cmdblob, &cmdoffset, (byte*)&entvalue, sizeof(u32));
    Load(false, cmdblob, &cmdoffset, (byte*)odd_osap, 20);

#ifdef TPMTEST
    PrintBytes("\nTPMosap command: ", cmdblob, cmdoffset);
#endif

    // execute
    if(!submitTPMReq(fd, cmdoffset, cmdblob, &outsize, ansblob)) {
        fprintf(g_logFile, "submitTPMReq failed in TPMosap\n");
        return false;
        }

#ifdef TPMTEST
    PrintBytes("TPMosap response: ", ansblob, outsize);
#endif

    // decode response
    Unload(true, ansblob, &ansoffset, (byte*) &tagout, sizeof(u16));
    Unload(true, ansblob, &ansoffset, (byte*) &paramsize, sizeof(u32));
    Unload(true, ansblob, &ansoffset, (byte*) &result, sizeof(u32));
    if(result!=TPM_SUCCESS) {
        fprintf(g_logFile, "TPMosap request failed %d\n", result);
        return false;
    }
    //  hauth, nonceeven, evenosap
    Unload(true, ansblob, &ansoffset, (byte*) phauth, sizeof(u32));
    Unload(false, ansblob, &ansoffset, (byte*) nonce_even, 20);
    Unload(false, ansblob, &ansoffset, (byte*) even_osap, 20);
    return true;
}


bool TPMseal(int fd, u32 hkey, byte* encauth, u32 pcrinfosize, byte* pcrinfo, 
             u32 sealinsize, byte* sealin, u32 hauth, u32* psealsizeout, 
             byte* sealout, byte* nonce_odd, byte* nonce_even,
             byte contsession, byte* pubauth)
{
    byte    cmdblob[TPMMAXBUF];
    int     cmdoffset= 0;
    byte    ansblob[TPMMAXBUF];
    int     ansoffset= 0;
    int     endsealdata;

    u16     tagin= TPM_TAG_RQU_AUTH1_COMMAND;
    u32     insize;
    u32     cmdin= TPM_ORD_SEAL;

    u16     tagout= 0;
    int     outsize= TPMMAXBUF;
    u32     paramsize= 0;
    u32     result= 0;

    // check parameters
    insize= 141+sealinsize;

    // build command
    Load(true, cmdblob, &cmdoffset, (byte*)&tagin, sizeof(u16));
    Load(true, cmdblob, &cmdoffset, (byte*)&insize, sizeof(u32));
    Load(true, cmdblob, &cmdoffset, (byte*)&cmdin, sizeof(u32));
    Load(true, cmdblob, &cmdoffset, (byte*)&hkey, sizeof(u32));
    Load(false, cmdblob, &cmdoffset, encauth, 20);
    Load(true, cmdblob, &cmdoffset, (byte*)&pcrinfosize, sizeof(u32));
    Loadpcrinfolong(cmdblob, &cmdoffset, (byte*)pcrinfo);
    Load(true, cmdblob, &cmdoffset, (byte*)&sealinsize, sizeof(u32));
    Load(false, cmdblob, &cmdoffset, (byte*)sealin, sealinsize);
    Load(true, cmdblob, &cmdoffset, (byte*)&hauth, sizeof(u32));
    Load(false, cmdblob, &cmdoffset, (byte*)nonce_odd, 20);
    Load(true, cmdblob, &cmdoffset, (byte*)&contsession, sizeof(byte));
    Load(false, cmdblob, &cmdoffset, pubauth, 20);

#ifdef TPMTEST
    fprintf(g_logFile, "insize: %d\n", insize);
    fprintf(g_logFile, "cmdoffset: %d\n", cmdoffset);
    PrintBytes("\nTPMseal command:\n", cmdblob, cmdoffset);
#endif

    // execute
    if(!submitTPMReq(fd, cmdoffset, cmdblob, &outsize, ansblob)) {
        fprintf(g_logFile, "submitTPMReq failed in TPMseal\n");
        return false;
        }

#ifdef TPMTEST
    PrintBytes("TPMseal response:\n", ansblob, outsize);
#endif

    // decode response
    // retrieve sealeddata, nonceeven, contsession, resauth
    Unload(true, ansblob, &ansoffset, (byte*) &tagout, sizeof(u16));
    Unload(true, ansblob, &ansoffset, (byte*) &paramsize, sizeof(u32));
    Unload(true, ansblob, &ansoffset, (byte*) &result, sizeof(u32));
    if(result!=TPM_SUCCESS) {
        fprintf(g_logFile, "TPMseal request failed %d\n", result);
        return false;
    }

    // calculate *psealsizeout
    if(paramsize<52)
        return false;

    endsealdata= paramsize-41;  // nonce_even, contauthsession, authdata
    *psealsizeout= endsealdata-ansoffset;

    Unload(false, ansblob, &ansoffset, (byte*) sealout, *psealsizeout);
    Unload(false, ansblob, &ansoffset, (byte*) nonce_even, 20);
    Unload(true, ansblob, &ansoffset, (byte*) &contsession, sizeof(byte));
    Unload(false, ansblob, &ansoffset, (byte*) pubauth, 20);

#ifdef TPMTEST
    fprintf(g_logFile, "\nSize of sealeddata: %d\n", *psealsizeout);
    PrintBytes("sealed data:\n", sealout, *psealsizeout);
    PrintBytes("new nonce even: ", nonce_even, 20);
    fprintf(g_logFile, "contsession: %08x\n", contsession);
    PrintBytes("authdata: ", pubauth, 20);
#endif

    return true;
}


bool TPMunseal(int fd, u32 hkey, u32 hauth, byte* nonce_odd, 
               byte contsession, byte* pubauth, u32 hauthd, byte* nonce_oddd, 
               byte contsessiond, byte* pubauthd, int sizesecret, 
               byte* shared_secret, byte* nonce_even, byte* resauth, 
               u32 sizein, byte* in, u32* psizeout, byte* out,
               byte* nonce_evend, byte* resauthd)
{
    byte    cmdblob[TPMMAXBUF];
    int     cmdoffset= 0;
    byte    ansblob[TPMMAXBUF];
    int     ansoffset= 0;

    u16     tagin= TPM_TAG_RQU_AUTH2_COMMAND;
    u32     insize= 0;
    u32     cmdin= TPM_ORD_UNSEAL;

    u16     tagout= 0;
    int     outsize= TPMMAXBUF;
    u32     paramsize= 0;
    u32     result= 0;

    // check parameters
    insize= 104+sizein;

    // build command
    Load(true, cmdblob, &cmdoffset, (byte*)&tagin, sizeof(u16));
    Load(true, cmdblob, &cmdoffset, (byte*)&insize, sizeof(u32));
    Load(true, cmdblob, &cmdoffset, (byte*)&cmdin, sizeof(u32));
    Load(true, cmdblob, &cmdoffset, (byte*)&hkey, sizeof(u32));
    Load(false, cmdblob, &cmdoffset, in, sizein);
    Load(true, cmdblob, &cmdoffset, (byte*)&hauth, sizeof(u32));
    Load(false, cmdblob, &cmdoffset, nonce_odd, 20);
    Load(false, cmdblob, &cmdoffset, &contsession, 1);
    Load(false, cmdblob, &cmdoffset, pubauth, 20);
    Load(true, cmdblob, &cmdoffset, (byte*)&hauthd, sizeof(u32));
    Load(false, cmdblob, &cmdoffset, nonce_oddd, 20);
    Load(false, cmdblob, &cmdoffset, &contsessiond, 1);
    Load(false, cmdblob, &cmdoffset, pubauthd, 20);

#ifdef TPMTEST
    fprintf(g_logFile, "insize: %d hauth: %08x, hauthd: %08x, key: %08x\n", 
            insize, hauth, hauthd, hkey);
    fprintf(g_logFile, "cmdoffset: %d\n", cmdoffset);
    PrintBytes("\nTPMunseal command:\n", cmdblob, cmdoffset);
    PrintBytes("in data: ", in, sizein);
#endif

    // execute
    if(!submitTPMReq(fd, cmdoffset, cmdblob, &outsize, ansblob)) {
        fprintf(g_logFile, "submitTPMReq failed in TPMunseal\n");
        return false;
        }

#ifdef TPMTEST
    PrintBytes("TPMunseal response:\n", ansblob, outsize);
#endif

    // decode response
    // retrieve sealeddata, nonceeven, contsession, resauth
    Unload(true, ansblob, &ansoffset, (byte*) &tagout, sizeof(u16));
    Unload(true, ansblob, &ansoffset, (byte*) &paramsize, sizeof(u32));
    Unload(true, ansblob, &ansoffset, (byte*) &result, sizeof(u32));
    if(result!=TPM_SUCCESS) {
        fprintf(g_logFile, "TPMunseal request failed %d\n", result);
        return false;
    }
    Unload(true, ansblob, &ansoffset, (byte*) psizeout, sizeof(u32));
    Unload(false, ansblob, &ansoffset, out, *psizeout);
    Unload(false, ansblob, &ansoffset, nonce_even, 20);
    Unload(true, ansblob, &ansoffset, (byte*) &contsession, sizeof(byte));
    Unload(false, ansblob, &ansoffset, (byte*) resauth, 20);
    Unload(false, ansblob, &ansoffset, nonce_evend, 20);
    Unload(true, ansblob, &ansoffset, (byte*) &contsessiond, sizeof(byte));
    Unload(false, ansblob, &ansoffset, (byte*) resauthd, 20);

#ifdef TPMTEST
    fprintf(g_logFile, "\nsize of unsealeddata: %d\n", *psizeout);
    PrintBytes("unsealed data:\n", out, *psizeout);
    PrintBytes("new nonce even: ", nonce_even, 20);
    fprintf(g_logFile, "contsession: %08x\n", contsession);
    PrintBytes("resauthdata: ", resauth, 20);
    PrintBytes("new data nonce even: ", nonce_evend, 20);
    fprintf(g_logFile, "contsession: %08x\n", contsessiond);
    PrintBytes("resauthdata: ", resauthd, 20);
#endif
    return true;
}


bool TPMloadKey(int fd, u32 hparentKey, int sizekeyIn, byte* keyblob,
                u32 hauth, byte* nonce_odd, byte contsession, u32* pkeyhandle,
                byte* nonce_even, byte* pubauth, byte* resauth)
{
    byte    cmdblob[TPMMAXBUF];
    int     cmdoffset= 0;
    byte    ansblob[TPMMAXBUF];
    int     ansoffset= 0;

    u16     tagin= TPM_TAG_RQU_AUTH1_COMMAND;
    u32     insize= 0;
    u32     cmdin= TPM_ORD_LOADKEY2;

    u16     tagout= 0;
    int     outsize= TPMMAXBUF;
    u32     paramsize= 0;
    u32     result= 0;

    // check parameters
    insize= 59+sizekeyIn;

    // build command
    Load(true, cmdblob, &cmdoffset, (byte*)&tagin, sizeof(u16));
    Load(true, cmdblob, &cmdoffset, (byte*)&insize, sizeof(u32));
    Load(true, cmdblob, &cmdoffset, (byte*)&cmdin, sizeof(u32));
    Load(true, cmdblob, &cmdoffset, (byte*)&hparentKey, sizeof(u32));
    Load(false, cmdblob, &cmdoffset, keyblob, sizekeyIn);
    Load(true, cmdblob, &cmdoffset, (byte*)&hauth, sizeof(u32));
    Load(false, cmdblob, &cmdoffset, nonce_odd, 20);
    Load(false, cmdblob, &cmdoffset, &contsession, 1);
    Load(false, cmdblob, &cmdoffset, pubauth, 20);

#ifdef TPMTEST
    fprintf(g_logFile, "\nloadKey\n");
    fprintf(g_logFile, "cmdoffset: %d\n", cmdoffset);
    PrintBytes("\nTPMloadKey command:\n", cmdblob, cmdoffset);
#endif 

    // execute
    if(!submitTPMReq(fd, cmdoffset, cmdblob, &outsize, ansblob)) {
        fprintf(g_logFile, "submitTPMReq failed in TPMloadKey\n");
        return false;
        }

#ifdef TPMTEST
    PrintBytes("TPMloadKey response:\n", ansblob, outsize);
#endif

    // decode response
    // retrieve sealeddata, nonceeven, contsession, resauth
    Unload(true, ansblob, &ansoffset, (byte*) &tagout, sizeof(u16));
    Unload(true, ansblob, &ansoffset, (byte*) &paramsize, sizeof(u32));
    Unload(true, ansblob, &ansoffset, (byte*) &result, sizeof(u32));
    if(result!=TPM_SUCCESS) {
        fprintf(g_logFile, "TPMloadKey request failed %d\n", result);
        return false;
    }
    Unload(true, ansblob, &ansoffset, (byte*) pkeyhandle, sizeof(u32));
    Unload(false, ansblob, &ansoffset, nonce_even, 20);
    Unload(true, ansblob, &ansoffset, (byte*) &contsession, sizeof(byte));
    Unload(false, ansblob, &ansoffset, (byte*) resauth, 20);

#ifdef TPMTEST
    fprintf(g_logFile, "contsession: %08x\n", contsession);
    PrintBytes("resauthdata: ", resauth, 20);
    PrintBytes("new data nonce even: ", nonce_even, 20);
#endif
    return true;
}


bool TPMquote2(int fd, u32 keyHandle, byte* toSign, int pcrselectsize, 
               byte* pcrselection, bool addVer, u32 hkeyauth, 
               int* psizepcrinfo, byte*pcrinfo, int* psizesig,
               byte* sig, int* pVersionsize, byte* versioninfo,
               byte* nonce_even, byte* nonce_odd, 
               byte contsession, byte* privauth, byte* resauth)
{
    byte    cmdblob[TPMMAXBUF];
    int     cmdoffset= 0;
    byte    ansblob[TPMMAXBUF];
    int     ansoffset= 0;

    u16     tagin= TPM_TAG_RQU_AUTH1_COMMAND;
    u32     insize;
    u32     cmdin= TPM_ORD_QUOTE2;

    u16     tagout= 0;
    int     outsize= TPMMAXBUF;
    u32     paramsize= 0;
    u32     result= 0;

    // check parameters
    insize= 80+sizeof(tpm_pcr_selection);
    *psizepcrinfo= sizeof(tpm_pcr_selection);

    // build command
    Load(true, cmdblob, &cmdoffset, (byte*)&tagin, sizeof(u16));
    Load(true, cmdblob, &cmdoffset, (byte*)&insize, sizeof(u32));
    Load(true, cmdblob, &cmdoffset, (byte*)&cmdin, sizeof(u32));
    Load(true, cmdblob, &cmdoffset, (byte*)&keyHandle, sizeof(u32));
    Load(false, cmdblob, &cmdoffset, toSign, 20);
    Loadpcrelection(cmdblob, &cmdoffset, pcrselection);
    Load(true, cmdblob, &cmdoffset, (byte*)&addVer, sizeof(byte));
    Load(true, cmdblob, &cmdoffset, (byte*)&hkeyauth, sizeof(u32));
    Load(false, cmdblob, &cmdoffset, (byte*)nonce_odd, 20);
    Load(true, cmdblob, &cmdoffset, (byte*)&contsession, sizeof(byte));
    Load(false, cmdblob, &cmdoffset, privauth, 20);

#ifdef TPMTEST
    fprintf(g_logFile, "insize: %d\n", insize);
    fprintf(g_logFile, "cmdoffset: %d\n", cmdoffset);
    PrintBytes("\nTPMquote2 command: ", cmdblob, cmdoffset);
#endif

    // execute
    if(!submitTPMReq(fd, cmdoffset, cmdblob, &outsize, ansblob)) {
        fprintf(g_logFile, "submitTPMReq failed in TPMquote2\n");
        return false;
        }

#ifdef TPMTEST
    PrintBytes("TPMquote2 response: ", ansblob, outsize);
#endif

    // decode response
    // retrieve sealeddata, nonceeven, contsession, resauth
    Unload(true, ansblob, &ansoffset, (byte*) &tagout, sizeof(u16));
    Unload(true, ansblob, &ansoffset, (byte*) &paramsize, sizeof(u32));
    Unload(true, ansblob, &ansoffset, (byte*) &result, sizeof(u32));
    if(result!=TPM_SUCCESS) {
        fprintf(g_logFile, "TPMquote2 request failed %d\n", result);
        return false;
    }

    *psizepcrinfo= sizeof(tpm_pcrinfo_short);
    Unload(false, ansblob, &ansoffset, pcrinfo, *psizepcrinfo);
    Unload(true, ansblob, &ansoffset, (byte*)pVersionsize, sizeof(u32));
    Unload(false, ansblob, &ansoffset, versioninfo, *pVersionsize);
    Unload(true, ansblob, &ansoffset, (byte*)psizesig, sizeof(u32));
    Unload(false, ansblob, &ansoffset, sig, *psizesig);
    Unload(false, ansblob, &ansoffset, (byte*) nonce_even, 20);
    Unload(true, ansblob, &ansoffset, (byte*) &contsession, sizeof(byte));
    Unload(false, ansblob, &ansoffset, (byte*) resauth, 20);

#ifdef TPMTEST
    fprintf(g_logFile, "\nSize of signature: %d\n", *psizesig);
    PrintBytes("signature: ", sig, *psizesig);
    PrintBytes("new nonce even: ", nonce_even, 20);
    fprintf(g_logFile, "contsession: %08x\n", contsession);
    PrintBytes("authdata: ", privauth, 20);
#endif

    return true;
}


bool TPMgetpubkey(int fd, u32 keyHandle, u32 hkeyauth, int* pmodsize, byte* modulus,
                  byte* nonce_even, byte* nonce_odd, byte contsession, 
                  byte* pubauth, byte* resauth)
{
    byte        cmdblob[TPMMAXBUF];
    int         cmdoffset= 0;
    byte        ansblob[TPMMAXBUF];
    int         ansoffset= 0;

    u16         tagin= TPM_TAG_RQU_AUTH1_COMMAND;
    u32         insize= 59;
    u32         cmdin= TPM_ORD_GETPUBKEY;

    u16         tagout= 0;
    int         outsize= TPMMAXBUF;
    u32         paramsize= 0;
    u32         result= 0;
    u32         n;

    // check parameters

    // build command
    Load(true, cmdblob, &cmdoffset, (byte*)&tagin, sizeof(u16));
    Load(true, cmdblob, &cmdoffset, (byte*)&insize, sizeof(u32));
    Load(true, cmdblob, &cmdoffset, (byte*)&cmdin, sizeof(u32));
    Load(true, cmdblob, &cmdoffset, (byte*)&keyHandle, sizeof(u32));
    Load(true, cmdblob, &cmdoffset, (byte*)&hkeyauth, sizeof(u32));
    Load(false, cmdblob, &cmdoffset, (byte*)nonce_odd, 20);
    Load(true, cmdblob, &cmdoffset, (byte*)&contsession, sizeof(byte));
    Load(false, cmdblob, &cmdoffset, pubauth, 20);

#ifdef TPMTEST
    PrintBytes("\nTPMgetpubkey command: ", cmdblob, cmdoffset);
#endif

    // execute
    if(!submitTPMReq(fd, cmdoffset, cmdblob, &outsize, ansblob)) {
        fprintf(g_logFile, "submitTPMReq failed in TPMgetpubkey\n");
        return false;
        }

#ifdef TPMTEST
    PrintBytes("TPMgetpubkey response: ", ansblob, outsize);
#endif

    // decode response
    Unload(true, ansblob, &ansoffset, (byte*) &tagout, sizeof(u16));
    Unload(true, ansblob, &ansoffset, (byte*) &paramsize, sizeof(u32));
    Unload(true, ansblob, &ansoffset, (byte*) &result, sizeof(u32));
    if(result!=TPM_SUCCESS) {
        fprintf(g_logFile, "TPMgetpubkey request failed %d\n", result);
        return false;
    }
    ansoffset+= 8;   //skip algid, encscheme, sigscheme
    Unload(true, ansblob, &ansoffset, (byte*) &n, sizeof(u32)); // paramsize
    ansoffset+= n; // skip past alg params
    Unload(true, ansblob, &ansoffset, (byte*) pmodsize, sizeof(u32)); // modulus length
    Unload(false, ansblob, &ansoffset, modulus, *pmodsize);
    Unload(false, ansblob, &ansoffset, (byte*) nonce_even, 20);
    Unload(true, ansblob, &ansoffset, (byte*) &contsession, sizeof(byte));
    Unload(false, ansblob, &ansoffset, (byte*) resauth, 20);

    // memcpy(modulus, something,256);
    return true;
}


bool TPMterminatehandle(int fd, u32 handle)
{
    byte    cmdblob[TPMMAXBUF];
    int     cmdoffset= 0;
    byte    ansblob[TPMMAXBUF];
    int     ansoffset= 0;

    u16     tagin= TPM_TAG_RQU_COMMAND;
    u32     insize= 14;
    u32     cmdin= TPM_ORD_TERMINATEHANDLE;

    u16     tagout= 0;
    int     outsize= TPMMAXBUF;
    u32     paramsize= 0;
    u32     result= 0;

    // check parameters

    // build command
    Load(true, cmdblob, &cmdoffset, (byte*)&tagin, sizeof(u16));
    Load(true, cmdblob, &cmdoffset, (byte*)&insize, sizeof(u32));
    Load(true, cmdblob, &cmdoffset, (byte*)&cmdin, sizeof(u32));
    Load(true, cmdblob, &cmdoffset, (byte*)&handle, sizeof(u32));

#ifdef TPMTEST
    PrintBytes("\nTPMterminatehandle command: ", cmdblob, cmdoffset);
#endif

    // execute
    if(!submitTPMReq(fd, cmdoffset, cmdblob, &outsize, ansblob)) {
        fprintf(g_logFile, "submitTPMReq failed in TPMterminatehandle\n");
        return false;
        }

#ifdef TPMTEST
    PrintBytes("TPMterminatehandle response: ", ansblob, outsize);
#endif

    // decode response
    Unload(true, ansblob, &ansoffset, (byte*) &tagout, sizeof(u16));
    Unload(true, ansblob, &ansoffset, (byte*) &paramsize, sizeof(u32));
    Unload(true, ansblob, &ansoffset, (byte*) &result, sizeof(u32));
    if(result!=TPM_SUCCESS) {
        fprintf(g_logFile, "TPMterminatehandle request failed %d\n", result);
        return false;
    }
    return true;
}


bool TPMgetnvindexsize(int fd, int pcr, int* psize, byte* out)
{
    return true;
}


bool TPMgetflags(int fd, int pcr, int* psize, byte* out)
{
    return true;
}


bool TPMreleaselocality(int fd, int pcr, int* psize, byte* out)
{
    return true;
}


bool TPMready(int fd, int pcr, int* psize, byte* out)
{
    return true;
}


bool TPMsavestate(int fd, int pcr, int* psize, byte* out)
{
    return true;
}


// --------------------------------------------------------------------------


tpmStatus::tpmStatus()
{
    m_fTPMInitialized= false;
    m_tpmfd= -1;
    m_fSRKAuthSet= false;;
    m_fTPMAuthSet= false;
    m_szTPMSecret= NULL;
    m_szSRKSecret= NULL;
    m_fSealKeyValid= false;
    m_hSealKey= 0;
    m_fQuoteKeyValid= false;
    m_hQuoteKey= 0;
    m_fpcrSelectionValid= false;
    m_rgpcrSValid= false;
    m_npcrs= 0;
    m_locality= 0;
    m_fEKKeyValid= false;
    m_faikKeyValid= false;
    m_iaikmodulusLen= -1;
    m_iEkmodulusLen= -1; 
    m_rgEKCert= NULL;
    m_rgAIKCert= NULL;
}


tpmStatus::~tpmStatus()
{
    m_fTPMInitialized= false;
    m_tpmfd= -1;
    m_locality= 0;
    m_fSRKAuthSet= false;
    m_fTPMAuthSet= false;
    memset(m_rgSRKAuth,0, 20);
    memset(m_rgTPMAuth,0, 20);
    if(m_szTPMSecret==NULL)
        free(m_szTPMSecret);
    m_szTPMSecret= NULL;
    if(m_szSRKSecret==NULL)
        free(m_szSRKSecret);
    m_szSRKSecret= NULL;
    m_fEKKeyValid= false;
    m_faikKeyValid= false;
    m_iaikmodulusLen= -1;
    m_iEkmodulusLen= -1; 
    //m_rgekmodulus[256];
    if(m_rgEKCert==NULL)
        free(m_rgEKCert);
    m_rgEKCert= NULL;
    if(m_rgAIKCert==NULL)
        free(m_rgAIKCert);
    m_rgAIKCert= NULL;
}


bool tpmStatus::initTPM(const char* deviceName)
{
    if(m_fTPMInitialized)
        return true;

    m_tpmfd= open(deviceName, O_RDWR);
    if(m_tpmfd<0) {
        fprintf(g_logFile, "Can't open tpm driver %s\n", deviceName);
        fprintf(g_logFile, "Open error: %s\n", strerror(errno));
        return false;
        }

#ifdef TPMTEST
    if(!TPMgetCapability(m_tpmfd)) {
        fprintf(g_logFile, "GetCapability failed\n");
    }
#endif

    if(!setSRKauth(NULL)) {
        fprintf(g_logFile, "cant set SRK Auth\n");
        return false;
    }


    // load SRK KEY
    if(!loadKey(KEYTYPE_SRK, NULL, 0, &m_hSealKey)) {
        fprintf(g_logFile, "Cant load SRK Key\n");
        return false;
    }
    m_fSealKeyValid= true;

    // init PCRs
#ifdef PCR18
    byte pcrMask[3]= {0,0,0x6};  // pcr 17, 18
#else
    byte pcrMask[3]= {0,0,0x2};  // pcr 17
#endif
    if(!selectPCRCompositeIndex(pcrMask)) {
        fprintf(g_logFile, "Cant select PCRs\n");
        return false;
    }

    m_fTPMInitialized= true;
    return true;
}


bool tpmStatus::setLocality(u32 in)
{
    // send setLocality command
    // check result
    return true;
}


bool tpmStatus::getLocality(unsigned* pOut)
{
    *pOut= m_locality;
    return true;
}


bool tpmStatus::getPCRValue(int pcr, int* psize, byte* buf)
{
    return TPMpcrRead(m_tpmfd, pcr, psize, buf);
}


bool tpmStatus::setPCRValue(int pcr, int size, byte* buf)
{
    return true;
}

bool tpmStatus::selectPCRCompositeIndex(byte* pM)
{
    int     numPCRs= 0;
    byte    cb;

    // PCR's used
    for(int i=0; i<24;i++) {
        if((i%8)==0)
            cb= pM[i/8];
        if((cb&0x01)!=0) {
            numPCRs++;
        }
        cb>>= 1;
    }

    m_npcrs= 3;
    for(int i=0; i<3; i++)
        m_rgpcrMask[i]= pM[i];
    m_fpcrSelectionValid= true;

    return true;
}


bool tpmStatus::getCompositePCR(u32 loc, byte* pM, unsigned* pSize, byte* buf)
{
    int     i, n;
    int     numPCRs= 0;
    int     rgiPCR[24];
    byte    cb= 0;

    // PCR's used
    for(i=0; i<24;i++) {
        if((i%8)==0)
            cb= pM[i/8];
        if((cb&0x01)!=0) {
            rgiPCR[numPCRs++]= i;
        }
        cb>>= 1;
    }

    if((int)(*pSize)<(numPCRs*20)) {
        fprintf(g_logFile, "getCompositePCR: buffer too small for PCRs\n");
        return false;
    }

    for(i=0; i<numPCRs; i++) {
        n= 20;
        if(!getPCRValue(rgiPCR[i], &n, &buf[20*i])) {
            fprintf(g_logFile, "getCompositePCR: getPCRValue failed for %d\n",
                    rgiPCR[i]);
            return false;
        }
    }
    *pSize= 20*numPCRs;
    return true;
}


bool tpmStatus::loadKey(u32 keytype, byte* buf, int size, u32* ph)
{
    bool                fRet= true;
    u32                 ord= TPM_ORD_LOADKEY2;
    byte                osap[40];   
    byte*               even_osap= osap;
    byte*               odd_osap= &osap[20];
    byte                nonce_even[20];
    byte                nonce_odd[20];
    byte                shared_secret[20];
    byte                pubauth[20];
    byte                resauth[20];
    u32                 hauth= 0;
    byte                contsession= 0;
    int                 inparamsize= 0;
    byte                inparams[1024];
    byte                digest[20];

    Sha1                oSha1;

    u32                 ordk= TPM_ORD_GETPUBKEY;
    byte                osapk[40];   
    byte*               even_osapk= osapk;
    byte*               odd_osapk= &osapk[20];
    byte                nonce_evenk[20];
    byte                nonce_oddk[20];
    byte                shared_secretk[20];
    byte                pubauthk[20];
    byte                resauthk[20];
    u32                 hauthk= 0;
    byte                contsessionk= 0;

    if(keytype==KEYTYPE_SRK) {
        *ph= TPM_KH_SRK;
        return true;
    }
    if(keytype!=KEYTYPE_AIK) {
        fprintf(g_logFile, "Key type not supported\n");
        fRet= false;
        goto finish;
    }
    if(m_fTPMAuthSet) {
        fprintf(g_logFile, "Owner auth not set\n");
        fRet= false;
        goto finish;
    }

    if(!m_fSealKeyValid) {
        fprintf(g_logFile, "TPMloadKey: SRK not valid\n");
        fRet= false;
        goto finish;
    }

    memset(odd_osap,0,20);
    memset(even_osap,0,20);
    memset(nonce_even,0,20);
    memset(nonce_odd,0,20);

    // TPMosap
    if(!TPMosap(m_tpmfd, m_locality, TPM_ET_SRK, TPM_KH_SRK, 
                odd_osap, &hauth, nonce_even, even_osap)) {
        fprintf(g_logFile, "TPM_osap failed in loadKey\n");
        fRet= false;
        goto finish;
    }   

    // shared secret= hmacsha1(m_szSRKSecret, evenosap||oddosap)
    if(!hmac_sha1(osap, 40, m_rgSRKAuth, 20, shared_secret)) {
        fprintf(g_logFile, "hmacsha1 failed in loadKey\n");
        fRet= false;
        goto finish;
    }

    //  digest= Sha1(ordinal||inKey)
    inparamsize= 0;
    Load(true, inparams, &inparamsize, (byte*)&ord, sizeof(u32));
    Load(false, inparams, &inparamsize, buf, size);
    oSha1.Init();
    oSha1.Update(inparams, inparamsize);
    oSha1.Final();
    oSha1.getDigest(digest);

    // now calculate pubauth
    //  pubauth= hmac(sharedsecret, digest||nonceeven||nonceodd||cont_session)
    inparamsize= 0;
    Load(false, inparams, &inparamsize, digest, 20);
    Load(false, inparams, &inparamsize, nonce_even, 20);
    Load(false, inparams, &inparamsize, nonce_odd, 20);
    Load(false, inparams, &inparamsize, &contsession, 1);
    if(!hmac_sha1(inparams, inparamsize, shared_secret, 20, pubauth)) {
        fprintf(g_logFile, "hmacsha1 pubauth failed in sealData\n");
        fRet= false;
        goto finish;
    }

#ifdef TPMTEST
    PrintBytes("\nshared secret: ", shared_secret, 20);
    PrintBytes("digest: ", digest, 20);
    PrintBytes("pubauth: ", pubauth, 20);
#endif

    if(!TPMloadKey(m_tpmfd, m_hSealKey, size, buf, hauth, nonce_odd, 
                   contsession, &m_hQuoteKey, nonce_even, pubauth, resauth)) {
        fprintf(g_logFile, "Can't load key in loadKey\n");
        fRet= false;
        goto finish;
    }

    // auth handle and data for quote key
    memset(odd_osapk,0,20);
    memset(even_osapk,0,20);
    memset(nonce_evenk,0,20);
    memset(nonce_oddk,0,20);

    // TPMosap
    if(!TPMosap(m_tpmfd, m_locality, TPM_ET_KEYHANDLE, m_hQuoteKey, 
                odd_osapk, &hauthk, nonce_evenk, even_osapk)) {
        fprintf(g_logFile, "TPM_osap failed for getpubkey in loadKey\n");
        fRet= false;
        goto finish;
    }   

    // shared secret= hmacsha1(m_szSRKSecret, evenosap||oddosap)
    //if(!hmac_sha1(osapk, 40, m_rgTPMAuth, 20, shared_secretk)) {
    if(!hmac_sha1(osapk, 40, m_rgSRKAuth, 20, shared_secretk)) {
        fprintf(g_logFile, "hmacsha1 failed in loadKey\n");
        fRet= false;
        goto finish;
    }

    //  digest= Sha1(ordinal)
    inparamsize= 0;
    Load(true, inparams, &inparamsize, (byte*)&ordk, sizeof(u32));
    oSha1.Init();
    oSha1.Update(inparams, inparamsize);
    oSha1.Final();
    oSha1.getDigest(digest);

    // now calculate pubauth
    //  pubauth= hmac(sharedsecret, digest||nonceeven||nonceodd||cont_session)
    inparamsize= 0;
    Load(false, inparams, &inparamsize, digest, 20);
    Load(false, inparams, &inparamsize, nonce_evenk, 20);
    Load(false, inparams, &inparamsize, nonce_oddk, 20);
    Load(false, inparams, &inparamsize, &contsessionk, 1);
    if(!hmac_sha1(inparams, inparamsize, shared_secretk, 20, pubauthk)) {
        fprintf(g_logFile, "hmacsha1 pubauth failed for getpubkey in sealData\n");
        fRet= false;
        goto finish;
    }

#ifdef TPMTEST
    PrintBytes("\nshared secretk: ", shared_secret, 20);
    fprintf(g_logFile, "Key handle: %08x\n", m_hQuoteKey);
    fprintf(g_logFile, "Auth handle: %08x\n", hauthk);
    PrintBytes("digest: ", digest, 20);
    PrintBytes("pubauthk: ", pubauth, 20);
#endif

    // get modulus length and modulus
    if(!TPMgetpubkey(m_tpmfd, m_hQuoteKey, hauthk, &m_iaikmodulusLen, m_rgaikmodulus,
                     nonce_evenk, nonce_oddk, contsessionk, pubauthk, resauthk)) {
        fprintf(g_logFile, "Can't get public key modulus\n");
        fRet= false;
        goto finish;
    }

finish:
#ifdef TERMINATEHANDLES
    if(hauth==0)
        TPMterminatehandle(m_tpmfd, hauth);
#endif
    return fRet;
}


bool tpmStatus::setSRKauth(const char* srkSecret)
{
    if(srkSecret!=NULL)
        m_szSRKSecret= strdup(srkSecret);
    else
        m_szSRKSecret= NULL;
    memset(m_rgSRKAuth,0, 20);  // well know secret

    m_fSRKAuthSet= true;
    return true;
}


bool tpmStatus::setTPMauth(const char* ownerSecret)
{
    Sha1    osha1;

    if(ownerSecret!=NULL) {
        m_szTPMSecret= strdup(ownerSecret);
        osha1.Init();
        osha1.Update((byte*)ownerSecret, strlen(ownerSecret));
        osha1.Final();
        osha1.getDigest(m_rgTPMAuth);
    }
    else {
        m_szTPMSecret= NULL;
        memset(m_rgTPMAuth, 0, 20);  
    }
    m_fTPMAuthSet= true;
    return true;
}


bool tpmStatus::sealData(unsigned sizetoSeal, byte* tosealData, 
                         unsigned* psizeSealed, byte* sealedData)
{
    u32                 ord= TPM_ORD_SEAL;
    byte                osap[40];   
    byte*               even_osap= osap;
    byte*               odd_osap= &osap[20];
    byte                nonce_even[20];
    byte                nonce_odd[20];
    byte                shared_secret[20];
    byte                authdata[20];
    byte                encauth[20];
    byte                pubauth[20];
    u32                 hauth= 0;
    byte                contsession= 0;
    tpm_pcrinfo_long    pcrinfo;
    Sha1                oSha1;
    byte                pcrValues[20*24];
    tpm_pcr_selection   pcrsel;
    int                 inparamsize= 0;
    byte                inparams[256];
    byte                digest[20];
    u32                 pcrinfosize= sizeof(tpm_pcrinfo_long);
    bool                fRet= true;

    if(!m_fSRKAuthSet) {
        fprintf(g_logFile, "SRK Auth not set\n");
        fRet= false;
        goto finish;
    }

    memset(odd_osap,0,20);
    memset(even_osap,0,20);
    memset(nonce_even,0,20);
    memset(nonce_odd,0,20);

    if(!m_fSealKeyValid) {
        fprintf(g_logFile, "Sealing key invalid in sealData\n");
        fRet= false;
        goto finish;
    }
    if(!m_fpcrSelectionValid) {
        fprintf(g_logFile, "Pcr selection invalid in sealData\n");
        fRet= false;
        goto finish;
    }

    // init pcr_info
    if(!fetchpcrValues(m_tpmfd, m_rgpcrMask, pcrValues)) {
        fprintf(g_logFile, "fetchpcrValues failed in sealData\n");
        fRet= false;
        goto finish;
    }
    pcrsel.m_size= 3;
    for(int i=0; i<3; i++)
        pcrsel.m_mask[i]= m_rgpcrMask[i];
    if(!create_pcrinfo(m_locality, pcrsel, pcrValues, &pcrinfo)) {
        fprintf(g_logFile, "create_pcrinfo failed in sealData\n");
        fRet= false;
        goto finish;
    }
#ifdef TPMTEST
    PrintBytes("pcrinfo: ", (byte*)&pcrinfo, sizeof(pcrinfo));
#endif

    // TPMosap
    if(!TPMosap(m_tpmfd, m_locality, TPM_ET_SRK, TPM_KH_SRK, 
                odd_osap, &hauth, nonce_even, even_osap)) {
        fprintf(g_logFile, "TPM_osap failed in sealData\n");
        fRet= false;
        goto finish;
    }   

    // shared secret= hmacsha1(m_rgSRKAuth, evenosap||oddosap)
    if(!hmac_sha1(osap, 40, m_rgSRKAuth, 20, shared_secret)) {
        fprintf(g_logFile, "hmacsha1 failed in sealData\n");
        fRet= false;
        goto finish;
    }

    // enc_auth= XOR(authdata, sha1(shared_secret || last_even_nonce)) 
    oSha1.Init();
    oSha1.Update(shared_secret, 20);
    oSha1.Update(nonce_even, 20);
    oSha1.Final();
    oSha1.getDigest(authdata);
    myXOR(20, encauth, authdata, m_rgSRKAuth);

    // now calculate pubauth
    //  pubauth= hmac(sharedsecret, digest||nonceeven||nonceodd||cont_session)
    //  digest= Sha1(ordinal||encauth||pcrinfosize||pcrinfo||insize||in)
    Load(true, inparams, &inparamsize, (byte*)&ord, sizeof(u32));
    Load(false, inparams, &inparamsize, encauth, 20);
    Load(true, inparams, &inparamsize, (byte*)&pcrinfosize, sizeof(u32));
    Loadpcrinfolong(inparams, &inparamsize, (byte*)&pcrinfo);
    Load(true, inparams, &inparamsize, (byte*)&sizetoSeal, sizeof(u32));
    Load(false, inparams, &inparamsize, (byte*)tosealData, sizetoSeal);
    oSha1.Init();
    oSha1.Update(inparams, inparamsize);
    oSha1.Final();
    oSha1.getDigest(digest);
    inparamsize= 0;
    Load(false, inparams, &inparamsize, digest, 20);
    Load(false, inparams, &inparamsize, nonce_even, 20);
    Load(false, inparams, &inparamsize, nonce_odd, 20);
    Load(false, inparams, &inparamsize, &contsession, 1);
    if(!hmac_sha1(inparams, inparamsize, shared_secret, 20, pubauth)) {
        fprintf(g_logFile, "hmacsha1 pubauth failed in sealData\n");
        fRet= false;
        goto finish;
    }
#ifdef TPMTEST
    fprintf(g_logFile, "size of pcrinfo: %d\n", pcrinfosize);
    PrintBytes("pcrinfo: ", (byte*)&pcrinfo, pcrinfosize);
    fprintf(g_logFile, "handle from osap: %08x\n", hauth);
    PrintBytes("shared secret: ", shared_secret, 20);
    PrintBytes("encauth: ", encauth, 20);
    PrintBytes("digest: ", digest, 20);
    PrintBytes("pubauth: ", pubauth, 20);
#endif

    // send seal command
    if(!TPMseal(m_tpmfd, m_hSealKey, encauth, sizeof(pcrinfo), (byte*) &pcrinfo, 
                sizetoSeal, tosealData, hauth, psizeSealed, sealedData, 
                nonce_odd, nonce_even, contsession, pubauth)) {
        fprintf(g_logFile, "TPMseal failed in sealData\n");
        fRet= false;
        goto finish;
    }
   
finish: 
#ifdef TERMINATEHANDLES
    if(hauth!=0)
        TPMterminatehandle(m_tpmfd, hauth);
#endif
    return fRet;
}


bool tpmStatus::unsealData(unsigned sealedSize, byte* sealedData,
                           unsigned* punsealedSize, byte* unSealed)
{
    u32                 ord= TPM_ORD_UNSEAL;
    byte                osap[40];   
    byte*               even_osap= osap;
    byte*               odd_osap= &osap[20];
    byte                nonce_even[20];
    byte                nonce_odd[20];
    byte                shared_secret[20];
    byte                pubauth[20];
    u32                 hauth= 0;
    byte                contsession= false;

    u32                 hauthd= 0;
    byte                nonce_evend[20];
    byte                nonce_oddd[20];
    byte                contsessiond= false;
    byte                pubauthd[20];
    byte                resauth[20];
    byte                resauthd[20];

    Sha1                oSha1;
    int                 inparamsize= 0;
    byte                inparams[512];
    byte                digest[20];
    bool                fRet= true;

    if(!m_fSRKAuthSet) {
        fprintf(g_logFile, "SRK Auth nor set\n");
        fRet= false;
        goto finish;
    }

    memset(odd_osap,0,20);
    memset(even_osap,0,20);
    memset(nonce_even,0,20);
    memset(nonce_odd,0,20);
    memset(nonce_evend,0,20);
    memset(nonce_oddd,0,20);
    memset(pubauth,0,20);
    memset(pubauthd,0,20);
    memset(resauth,0,20);
    memset(resauthd,0,20);
    memset(inparams,0,20);

    if(!m_fSealKeyValid) {
        fprintf(g_logFile, "Sealing key invalid in unsealData\n");
        fRet= false;
        goto finish;
    }

    // TPMosap, use the old one?
    if(!TPMosap(m_tpmfd, m_locality, TPM_ET_SRK, TPM_KH_SRK, 
                odd_osap, &hauth, nonce_even, even_osap)) {
        fprintf(g_logFile, "TPM_osap failed in unsealData\n");
        fRet= false;
        goto finish;
    }   

    // shared secret= hmacsha1(m_rgSRKAuth, evenosap||oddosap)
    if(!hmac_sha1(osap, 40, m_rgSRKAuth, 20, shared_secret)) {
        fprintf(g_logFile, "hmacsha1 failed in unsealData\n");
        fRet= false;
        goto finish;
    }

    // open oaip session
    if(!TPMoiap(m_tpmfd, m_locality, &hauthd, nonce_evend)) {
        fprintf(g_logFile, "TPMoiap failed in unsealData\n");
        fRet= false;
        goto finish;
    }

#ifdef TPMTEST
    fprintf(g_logFile, "input sealed size: %d\n", sealedSize);
    PrintBytes("input sealed data\n", sealedData, sealedSize);
#endif

    // calculate auth data (parameters and data)

    // digest= sha1(ordinal || indata)
    memset(inparams,0,512);
    inparamsize= 0;
    Load(true, inparams, &inparamsize, (byte*)&ord, sizeof(u32));
    Load(false, inparams, &inparamsize, sealedData, sealedSize);
    oSha1.Init();
    oSha1.Update(inparams, inparamsize);
    oSha1.Final();
    oSha1.getDigest(digest);
#ifdef TPMTEST
    fprintf(g_logFile, "Sealed size: %d\n", sealedSize);
    PrintBytes("digest buffer: ", inparams, inparamsize);
    PrintBytes("auth data digest: ", digest, 20);
#endif

    // pubauth= hmacsha1(shared_secret,digest||nonce_even||nonce_odd||contsession)
    memset(inparams,0,512);
    inparamsize= 0;
    Load(false, inparams, &inparamsize, digest, 20);
    Load(false, inparams, &inparamsize, nonce_even, 20);
    Load(false, inparams, &inparamsize, nonce_odd, 20);
    Load(false, inparams, &inparamsize, &contsession, 1);
    if(!hmac_sha1(inparams, inparamsize, shared_secret, 20, pubauth)) {
        fprintf(g_logFile, "hmacsha1 failed in unsealData\n");
        fRet= false;
        goto finish;
    }
#ifdef TPMTEST
    PrintBytes("pubauth buffer: ", inparams, inparamsize);
    PrintBytes("pubauth: ", pubauth, 20);
#endif

    // pubauthd= hmacsha1(authSRK, digest||nonce_evend||nonce_oddd||contsessiond)
    memset(inparams,0,512);
    inparamsize= 0;
    Load(false, inparams, &inparamsize, digest, 20);
    Load(false, inparams, &inparamsize, nonce_evend, 20);
    Load(false, inparams, &inparamsize, nonce_oddd, 20);
    Load(false, inparams, &inparamsize, &contsessiond, 1);
    if(!hmac_sha1(inparams, inparamsize, m_rgSRKAuth, 20, pubauthd)) {
        fprintf(g_logFile, "hmacsha1 failed in unsealData\n");
        fRet= false;
        goto finish;
    }
#ifdef TPMTEST
    PrintBytes("pubauthd buffer: ", inparams, inparamsize);
    PrintBytes("pubauthd: ", pubauthd, 20);
#endif

    // send unseal command
    if(!TPMunseal(m_tpmfd, m_hSealKey, hauth, nonce_odd, contsession,
                  pubauth, hauthd, nonce_oddd, contsessiond, pubauthd,
                  20, shared_secret, nonce_even, resauth, 
                  sealedSize, sealedData, punsealedSize, unSealed,
                  nonce_evend, resauthd)) {
        fprintf(g_logFile, "TPMunseal failed in unsealData\n");
        fRet= false;
        goto finish;
    }
   
finish: 
#ifdef TERMINATEHANDLES
    if(hauth!=0)
        TPMterminatehandle(m_tpmfd, hauth);
    if(hauthd!=0)
        TPMterminatehandle(m_tpmfd, hauthd);
#endif
    return fRet;
}


bool tpmStatus::quoteData(unsigned sizequoteData, byte* toquoteData,
                          unsigned* pquotedSize, byte* quotedData)
{
    bool                fRet= true;
    u32                 ord= TPM_ORD_QUOTE2;
    byte                osap[40];   
    byte*               even_osap= osap;
    byte*               odd_osap= &osap[20];
    byte                nonce_even[20];
    byte                nonce_odd[20];
    byte                shared_secret[20];
    byte                authdata[20];
    byte                encauth[20];
    byte                privauth[20];
    byte                resauth[20];
    u32                 hauth= 0;
    byte                contsession= 0;
    int                 inparamsize= 0;
    byte                inparams[256];
    byte                digest[20];
    tpm_pcr_selection   pcrselect;
    int                 pcrinfosize;
    tpm_pcrinfo_short   pcrinfo;
    bool                addVer= false;
    int                 versionsize;
    byte                versioninfo[32];
    Sha1                oSha1;

    if(m_fQuoteKeyValid) {
        fprintf(g_logFile, "quote key not valid\n");
        fRet= false;
        goto finish;
    }

    memset(odd_osap,0,20);
    memset(even_osap,0,20);
    memset(nonce_even,0,20);
    memset(nonce_odd,0,20);

    // TPMosap for key auth
    if(!TPMosap(m_tpmfd, m_locality, TPM_ET_KEYHANDLE, m_hQuoteKey,
                odd_osap, &hauth, nonce_even, even_osap)) {
        fprintf(g_logFile, "TPM_osap failed in quoteData\n");
        fRet= false;
        goto finish;
    }   

    // pcr selection
    pcrselect.m_size= 3;
    for(int i=0; i<3; i++)
        pcrselect.m_mask[i]= m_rgpcrMask[i];

    // shared secret= hmacsha1(m_szSRKSecret, evenosap||oddosap)
    if(!hmac_sha1(osap, 40, m_rgSRKAuth, 20, shared_secret)) {
        fprintf(g_logFile, "hmacsha1 failed in quoteData\n");
        fRet= false;
        goto finish;
    }

    // enc_auth= XOR(authdata, sha1(shared_secret || last_even_nonce)) 
    oSha1.Init();
    oSha1.Update(shared_secret, 20);
    oSha1.Update(nonce_even, 20);
    oSha1.Final();
    oSha1.getDigest(authdata);
    myXOR(20, encauth, authdata, m_rgSRKAuth);

    // now calculate pubauth
    //  privauth= hmac(sharedsecret, digest||nonceeven||nonceodd||cont_session)
    //  digest= Sha1(ordinal||encauth||pcrinfosize||pcrinfo||insize||in)
    Load(true, inparams, &inparamsize, (byte*)&ord, sizeof(u32));
    Load(false, inparams, &inparamsize, (byte*)toquoteData, sizequoteData);
    Loadpcrelection(inparams, &inparamsize, (byte*)&pcrselect);
    Load(false, inparams, &inparamsize, (byte*)&addVer, sizeof(byte));
    oSha1.Init();
    oSha1.Update(inparams, inparamsize);
    oSha1.Final();
    oSha1.getDigest(digest);
    inparamsize= 0;
    Load(false, inparams, &inparamsize, digest, 20);
    Load(false, inparams, &inparamsize, nonce_even, 20);
    Load(false, inparams, &inparamsize, nonce_odd, 20);
    Load(false, inparams, &inparamsize, &contsession, 1);
    if(!hmac_sha1(inparams, inparamsize, shared_secret, 20, privauth)) {
        fprintf(g_logFile, "hmacsha1 privauth failed in quoteData\n");
        fRet= false;
        goto finish;
    }
#ifdef TPMTEST
    fprintf(g_logFile, "size of pcrselection: %d\n", pcrselectsize);
    PrintBytes("pcrselect: ", (byte*)&pcrselect, pcrselectsize);
    fprintf(g_logFile, "handle from osap: %08x\n", hauth);
    PrintBytes("shared secret: ", shared_secret, 20);
    PrintBytes("encauth: ", encauth, 20);
    PrintBytes("digest: ", digest, 20);
    PrintBytes("privauth: ", privauth, 20);
#endif

    if(!TPMquote2(m_tpmfd, m_hQuoteKey, toquoteData, sizeof(pcrselect), 
               (byte*)&pcrselect, addVer, hauth, &pcrinfosize, (byte*)&pcrinfo,
               (int*)pquotedSize, quotedData, &versionsize, versioninfo, 
               nonce_even, nonce_odd, contsession, privauth, resauth)) {
        fprintf(g_logFile, "TPMquote2 failed\n");
        fRet= false;
        goto finish;
    }

finish:
#ifdef TERMINATEHANDLES
    if(hauth!=0)
        TPMterminatehandle(m_tpmfd, hauth);
#endif
    return fRet;
}


int tpmStatus::getRandom(int size, byte* puData)
{
    return TPMgetRandom(m_tpmfd, size, puData);
}


bool tpmStatus::closeTPM()
{
    m_fTPMInitialized= false;
    close(m_tpmfd);
    return true;
}


// --------------------------------------------------------------------------


bool tpmStatus::makeAIK(int numCerts, byte** rgpCerts, 
                        const char* pcaFile, const char* reqFile, 
                        const char* aikBlobFile, const char* aikPKFile)
//
//  Note:  This function does not assume an inited tpmStatus object
//
{
    return false;
}


bool tpmStatus::getAIKKey(const char* aikBlobFile, const char* aikCertFile)
{
#ifdef TEST
    if(aikCertFile==NULL)
        fprintf(g_logFile, "tpmStatus::getAIKKey(%s), no certfile\n", aikCertFile);
    else
        fprintf(g_logFile, "tpmStatus::getAIKKey(%s, %s)\n", aikBlobFile, aikCertFile);
    fflush(g_logFile);
#endif
    if(aikBlobFile==NULL) {
        fprintf(g_logFile, "No AIK Blob file\n");
        return false;
    }

    byte    aikBuf[2048];
    int     aikSize= 2048;

    //  Key Blob in file
    if(!getBlobfromFile(aikBlobFile, aikBuf, &aikSize)) {
        fprintf(g_logFile, "Can't get AIK from file %s\n", aikBlobFile);
        return false;
    }

#ifdef TEST
    fprintf(g_logFile, "getAIKKey got blob %d\n", aikSize);
    fflush(g_logFile);
#endif

    if(!loadKey(KEYTYPE_AIK, aikBuf, aikSize, &m_hQuoteKey)) {
        fprintf(g_logFile, "Can't load aik\n");
        return false;
    }

#ifdef TEST
    fprintf(g_logFile, "getAIKKey loaded blob\n");
    fflush(g_logFile);
#endif

    m_faikKeyValid= true;
    m_rgAIKCert= NULL;
    if(aikCertFile!=NULL) {
        fprintf(g_logFile, "Loading AIK Cert file\n");
        m_rgAIKCert= readandstoreString(aikCertFile);
        if(m_rgAIKCert==NULL) {
            fprintf(g_logFile, "Cant read AIK key cert file\n");
            return false;
        }
    }

#ifdef TEST
    if(m_faikKeyValid) {
        fprintf(g_logFile, "\nAIK length: %d\n", m_iaikmodulusLen);
        PrintBytes("AIK modulus: ", m_rgaikmodulus, m_iaikmodulusLen);
    }
    if(m_rgAIKCert!=NULL)
        fprintf(g_logFile, "AIKCert:\n%s\n", m_rgAIKCert);
    fflush(g_logFile);
#endif

    return true;
}


bool tpmStatus::getEKInfo(const char* fileName, bool fgetKey)
{
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

    revmemcpy((byte*)bnM.m_pValue, m_rgaikmodulus, m_iaikmodulusLen);
    revmemcpy((byte*)bnC.m_pValue, (byte*) signedData, dataSize);
    bnE.m_pValue[0]= 0x10001ULL;

#ifdef TPMTEST
    fprintf(g_logFile, "\naikmodulus for verify\n");
    printNum(bnM); fprintf(g_logFile, "\n\n");
#endif

    if(!mpRSAENC(bnC, bnE, bnM, bnR)) {
        fprintf(g_logFile, "\nENC fails\n");
        return false;
    }

    byte  result[512];
    revmemcpy(result, (byte*)bnR.m_pValue, m_iaikmodulusLen);

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

#ifdef NOQUOTE2  // should never happen
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
                        SHA1DIGESTBYTESIZE, pcrDigest, false,
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
    tpmStatus   oTpm;
    unsigned    u, v;
    unsigned    locality;
    byte        rgpcr[BUFSIZE];
    byte        rgtoSeal[BUFSIZE];
    byte        rgSealed[BUFSIZE];
    byte        rgunSealed[BUFSIZE];
    byte        rgtoSign[BUFSIZE];
    byte        rgSigned[BUFSIZE];
    byte        rgRandom[BUFSIZE];
    bool        fInitAIK= false;
    const char*       reqFile= "HW/requestFile";
    const char*       aikBlobFile= "HW/aikblob";
    const char*       pcaFile= "HW/pcaBlobFile";
    const char*       aikKeyFile= "HW/aikKeyFile.txt";
    char*       ownerSecret= NULL;
    char*       aikCertFile= NULL;
    char*       ekCertFile= NULL;
    int         i, n;
    int         size;

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
                fprintf(g_logFile, "vTCIDirect.exe -initAIK -ownerSecret secret -AIKBlob blobfile -AIKCertFile file -ekCertFile file\n");
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

    if(!oTpm.setSRKauth(NULL)) {
        fprintf(g_logFile, "can't set SRK auth\n");
        return false;
    }

    if(fInitAIK) {
        if(!oTpm.setTPMauth(ownerSecret)) {
            fprintf(g_logFile, "can't set TPM auth\n");
            return false;
        }
        fprintf(g_logFile, "Initing AIK Key\n");
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
    if((n=oTpm.getRandom(16, rgRandom))>=0) {
        fprintf(g_logFile, "\ngetRandom succeeded got %d bytes\n", n);
        PrintBytes("Random bytes: ", rgRandom, 16);
    }
    else {
        fprintf(g_logFile, "\ngetRandom failed\n");
        return 1;
    }

    int pcrno= 17;
    size= BUFSIZE;
    if(oTpm.getPCRValue(pcrno, &size, rgpcr)) {
        fprintf(g_logFile, "\ngetPCRValue, pcr %d, succeeded\n", pcrno);
        PrintBytes("PCR contents: ", rgpcr, 20);
    }
    else {
        fprintf(g_logFile, "\ngetRandom succeeded got %d bytes\n", n);
    }
    memcpy(oTpm.m_rgpcrS,rgpcr,20);
#ifdef PCR18
    pcrno= 18;
    size= BUFSIZE;
    if(oTpm.getPCRValue(pcrno, &size, rgpcr)) {
        fprintf(g_logFile, "\ngetPCRValue, pcr %d, succeeded\n", pcrno);
        PrintBytes("PCR contents: ", rgpcr, 20);
    }
    else {
        fprintf(g_logFile, "\ngetRandom succeeded got %d bytes\n", n);
    }
    memcpy(&oTpm.m_rgpcrS[20],rgpcr,20);
    oTpm.m_rgpcrSValid= true;
#else
    oTpm.m_rgpcrSValid= true;
#endif

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

    // TPM Policy
    if(ownerSecret!=NULL) {
        if(!oTpm.setTPMauth(ownerSecret))
            return false;
    }
    fprintf(g_logFile, "setTPMauth succeeded\n");

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
    }

    
    u= BUFSIZE;
    byte    nonce[20];
    u32     sizetoquote= 20;
    memset(nonce,0,sizeof(nonce));
    if(oTpm.quoteData(sizeof(nonce), nonce, &u, rgSigned)) {
        fprintf(g_logFile, "\nquoteData succeeded\n");
        PrintBytes("\nData to quote\n", nonce, 20);
        PrintBytes("Quoted bytes\n", rgSigned, u);
    }
    else {
        fprintf(g_logFile, "\nquoteData failed\n");
    }

    if(oTpm.m_fpcrSelectionValid && oTpm.m_rgpcrSValid) {
        bool fR= oTpm.verifyQuote(u, rgSigned, oTpm.m_rgpcrMask, oTpm.m_rgpcrS, 
                             oTpm.m_locality, sizetoquote, nonce, false, 0, NULL);

        if(fR)
            fprintf(g_logFile, "verify returns true\n");
        else
            fprintf(g_logFile, "verify returns false\n");
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


