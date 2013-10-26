//  File: taoEnvironment.cpp
//      John Manferdelli
//  Description: trusted primitives for this code identity (seal, unseal, attest)
//               This is the revised version after the paper
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


#include "jlmTypes.h"
#include "logging.h"
#include "jlmcrypto.h"
#include "jlmUtility.h"
#include "modesandpadding.h"
#include "bignum.h"
#include "sha256.h"
#include "tao.h"
#include "bignum.h"
#include "mpFunctions.h"
#include "cryptoHelper.h"
#include "trustedKeyNego.h"

#ifdef TPMSUPPORT
#include "TPMHostsupport.h"
#endif

extern int            g_szpolicykeySize;
extern char           g_szXmlPolicyCert[];

#include "hashprep.h"
#include "linuxHostsupport.h"

#include <string.h>
#include <time.h>
#include <unistd.h>


// -------------------------------------------------------------------------
#ifndef  VALIDATEATTESTONLY


taoEnvironment::taoEnvironment()
{
    m_envType= PLATFORMTYPENONE;
    m_envValid= false;

    m_domain= NULL;
    m_program= NULL;
    m_machine= NULL;

    m_sealedsymKeyValid= false;
    m_sealedsymKeySize= 0;
    m_sealedsymKey= NULL;
    m_symKeyValid= false;
    m_symKeyType= KEYTYPENONE;
    m_symKeySize= 0;
    m_symKey= NULL;

    m_sealedprivateKeyValid= false;
    m_sealedprivateKeySize= 0;
    m_sealedprivateKey= NULL;
    m_privateKeyValid= false;
    m_privateKeyType= KEYTYPENONE;
    m_privateKeySize= 0;
    m_privateKey= NULL;

    m_myMeasurementValid= false;
    m_myMeasurementType= HASHTYPENONE;
    m_myMeasurementSize= 0;
    m_myMeasurement= NULL;

    m_myCertificateValid= false;
    m_myCertificateType= EVIDENCENONE;
    m_myCertificateSize= 0;
    m_myCertificate= NULL;

    m_ancestorEvidenceValid= false;
    m_ancestorEvidenceSize= 0;
    m_ancestorEvidence= NULL;

    m_publicKeyValid= false;
    m_publicKeySize= 0;
    m_publicKey= NULL;

    m_serializedpublicKeySize= 0;
    m_serializedpublicKey= NULL;
    m_publicKeyBlockSize= 0;

    m_szPrivateKeyName= NULL;
    m_szPrivateSubjectName= NULL;
    m_szPrivateSubjectId= NULL;

    m_serializedprivateKeySize= 0;
    m_serializedprivateKey= NULL;
}


taoEnvironment::~taoEnvironment()
{
}


#ifdef TEST
void taoEnvironment::printData()
{
    if(m_envValid)
        fprintf(g_logFile, "\ttaoEnvironment valid\n");
    else
        fprintf(g_logFile, "\ttaoEnvironment invalid\n");
    fprintf(g_logFile, "\ttaoEnvironment type: %08x\n", m_envType);
    m_fileNames.printAll();
    if(m_myMeasurementValid) {
        fprintf(g_logFile, "\tMeasurement valid\n");
        fprintf(g_logFile, "\tMeasurement type: %08x, size: %d\n",
                        m_myMeasurementType, m_myMeasurementSize);
        PrintBytes("Measurement: ", m_myMeasurement, m_myMeasurementSize);
    }
    else
        fprintf(g_logFile, "\tMeasurement invalid\n");
    if(m_sealedsymKeyValid) {
        fprintf(g_logFile, "\tSealed sym key valid\n");
        fprintf(g_logFile, "\tSealed sym key size: %d\n", m_sealedsymKeySize);
        PrintBytes("Sealed sym key:\n", m_sealedsymKey, m_sealedsymKeySize);
    }
    else
        fprintf(g_logFile, "\tSealed sym key invalid\n");
    if(m_sealedprivateKeyValid) {
        fprintf(g_logFile, "\tSealed private key valid\n");
        fprintf(g_logFile, "\tSealed private key size: %d\n",
                m_sealedprivateKeySize);
#ifdef TEST1
        PrintBytes("Sealed private key: ",
                    m_sealedprivateKey, m_sealedprivateKeySize);
#endif
    }
    else
        fprintf(g_logFile, "\tSealed private key invalid\n");
    if(m_symKeyValid) {
        fprintf(g_logFile, "\tSym key valid\n");
        fprintf(g_logFile, "\tSym key size: %d\n", m_symKeySize);
#ifdef TEST1
        PrintBytes("Sym key: ", m_symKey, m_symKeySize);
#endif
    }
    else
        fprintf(g_logFile, "\tSym key invalid\n");
    if(m_policyKeyValid) {
        fprintf(g_logFile, "\tPolicy key valid\n");
        fprintf(g_logFile, "\tPolicy key type: %08x, size: %d\n",
                        m_policyKeyType, m_sizepolicyKey);
#ifdef TEST1
        PrintBytes("Policy: ", m_policyKey, m_sizepolicyKey);
#endif
    }
    else
        fprintf(g_logFile, "\tPolicy invalid\n");
    if(m_privateKeyValid) {
        fprintf(g_logFile, "\tPrivate key valid\n");
        fprintf(g_logFile, "\tPrivate key type: %08x, size: %d\n",
                        m_privateKeyType, m_privateKeySize);
#ifdef TEST1
        PrintBytes("Private key: ", m_privateKey, m_privateKeySize);
#endif
    }
    else
        fprintf(g_logFile, "\tPrivate key invalid\n");

    fprintf(g_logFile, "\tPublic key size: %d, block size: %d\n", 
            m_publicKeySize, m_publicKeyBlockSize);
#ifdef TEST1
    PrintBytes("Public key: ", (byte*)m_publicKey, m_publicKeySize);
#endif
    if(m_myCertificateValid) {
        fprintf(g_logFile, "\tCertificate valid\n");
        fprintf(g_logFile, "\tCertificate type: %08x, size: %d\n%s\n",
                m_myCertificateType, m_myCertificateSize, m_myCertificate);
    }
    else
        fprintf(g_logFile, "\tCertificate invalid\n");
    if(m_ancestorEvidenceValid) {
        fprintf(g_logFile, "\tEvidence valid\n");
        fprintf(g_logFile, "\tEvidence size: %d\n", m_ancestorEvidenceSize);
        fprintf(g_logFile, "\tEvidence:\n%s\n", m_ancestorEvidence);
    }
    else
        fprintf(g_logFile, "\tEvidence invalid\n");
    fflush(g_logFile);
}
#endif


bool taoEnvironment::EnvInit(u32 type, const char* program, const char* domain, 
                             const char* directory, const char* subdirectory, 
                             taoHostServices* host, 
                             const char* serviceProvider, int nArgs, char** rgszParameter)
{
    char    szhostName[256];    // FIX
    int     n= 256;             // FIX

#ifdef TEST
    fprintf(g_logFile, "taoEnvironment::EnvInit: %04x, %s, %s, %s, %s, %s\n",
            type, program, domain, directory, directory, serviceProvider);
#endif
    m_envValid= false;
    m_envType= type;

    if(program==NULL)
        return false;
    m_program= strdup(program);
    if(domain==NULL)
        return false;
    m_domain= strdup(domain);

    if(gethostname(szhostName, n)==0) {
        m_machine= strdup(szhostName);
    }
    else {
        m_machine= strdup("NoName");
    } 
    if(!initKeyNames()) {
        fprintf(g_logFile, "taoEnvironment::EnvInit: cant init key names\n");
        return false;
    }
#ifdef TEST
    fprintf(g_logFile, "taoEnvironment::EnvInit, host: %s\n\tkeynames: %s, %s, %s\n",
            m_machine, m_szPrivateKeyName, 
            m_szPrivateSubjectName, m_szPrivateSubjectId);
#endif

    // Host should already be initialized
    if(host==NULL) {
        fprintf(g_logFile, "taoEnvironment::EnvInit: no host\n");
        return false;
    }
    m_myHost= host;

    // initialize file names
    if(!m_fileNames.initNames(directory, subdirectory)) {
        fprintf(g_logFile, "taoEnvironment::EnvInit: cant init names\n");
        return false;
    }
#ifdef TEST
    fprintf(g_logFile, "taoEnvironment::EnvInit, file names\n");
    m_fileNames.printAll();
    fflush(g_logFile);
#endif

    switch(type) {
      default:
      case PLATFORMTYPEHYPERVISOR:
        return false;

      case PLATFORMTYPEKVMHYPERVISOR:
        // service provider is kvmtciodd
      case PLATFORMTYPELINUX:
      case PLATFORMTYPEKVMHOSTEDLINUXGUESTOS:
        // service provider is tciodd
        if(!m_linuxEnvChannel.initLinuxService(serviceProvider, true)) {
            fprintf(g_logFile, "taoEnvironment::EnvInit: cant init linuxService\n");
            return false;
        }
#ifdef TEST
        fprintf(g_logFile, "taoEnvironment::EnvInit, linux service initialized %s\n",
                serviceProvider);
        fflush(g_logFile);
#endif
        break;
      case PLATFORMTYPELINUXAPP:
        // direct call, nothing to open
        break;
    }

    // get policy key
    if(!GetPolicyKey()) {
        fprintf(g_logFile, "taoEnvironment::EnvInit: cant get policy key\n");
        return false;
    }
#ifdef TEST
    fprintf(g_logFile, "taoEnvironment::EnvInit, policy key initialized\n");
    fflush(g_logFile);
#endif

    if(firstRun()) {
#ifdef TEST
        fprintf(g_logFile, "taoEnvironment::EnvInit, firstRun\n");
        m_fileNames.printAll();
#endif

#if TAOUSERSA1024
        if(!initTao(KEYTYPEAES128PAIREDENCRYPTINTEGRITY, KEYTYPERSA1024INTERNALSTRUCT)) 
#endif
#if TAOUSERSA2048
        if(!initTao(KEYTYPEAES128PAIREDENCRYPTINTEGRITY, KEYTYPERSA2048INTERNALSTRUCT))
#endif
        {
            fprintf(g_logFile, "taoEnvironment::EnvInit: cant init Tao\n");
            return false;
        }
#ifdef TEST
        fprintf(g_logFile, "taoEnvironment::initTao succeeded\n");
#endif
        if(!saveTao()) {
            fprintf(g_logFile, "taoEnvironment::EnvInit: cant save Tao\n");
            return false;
        }
#ifdef TEST
        fprintf(g_logFile, "taoEnvironment::initTao saveKeys succeeded\n");
#endif
    }
    else {
#ifdef TEST
        fprintf(g_logFile, "taoEnvironment::EnvInit, restore\n");
        m_fileNames.printAll();
        fflush(g_logFile);
#endif

        // get code digest
        int     sizeCodeDigest= 64;
        u32     codeDigestType= 0;
        byte    codeDigest[64];         // FIX

        if(!m_myHost->GetHostedMeasurement(&sizeCodeDigest, 
                                &codeDigestType, codeDigest)) {
            fprintf(g_logFile, "taoEnvironment::EnvInit: Can't get code digest\n");
            return false;
        }

        m_myMeasurementType= codeDigestType;
        m_myMeasurementSize= sizeCodeDigest;
        m_myMeasurement= (byte*) malloc(sizeCodeDigest);
        if(m_myMeasurement==NULL) {
            fprintf(g_logFile, "taoEnvironment::EnvInit: can't malloc code id\n");
            return false;
        }
        memcpy(m_myMeasurement, codeDigest, m_myMeasurementSize);
        m_myMeasurementValid= true;
#ifdef TEST
        fprintf(g_logFile, "taoEnvironment::EnvInit, got measurement %d %d\n",
                codeDigestType, sizeCodeDigest);
        PrintBytes("        Measurement:\n", m_myMeasurement, 
                   m_myMeasurementSize);
        fflush(g_logFile);
#endif

        if(!restoreTao()) {
            fprintf(g_logFile, "taoEnvironment::EnvInit: cant restore Tao\n");
            return false;
        }
    }
#ifdef TEST
    fprintf(g_logFile, "EnvInit succeeded\n");
    fflush(g_logFile);
#endif

    m_envValid= true;
    return true;
}


bool taoEnvironment::EnvClose()
{
    switch(m_envType) {
      case PLATFORMTYPEKVMHYPERVISOR:
      case PLATFORMTYPEKVMHOSTEDLINUXGUESTOS:
      case PLATFORMTYPELINUX:
      case PLATFORMTYPEGUESTLINUX:
        m_linuxEnvChannel.closeLinuxService();
        return true;
    }
    return false;
}


bool taoEnvironment::firstRun()
{
    struct stat statBlock;

    if(m_fileNames.m_szsymFile==NULL || m_fileNames.m_szprivateFile==NULL ||
                           m_fileNames.m_szcertFile==NULL)
        return false;
    if(stat(m_fileNames.m_szprivateFile, &statBlock)<0)
        return true;
    if(stat(m_fileNames.m_szcertFile, &statBlock)<0)
        return true;
    if(stat(m_fileNames.m_szsymFile, &statBlock)<0)
        return true;

    return false;
}


bool taoEnvironment::InitMyMeasurement()
{
    int     size= 256;  // FIX
    byte    tbuf[256];  // FIX
    u32     type;

    if(!m_envValid)
        return false;

    if(m_myMeasurementValid)
        return true;
    
    if(!m_myHost->GetHostedMeasurement(&size, &type, tbuf)) 
        return false;

    m_myMeasurement= (byte*)malloc(size);
    if(m_myMeasurement==NULL)
        return false;

    m_myMeasurementType= type;
    m_myMeasurementSize= size;
    memcpy(tbuf, m_myMeasurement, size);
    m_myMeasurementValid= true;
    return true;
}


bool taoEnvironment::initKeyNames()
{
    char    szName[2048];   // FIX

#ifdef TEST
    fprintf(g_logFile, "taoEnvironment::initKeyNames\n");
    fflush(g_logFile);
#endif
    if(m_domain==NULL || m_machine==NULL) {
        fprintf(g_logFile, "taoEnvironment::initKeyNames domain or directory null\n");
        return false;
    }

    switch(m_envType) {
      case PLATFORMTYPEKVMHYPERVISOR:
      case PLATFORMTYPEKVMHOSTEDLINUXGUESTOS:
      case PLATFORMTYPELINUX:
      case PLATFORMTYPEGUESTLINUX:
        sprintf(szName, "//%s/%s/Keys/%sAttest", m_domain, m_machine, m_program);
        m_szPrivateKeyName= strdup(szName);
        sprintf(szName, "//%s/%s/Keys/%s", m_domain, m_machine, m_program);
        m_szPrivateSubjectName= strdup(szName);
        m_szPrivateSubjectId= strdup(szName);
        return true;
      case PLATFORMTYPELINUXAPP:
        sprintf(szName, "//%s/%s/Keys/%sProgram", m_domain, m_machine, m_program);
        m_szPrivateKeyName= strdup(szName);
        sprintf(szName, "//%s/%s/Keys/%s", m_domain, m_machine, m_program);
        m_szPrivateSubjectName= strdup(szName);
        m_szPrivateSubjectId= strdup(szName);
        return true;
    }
    return false;
}


bool taoEnvironment::GetMyMeasurement(int* psize, u32* ptype, byte* buf)
{
    if(!m_envValid)
        return false;

    if(m_myMeasurementValid) {
        if(*psize<m_myMeasurementSize)
            return false;
        *psize= m_myMeasurementSize;
        memcpy(buf, m_myMeasurement, *psize);
        return true;
    }
    if(!InitMyMeasurement())
        return false;
    return GetMyMeasurement(psize, ptype, buf);
}


bool taoEnvironment::GetHostedMeasurement(int pid, int* psize, u32* ptype, byte* buf)
{
    // done in tcService
    return false;
}


bool taoEnvironment::StartHostedProgram(const char* name, int an, char** av, int* phandle)
{
    // done in tcService
    return false;
}


bool taoEnvironment::GetEntropy(int size, byte* buf)
{
    // for now, just get bits from system
    // later, this should include a PRNG seeded by host entropy
    return getCryptoRandom(size*NBITSINBYTE, buf);
}


bool taoEnvironment::Seal(int hostedMeasurementSize, byte* hostedMeasurement,
                        int sizetoSeal, byte* toSeal, int* psizeSealed, byte* sealed)
{  
    byte    tmpout[4096];   // FIX

#ifdef TEST
    fprintf(g_logFile, "taoEnvironment::Seal, in %d, out %d\n", 
            sizetoSeal, *psizeSealed);
    fflush(g_logFile);
#endif
    if(!m_symKeyValid) {
        fprintf(g_logFile, "taoEnvironment::Seal, seal key invalid\n");
        return false;
    }

    if((2*sizeof(int)+sizetoSeal+hostedMeasurementSize)>4096) {
        fprintf(g_logFile, "taoEnvironment::Seal, buffer too small\n");
        return false;
    }

    // tmpout is hashsize||hash||sealdatasize||sealeddata
    int     n= 0;
    memcpy(&tmpout[n], &hostedMeasurementSize, sizeof(int));
    n+= sizeof(int);
    memcpy(&tmpout[n], hostedMeasurement, hostedMeasurementSize);
    n+= hostedMeasurementSize;
#ifdef TEST
    fprintf(g_logFile, "Sealing data length %d\n", sizetoSeal);
#endif
    memcpy(&tmpout[n], &sizetoSeal, sizeof(int));
    n+= sizeof(int);
    memcpy(&tmpout[n], toSeal, sizetoSeal);
    n+= sizetoSeal;

#ifdef TEST
    fprintf(g_logFile, "taoEnvironment::Seal, about to encryptBlob, n=%d\n",
            n);
    PrintBytes("To Seal: ", tmpout, n);
    fflush(g_logFile);
#endif
    if(!AES128CBCHMACSHA256SYMPADEncryptBlob(n, tmpout, psizeSealed, sealed,
                                    m_symKey, &m_symKey[AES128BYTEBLOCKSIZE])) {
        fprintf(g_logFile, "taoEnvironment::seal: AES128CBCHMACSHA256SYMPADEncryptBlob failed\n");
        return false;
    }

    PrintBytes("Encrypted Blob: ", sealed, *psizeSealed);
    return true;
}


bool taoEnvironment::Unseal(int hostedMeasurementSize, byte* hostedMeasurement,
                        int sizeSealed, byte* sealed, int *psizeunsealed, byte* unsealed)
{
    int     n= 0;
    int     outsize= 4096;  // FIX
    byte    tmpout[4096];   // FIX
    int     hashsize= 0;

#ifdef TEST
    fprintf(g_logFile, "taoEnvironment::Unseal\n");
#endif
    if(!m_symKeyValid) {
        fprintf(g_logFile, "taoEnvironment::Unseal, seal key invalid\n");
        return false;
    }
#ifdef TEST
    fprintf(g_logFile, "Attempting decryption\n");
    fflush(g_logFile);
#endif
    if(!AES128CBCHMACSHA256SYMPADDecryptBlob(sizeSealed, sealed, &outsize, tmpout, 
                        m_symKey, &m_symKey[AES128BYTEBLOCKSIZE])) {
        fprintf(g_logFile, 
           "taoEnvironment::unseal: AES128CBCHMACSHA256SYMPADDecryptBlob failed\n");
        return false;
    }
#ifdef TEST
    fprintf(g_logFile, "Decryption succeeded with size %d\n", outsize);
    fflush(g_logFile);
#endif

    // tmpout is hashsize||hash||sealdatasize||sealeddata
    memcpy(&hashsize, &tmpout[n], sizeof(int));
    n+= sizeof(int);
#ifdef TEST
    fprintf(g_logFile, "Got hashsize = %d\n", hashsize);
    fflush(g_logFile);
#endif

    if(hashsize!=hostedMeasurementSize) {
        fprintf(g_logFile, "Wrong measurement size: %d vs %d\n", hashsize,
                hostedMeasurementSize);
        return false;
    } else {
        fprintf(g_logFile, "The hash sizes match\n");
        fflush(g_logFile);
    }
    
#ifdef TEST
    fprintf(g_logFile, "tmpout is %p\n", tmpout);
    fprintf(g_logFile, "Comparing %p with %p of length %d\n", tmpout + n,
            hostedMeasurement, hashsize);
    PrintBytes("left meas:  ", &tmpout[n], hashsize);
    PrintBytes("right meas: ", hostedMeasurement, hashsize);
    fflush(g_logFile);
#endif
     
    if (memcmp(&tmpout[n], hostedMeasurement, hashsize) != 0) {
        fprintf(g_logFile, "The measurements don't match\n");
        return false;
    }
    n += hashsize;
#ifdef TEST
    fprintf(g_logFile, "The hashes match. Copying an int into %p\n", psizeunsealed);
    fflush(g_logFile);
#endif

    memcpy(psizeunsealed, &tmpout[n], sizeof(int));
#ifdef TEST
    fprintf(g_logFile, "Got unsealed size %d\n", *psizeunsealed);
    fflush(g_logFile);
#endif
    n+= sizeof(int);
    memcpy(unsealed, &tmpout[n], *psizeunsealed);
    return true;
}


bool taoEnvironment::Attest(int hostedMeasurementSize, byte* hostedMeasurement,
                        int sizetoAttest, byte* toAttest, int* psizeAttested, byte* attest)
{
#ifdef TEST
    fprintf(g_logFile, "taoEnvironment::Attest\n");
    fflush(g_logFile);
#endif
    if(!m_privateKeyValid)
        return false;

    if(*psizeAttested<m_publicKeyBlockSize)
        return false;

    byte        rgQuotedHash[SHA256DIGESTBYTESIZE];
    byte        rgToSign[512];  // FIX

    // Compute quote
    if(!sha256quoteHash(0, NULL, sizetoAttest, toAttest, hostedMeasurementSize, 
                        hostedMeasurement, rgQuotedHash)) {
            fprintf(g_logFile, "taoEnvironment::Attest: Cant compute sha256 quote hash\n");
            return false;
        }
    // pad
    if(!emsapkcspad(SHA256HASH, rgQuotedHash, m_publicKeyBlockSize, rgToSign)) {
        fprintf(g_logFile, "taoEnvironment::Attest: emsapkcspad returned false\n");
        return false;
    }
    // sign
    RSAKey* pRSA= (RSAKey*) m_privateKey;   // FIX
    bnum    bnMsg(m_publicKeyBlockSize/sizeof(u64));
    bnum    bnOut(m_publicKeyBlockSize/sizeof(u64));
    memset(bnMsg.m_pValue, 0, m_publicKeyBlockSize);
    memset(bnOut.m_pValue, 0, m_publicKeyBlockSize);
    revmemcpy((byte*)bnMsg.m_pValue, rgToSign, m_publicKeyBlockSize);
#ifdef TEST
    fprintf(g_logFile, "taoEnvironment::Attest about to decrypt, blocksize: %d\n", 
            m_publicKeyBlockSize);
    PrintBytes((char*)"ToSign: ", rgToSign, m_publicKeyBlockSize);
    pRSA->printMe();
    fflush(g_logFile);
#endif

    if(pRSA->m_pbnQ!=NULL && pRSA->m_pbnP!=NULL && pRSA->m_pbnDQ!=NULL && 
       pRSA->m_pbnDP!=NULL && pRSA->m_pbnQM1!=NULL && pRSA->m_pbnPM1!=NULL) {
        if(!mpRSADEC(bnMsg, *(pRSA->m_pbnP), *(pRSA->m_pbnPM1), *(pRSA->m_pbnDP), 
                     *(pRSA->m_pbnQ), *(pRSA->m_pbnQM1), *(pRSA->m_pbnDQ), 
                     *(pRSA->m_pbnM), bnOut)) {
            fprintf(g_logFile, "taoEnvironment::Attest: mpRSADEC returned false\n");
            return false;
        }
    }
    else {
        if(!mpRSAENC(bnMsg, *(pRSA->m_pbnD), *(pRSA->m_pbnM), bnOut)) {
            fprintf(g_logFile, "taoEnvironment::Attest: mpRSAENC returned false\n");
            return false;
        }
    }

#ifdef TEST
    fprintf(g_logFile, "taoEnvironment::Attest succeeded, m_publicKeyBlockSize: %d\n",
            m_publicKeyBlockSize);
    fflush(g_logFile);
#endif
    memcpy(attest, bnOut.m_pValue, m_publicKeyBlockSize);
    *psizeAttested= m_publicKeyBlockSize;
    return true;
}


bool taoEnvironment::GetPolicyKey()
{
#ifdef TEST
    fprintf(g_logFile, "taoEnvironment::GetPolicyKey(), environment: %d\n",
            m_envType);
    fflush(g_logFile);
#endif
    switch(m_envType) {
      default:
        fprintf(g_logFile, "taoEnvironment::GetPolicyKey, unsupported environment\n");
        return false;

      case PLATFORMTYPEKVMHYPERVISOR:
      case PLATFORMTYPEKVMHOSTEDLINUXGUESTOS:
      case PLATFORMTYPELINUX:
      case PLATFORMTYPEGUESTLINUX:
      case PLATFORMTYPELINUXAPP:
#ifdef TEST
        fprintf(g_logFile, "policy key from image %d\n", g_szpolicykeySize);
        fprintf(g_logFile, "policy key from image %s\n", g_szXmlPolicyCert);
        fflush(g_logFile);
#endif
        m_policyKey= (byte*) malloc(g_szpolicykeySize);
        if(m_policyKey==NULL) {
            fprintf(g_logFile, "taoEnvironment::GetPolicyKey, malloc failed\n");
            return false;
        }
        memcpy(m_policyKey, (byte*)g_szXmlPolicyCert, g_szpolicykeySize);
        m_sizepolicyKey= g_szpolicykeySize;
        m_policyKeyType= EVIDENCECERT;
        m_policyKeyValid= true;
        return true;
    }
}


bool taoEnvironment::initTao(u32 symType, u32 pubkeyType)
{
    bool        fRet= false;
    taoInit     myInit(m_myHost);

#ifdef TEST
    fprintf(g_logFile, "taoEnvironment::initTao\n");
    fprintf(g_logFile, 
            "taoEnvironment::initTao, SubjectName: %s, PrivateSubjectId: %s\n",
            m_szPrivateSubjectName, m_szPrivateSubjectId);
    fflush(g_logFile);
#endif
    fRet= myInit.initKeys(symType, pubkeyType, m_szPrivateKeyName,
                          m_szPrivateSubjectName, m_szPrivateSubjectId);
    if(!fRet) {
        fprintf(g_logFile, "taoEnvironment::initTao, taoInit.initKeys returned false\n");
        return false;
    }
#ifdef TEST
    fprintf(g_logFile, "taoEnvironment::initTao taoInit.initKeys succeeded\n");
    fflush(g_logFile);
#endif

    // copy keys
    m_symKeyValid= myInit.m_symKeyValid;
    if(myInit.m_symKeyValid) {
        m_symKeyType= myInit.m_symKeyType;
        m_symKeySize= myInit.m_symKeySize;
        m_symKey= (byte*) malloc(m_symKeySize);
        if(m_symKey==NULL) {
            return false;
        }
        memcpy(m_symKey, myInit.m_symKey, m_symKeySize);
    }
#ifdef TEST1
    fprintf(g_logFile, "taoEnvironment::initTao symetric keys initialized\n");
#endif

    m_privateKeyValid= myInit.m_privateKeyValid;
    if(myInit.m_privateKeyValid) {
        m_privateKeyType= myInit.m_privateKeyType;
        m_privateKeySize= myInit.m_privateKeySize;
        m_privateKey= (byte*) malloc(m_privateKeySize);
        if(m_privateKey==NULL) {
            return false;
        }
        memcpy(m_privateKey, myInit.m_privateKey, m_privateKeySize);
    }
#ifdef TEST1
    fprintf(g_logFile, "taoEnvironment::initTao private keys initialized\n");
#endif

    m_publicKeyValid= myInit.m_publicKeyValid;
    if(myInit.m_publicKeyValid) {
        m_publicKeySize= myInit.m_publicKeySize;
        m_publicKey= myInit.m_publicKey;
    }

    m_serializedpublicKeySize= myInit.m_serializedpublicKeySize;
    m_publicKeyBlockSize= myInit.m_publicKeyBlockSize;
    m_serializedpublicKey= (char*) malloc(m_serializedpublicKeySize);
    if(m_serializedpublicKey==NULL) {
        fprintf(g_logFile, "taoEnvironment::initTao can't malloc serialized keys\n");
        return false;
    }
    memcpy(m_serializedpublicKey, myInit.m_serializedpublicKey, m_serializedpublicKeySize);
#ifdef TEST
    fprintf(g_logFile, "taoEnvironment::initTao serialized keys initialized\n");
#endif

    if(myInit.m_myCertificateValid) {
        m_myCertificateValid= myInit.m_myCertificateValid;
        m_myCertificateType= myInit.m_myCertificateType;
        m_myCertificateSize= myInit.m_myCertificateSize;
        m_myCertificate= (char*) malloc(m_myCertificateSize);
        if(m_myCertificate==NULL) {
            fprintf(g_logFile, "taoEnvironment::initTao certificate invalid\n");
            return false;
        }
        memcpy(m_myCertificate, myInit.m_myCertificate, m_myCertificateSize);
    }

    if(myInit.m_ancestorEvidenceValid) {
        m_ancestorEvidenceValid= myInit.m_ancestorEvidenceValid;
        m_ancestorEvidenceSize= myInit.m_ancestorEvidenceSize;
        m_ancestorEvidence= (byte*) malloc(myInit.m_ancestorEvidenceSize);
        if(m_ancestorEvidence==NULL) {
            fprintf(g_logFile, "taoEnvironment::initTao no ancestor evidence\n");
            return false;
        }
        memcpy(m_ancestorEvidence, myInit.m_ancestorEvidence, m_ancestorEvidenceSize);
    }

    if(myInit.m_myMeasurementValid) {
        m_myMeasurementType= myInit.m_myMeasurementType;
        m_myMeasurementSize= myInit.m_myMeasurementSize;
        m_myMeasurement= (byte*) malloc(myInit.m_myMeasurementSize);
        if(m_myMeasurement==NULL) {
            fprintf(g_logFile, "taoEnvironment::initTao can't allocate measurement\n");
            return false;
        }
        memcpy(m_myMeasurement, myInit.m_myMeasurement, myInit.m_myMeasurementSize);
        m_myMeasurementValid= true;
    }

#ifdef TEST
    fprintf(g_logFile, "taoEnvironment::initTao returning true\n");
#endif
    return true;
}


// -------------------------------------------------------------------------


bool taoEnvironment::saveTao()
{
#ifdef TEST
    fprintf(g_logFile, "taoEnvironment::saveTao\n");
#endif
    if(!m_sealedsymKeyValid) {
        if(!hostsealKey(m_symKeyType, m_symKeySize, m_symKey,
                        &m_sealedsymKeySize, &m_sealedsymKey)) {
            fprintf(g_logFile, "taoEnvironment::saveTao: cant seal sym key\n");
            return false;
        }
        m_sealedsymKeyValid= true;
    }
    if(!m_sealedprivateKeyValid) {
        if(m_serializedprivateKeySize==0 || m_serializedprivateKey==NULL) {
            if(m_privateKeyType!=KEYTYPERSA1024INTERNALSTRUCT &&
               m_privateKeyType!=KEYTYPERSA2048INTERNALSTRUCT) {
                fprintf(g_logFile, "taoEnvironment::saveTao: cant serialize private key type\n");
                return false;
            }
            m_serializedprivateKey= ((RSAKey*)m_privateKey)->SerializetoString();
            if(m_serializedprivateKey==NULL) {
                fprintf(g_logFile, "taoEnvironment::saveTao: cant serialize private key\n");
                return false;
            }
#ifdef DUMPKEYSTOLOGFORDEBUGGING
            fprintf(g_logFile, "taoEnvironment::saveTao serialized privateKey: %s\n",
                    m_serializedprivateKey);
            PrintBytes((char*)"Symmetric key: ", m_symKey, m_symKeySize);
#endif
            m_serializedprivateKeySize= strlen(m_serializedprivateKey);
            if(m_privateKeyType==KEYTYPERSA2048INTERNALSTRUCT) {
                m_serializedprivateKeyType= KEYTYPERSA2048SERIALIZED;
            }
            else if(m_privateKeyType==KEYTYPERSA1024INTERNALSTRUCT) {
                m_serializedprivateKeyType= KEYTYPERSA1024SERIALIZED;
            }
            else {
                fprintf(g_logFile, "taoEnvironment::saveTao: shouldn't happen\n");
                return false;
            }
            if(!localsealKey(m_serializedprivateKeyType, m_serializedprivateKeySize,
                            (byte*)m_serializedprivateKey, &m_sealedprivateKeySize, 
                            &m_sealedprivateKey)) {
                fprintf(g_logFile, "taoEnvironment::saveTao: cant seal private key\n");
                return false;
            }
        }
        m_sealedprivateKeyValid= true;
    }

#ifdef TEST1
    RSAKey* pK= (RSAKey*)m_privateKey;  // FIX
    if(pK->m_pbnM!=NULL) {
        fprintf(g_logFile, "M(%d, %08x): ", pK->m_pbnM->mpSize(), pK->m_pbnM);
        printNum(*(pK->m_pbnM)); fprintf(g_logFile, "\n");
    }
    if(pK->m_pbnE!=NULL) {
        fprintf(g_logFile, "E(%d, %08x): ", pK->m_pbnE->mpSize(), pK->m_pbnE);
        printNum(*(pK->m_pbnE)); fprintf(g_logFile, "\n");
    }
    if(pK->m_pbnD!=NULL) {
        fprintf(g_logFile, "D(%d, %08x): ", pK->m_pbnD->mpSize(), pK->m_pbnD);
        printNum(*(pK->m_pbnD)); fprintf(g_logFile, "\n");
    }
    if(pK->m_pbnP!=NULL) {
        fprintf(g_logFile, "P(%d, %08x): ", pK->m_pbnP->mpSize(), pK->m_pbnP);
        printNum(*(pK->m_pbnP)); fprintf(g_logFile, "\n");
    }
    if(pK->m_pbnQ!=NULL) {
        fprintf(g_logFile, "Q(%d, %08x): ", pK->m_pbnQ->mpSize(), pK->m_pbnQ);
        printNum(*(pK->m_pbnQ)); fprintf(g_logFile, "\n");
    }
#endif

    if(!m_fileNames.putBlobData(m_fileNames.m_szsymFile, m_sealedsymKeyValid, 
                                m_sealedsymKeySize, m_sealedsymKey)) {
        fprintf(g_logFile, "taoEnvironment::saveTao: cant save sealed keys\n");
        return false;
    }
    if(!m_fileNames.putBlobData(m_fileNames.m_szprivateFile, m_sealedprivateKeyValid, 
                                m_sealedprivateKeySize, m_sealedprivateKey)) {
        fprintf(g_logFile, "taoEnvironment::saveTao: cant save private key\n");
        return false;
    }
    if(!m_fileNames.putBlobData(m_fileNames.m_szcertFile, m_myCertificateValid, 
                                m_myCertificateSize, (byte*)m_myCertificate)) {
        fprintf(g_logFile, "taoEnvironment::saveTao: cant save cert\n");
        return false;
    }
    m_myCertificateType= EVIDENCECERT;
    if(!m_fileNames.putBlobData(m_fileNames.m_szAncestorEvidence, 
                                m_ancestorEvidenceValid, 
                                m_ancestorEvidenceSize, m_ancestorEvidence)) {
        fprintf(g_logFile, "taoEnvironment::saveTao: cant save evidence\n");
    }
#ifdef TEST
    fprintf(g_logFile, "taoEnvironment::saveTao returns true\n");
#endif
    return true;
}


bool taoEnvironment::restoreTao()
{
#ifdef TEST
    fprintf(g_logFile, "taoEnvironment::restoreTao\n");
    fflush(g_logFile);
#endif
    if(!m_fileNames.getBlobData(m_fileNames.m_szsymFile, &m_sealedsymKeyValid, 
                                &m_sealedsymKeySize, &m_sealedsymKey)) {
        fprintf(g_logFile, "taoEnvironment::restoreTao: cant retrieve sealed keys\n");
        return false;
    }
    if(!m_fileNames.getBlobData(m_fileNames.m_szprivateFile, &m_sealedprivateKeyValid, 
                                &m_sealedprivateKeySize, &m_sealedprivateKey)) {
        fprintf(g_logFile, "taoEnvironment::restoreTao: cant retrieve private key\n");
        return false;
    }
    if(!m_fileNames.getBlobData(m_fileNames.m_szcertFile, &m_myCertificateValid, 
                                &m_myCertificateSize, (byte**)&m_myCertificate)) {
        fprintf(g_logFile, "taoEnvironment::restoreTao: cant retrieve cert\n");
        return false;
    }
    m_myCertificateType= EVIDENCECERT;
    if(!m_fileNames.getBlobData(m_fileNames.m_szAncestorEvidence, &m_ancestorEvidenceValid, 
                                &m_ancestorEvidenceSize, &m_ancestorEvidence)) {
        fprintf(g_logFile, "taoEnvironment::restoreTao: cant retrieve evidence\n");
    }

    if(!m_symKeyValid) {
        if(!hostunsealKey(m_sealedsymKeySize, m_sealedsymKey,
                          &m_symKeyType, &m_symKeySize, &m_symKey)) {
            fprintf(g_logFile, "taoEnvironment::restoreTao: cant unseal sym key\n");
            return false;
        }
        m_symKeyValid= true;
    }
    if(!m_privateKeyValid) {
        if(!localunsealKey(m_sealedprivateKeySize, m_sealedprivateKey,
                           &m_serializedprivateKeyType, &m_serializedprivateKeySize,
                           (byte**)&m_serializedprivateKey)) {
            fprintf(g_logFile, "taoEnvironment::restoreTao: cant unseal private key\n");
            return false;
        }
        switch(m_serializedprivateKeyType) {
          case KEYTYPERSA2048SERIALIZED:
          case KEYTYPERSA2048INTERNALSTRUCT:
            m_privateKeyType= KEYTYPERSA2048INTERNALSTRUCT;
            m_publicKeyBlockSize= 256;  // FIX
            break;
          case KEYTYPERSA1024SERIALIZED:
          case KEYTYPERSA1024INTERNALSTRUCT:
            m_privateKeyType= KEYTYPERSA1024INTERNALSTRUCT;
            m_publicKeyBlockSize= 128;  // FIX
            break;
          default:
            break;
        }
        RSAKey* pKey= new RSAKey();     // FIX
        if(pKey==NULL || !(KeyInfo*)pKey->ParsefromString(m_serializedprivateKey)) {
            fprintf(g_logFile, "taoEnvironment::restoreTao: cant parse private key\n");
            return false;
        }
        if(!pKey->getDataFromDoc()) {
            fprintf(g_logFile, "taoEnvironment::restoreTao: cant getdata from key doc\n");
            return false;
        }
        m_privateKeySize= sizeof(*pKey);
        m_privateKey= (byte*) pKey;
        m_privateKeyValid= true;
    }
#ifdef TEST1
    fprintf(g_logFile, "taoEnvironment::restoreTao privatekey sealed size, %d\n", 
            m_sealedprivateKeySize);
    fprintf(g_logFile, "taoEnvironment::restoreTao serialized key\n%s\n",
            m_serializedprivateKey);
    fprintf(g_logFile, "taoEnvironment::restoreTao privatekey size, %d\n", 
            m_privateKeySize);
    PrintBytes("Private key: ", m_privateKey, m_privateKeySize);
    if(pK->m_pbnM!=NULL) {
        fprintf(g_logFile, "M(%d, %08x): ", pK->m_pbnM->mpSize(), pK->m_pbnM);
        printNum(*(pK->m_pbnM)); fprintf(g_logFile, "\n");
    }
    fflush(g_logFile);
#endif

#ifdef TEST
    fprintf(g_logFile, "taoEnvironment::restoreTao returns true\n");
#endif
    return true;
}


bool taoEnvironment::clearKey(u32* ptype, int* psize, byte** ppkey)
{
    if(m_symKey!=NULL) {
        memset(m_symKey, 0, m_symKeySize);
        free(m_symKey);
        m_symKey= NULL;
        m_symKeyValid= false;
    }
    return true;
}


bool taoEnvironment::hostsealKey(u32 type, int size, byte* key, 
                            int* psealedSize, byte** ppsealed)
{
#ifdef TEST
    fprintf(g_logFile, "taoEnvironment::hostsealKey\n");
#endif

    int         insize= size+sizeof(int)+sizeof(u32);
    byte*       rgIn= (byte*) malloc(insize);
    int         outsize= size+4096;
    byte*       rgOut= (byte*) malloc(outsize);
    int         m= 0;
    bool        fRet= true;

    if(rgIn==NULL) {
        fprintf(g_logFile, "taoEnvironment::hostsealKey, malloc failed\n");
        fRet= false;
        goto cleanup;
    }
    if(rgOut==NULL) {
        fprintf(g_logFile, "taoEnvironment::hostsealKey, malloc failed\n");
        fRet= false;
        goto cleanup;
    }

    memcpy(&rgIn[m], &type, sizeof(u32));
    m+= sizeof(u32); 
    memcpy(&rgIn[m], &size, sizeof(int));
    m+= sizeof(int); 
    memcpy(&rgIn[m], key, size);
    m+= size;

    if(!m_myHost->Seal(m, rgIn, &outsize, rgOut)) {
        fprintf(g_logFile, "taoEnvironment::hostsealKey, seal failed\n");
        fRet= false;
        goto cleanup;
    }
    *ppsealed= (byte*) malloc(outsize);
    if(*ppsealed==NULL) {
        fprintf(g_logFile, "taoEnvironment::hostsealKey, cant malloc\n");
        fRet= false;
        goto cleanup;
    }
    memcpy(*ppsealed, rgOut, outsize);
    *psealedSize= outsize;

cleanup:
    if(rgOut!=NULL)
        free(rgOut);
    if(rgIn!=NULL)
        free(rgIn);
    return fRet;
}


bool taoEnvironment::hostunsealKey(int sealedSize, byte* sealed,
                              u32* ptype, int* psize, byte** ppkey)
{
#ifdef TEST
    fprintf(g_logFile, "taoEnvironment::hostunsealKey %d, %d\n",
            sealedSize, *psize);
    fflush(g_logFile);
#endif

    int         size= sealedSize+4096;
    byte*       rgOut= (byte*) malloc(size);
    int         m= 0;
    bool        fRet= true;

    if(rgOut==NULL) {
        fprintf(g_logFile, "taoEnvironment::hostunsealKey, malloc failed (%d)\n", size);
        return false;
    }
    
    if(!m_myHost->Unseal(sealedSize, sealed, &size, rgOut)) {
        fprintf(g_logFile, "taoEnvironment::hostunsealKey, Unseal failed\n");
        fRet= false;
        goto cleanup;
    }
#ifdef TEST1
    fprintf(g_logFile, "taoEnvironment::hostunsealKey, back from unseal\n");
    PrintBytes( "unsealed:\n", rgOut, size);
    fflush(g_logFile);
#endif

    memcpy(ptype, &rgOut[m], sizeof(u32));
    m+= sizeof(u32);
    memcpy(psize, &rgOut[m], sizeof(int));
    m+= sizeof(int);
    
    *ppkey= (byte*) malloc(*psize);
    if(*ppkey==NULL) {
        fprintf(g_logFile, "taoEnvironment::hostunsealKey, malloc failed\n");
        fRet= false;
        goto cleanup;
    }
    memcpy(*ppkey, &rgOut[m], *psize);
#ifdef TEST
    fprintf(g_logFile, "taoEnvironment::hostunsealKey, succeeds\n");
    fflush(g_logFile);
#endif

cleanup:
    if(rgOut!=NULL)
        free(rgOut);
    return fRet;
}


bool taoEnvironment::localsealKey(u32 type, int size, byte* key,
                                  int* psealedSize, byte** ppsealed)
{
    int         insize= size+sizeof(int)+sizeof(u32);
    byte*       rgIn= (byte*) malloc(insize);
    int         outsize= size+4096;
    byte*       rgOut= (byte*) malloc(outsize);
    int         m= 0;
    bool        fRet= true;

#ifdef TEST
    fprintf(g_logFile, "taoEnvironment::localsealKey %d, %d\n",
            type, size);
#endif

    if(rgIn==NULL) {
        fprintf(g_logFile, "taoEnvironment::localsealKey, malloc failed\n");
        fRet= false;
        goto cleanup;
    }
    if(rgOut==NULL) {
        fprintf(g_logFile, "taoEnvironment::localsealKey, malloc failed\n");
        fRet= false;
        goto cleanup;
    }

    memcpy(&rgIn[m], &type, sizeof(u32));
    m+= sizeof(u32); 
    memcpy(&rgIn[m], &size, sizeof(int));
    m+= sizeof(int); 
    memcpy(&rgIn[m], key, size);
    m+= size;

    if(!m_symKeyValid) {
        fprintf(g_logFile, 
            "taoEnvironment::localsealKey, key invalid\n");
        fRet= false;
        goto cleanup;
    }
    if(!m_myMeasurementValid) {
        fprintf(g_logFile, 
            "taoEnvironment::localsealKey, measurement invalid\n");
        fRet= false;
        goto cleanup;
    }
    fRet= Seal(m_myMeasurementSize, m_myMeasurement,
                    m, rgIn, &outsize, rgOut);
    if(!fRet) {
        fprintf(g_logFile, "taoEnvironment::localsealKey, Seal failed\n");
        fRet= false;
        goto cleanup;
    }
    *ppsealed= (byte*) malloc(outsize);
    if(*ppsealed==NULL) {
        fprintf(g_logFile, "taoEnvironment::localsealKey, malloc failed\n");
        fRet= false;
        goto cleanup;
    }
    memcpy(*ppsealed, rgOut, outsize);
    *psealedSize= outsize;

cleanup:
    if(rgIn!=NULL)
        free(rgIn);
    if(rgOut!=NULL)
        free(rgOut);
    return fRet;
}


bool taoEnvironment::localunsealKey(int sealedSize, byte* sealed,
                                    u32* ptype, int* psize, byte** ppkey)
{
#ifdef TEST
    fprintf(g_logFile, "taoEnvironment::localunsealKey\n");
#endif

    int         outsize= sealedSize+4096;
    byte*       rgOut= (byte*) malloc(outsize);
    int         m= 0;
    bool        fRet= true;

    if(rgOut==NULL) {
        fprintf(g_logFile, "taoEnvironment::localunsealKey, malloc failed\n");
        fRet= false;
        goto cleanup;
    }

    if(!m_myMeasurementValid) {
        fprintf(g_logFile, "taoEnvironment::localunsealKey, measurement invalid\n");
        fRet= false;
        goto cleanup;
    }

    if(!m_symKeyValid) {
        fprintf(g_logFile, "taoEnvironment::localunsealKey, symkey invalid\n");
        fRet= false;
        goto cleanup;
    }

    fRet= Unseal(m_myMeasurementSize, m_myMeasurement,
                      sealedSize, sealed, &outsize, rgOut);
    if(!fRet) {
        fprintf(g_logFile, "taoEnvironment::localunsealKey, Unseal failed\n");
        fRet= false;
        goto cleanup;
    }

    memcpy(ptype, &rgOut[m], sizeof(u32));
    m+= sizeof(u32);
    memcpy(psize, &rgOut[m], sizeof(int));
    m+= sizeof(int);
    
#ifdef TEST1
    fprintf(g_logFile, "taoEnvironment::localunsealKey size of unsealed blob %d\n",
            outsize);
    fprintf(g_logFile, "taoEnvironment::localunsealKey size of unsealed Key %d\n",
            *psize);
    PrintBytes("Unsealed blob\n", rgOut, outsize);
#endif

    *ppkey= (byte*) malloc(*psize);
    if(*ppkey==NULL) {
        fprintf(g_logFile, "taoEnvironment::localunsealKey, malloc failed\n");
        fRet= false;
        goto cleanup;
    }
    memcpy(*ppkey, &rgOut[m], *psize);

cleanup:
    if(rgOut!=NULL)
        free(rgOut);
    return fRet;
}


#endif  // VALIDATEATTESTONLY

// -------------------------------------------------------------------------


#include "cert.h"
#include "quote.h"
#include "validateEvidence.h"


bool VerifyAttestation(const char *attestation, const char *attestEvidence, 
                       RSAKey& oPolicyKey)  // FIX
{
    int             type= 0;
    PrincipalCert*  pattestCert= NULL;
    RSAKey*         pquoteKey= NULL;        // FIX
    evidenceList    oEvidence;
    char*           szQuoteAlg= NULL;
    char*           szQuoteInfo= NULL;
    char*           szCanonicalQuotedBody= NULL;
    char*           sznonce= NULL;
    char*           szdigest= NULL;
    char*           szQuoteValue= NULL;
    char*           szQuoteKeyInfo= NULL;
    char*           szQuotedKeyInfo= NULL;
    char*           szQuotedKeyName= NULL;
    bool            fRet= false;

    if(attestation==NULL) {
        fprintf(g_logFile, "VerifyAttestation: no attestation\n");
        return false;
    }
    if(attestEvidence==NULL) {
        fprintf(g_logFile, "VerifyAttestation: no evidence\n");
        return false;
    }
#ifdef TEST
    fprintf(g_logFile, "VerifyAttestation, attestation\n%s\nEvidence\n%s\n", 
            attestation, attestEvidence);
    fprintf(g_logFile, "Policy Key\n");
    oPolicyKey.printMe();
    fflush(g_logFile);
#endif

    // Get the information from attestation
    if(!decodeXMLQuote(attestation, &szQuoteAlg, &sznonce,
                    &szdigest, &szQuoteInfo, &szQuoteValue,
                    &szQuoteKeyInfo, &szQuotedKeyInfo, &szQuotedKeyName)) {
        fprintf(g_logFile, "VerifyAttestation: can't decode attest\n");
        goto done;
    }
#ifdef TEST
    fprintf(g_logFile, "VerifyAttestation\n");
    fprintf(g_logFile, "\tszQuoteAlg: %s\n", szQuoteAlg);
    fprintf(g_logFile, "\tszdigest: %s\n", szdigest);
    fprintf(g_logFile, "\tszQuoteInfo: %s\n", szQuoteInfo);
    fprintf(g_logFile, "\tszQuoteValue: %s\n", szQuoteValue);
    fprintf(g_logFile, "\tszQuoteKeyInfo: %s\n", szQuoteKeyInfo);
    fprintf(g_logFile, "\tszQuotedKeyInfo: %s\n", szQuotedKeyInfo);
    fflush(g_logFile);
#endif

    // Cert chain
    if(!oEvidence.m_doc.Parse(attestEvidence)) {
        fprintf(g_logFile, "VerifyAttestation: can't parse evidence list \n");
        goto done;
    }

    oEvidence.m_fDocValid= true;
    oEvidence.m_pRootElement= oEvidence.m_doc.RootElement();
    if(!oEvidence.parseEvidenceList(oEvidence.m_pRootElement)) {
        fprintf(g_logFile, "VerifyAttestation: can't parse evidence list \n");
        goto done;
    }
    if(!oEvidence.validateEvidenceList(&oPolicyKey)) {
        fprintf(g_logFile, "VerifyAttestation: can't verify evidence list \n");
        goto done;
    }
#ifdef TEST
    fprintf(g_logFile, "VerifyAttestation: evidence valid\n");
    fflush(g_logFile);
#endif

    // get parse attest cert
    if(!oEvidence.getSubjectEvidence(&type, (void**)&pattestCert)) {
        fprintf(g_logFile, "VerifyAttestation: can't get attest Cert\n");
        goto done;
    }
    if(type!=PRINCIPALCERT) {
        fprintf(g_logFile, "VerifyAttestation: attest Cert wrong type\n");
        goto done;
    }

    // get quoting key
    pquoteKey= (RSAKey*) pattestCert->getSubjectKeyInfo();  // FIX
    if(pquoteKey==NULL) {
        fprintf(g_logFile, "VerifyAttestation: can't get quoting key from Cert\n");
        goto done;
    }
#ifdef TEST
    fprintf(g_logFile, "VerifyAttestation: quote key\n");
    pquoteKey->printMe();
    fflush(g_logFile);
#endif

    // finally, check attestation
    szCanonicalQuotedBody= canonicalizeXML(szQuoteInfo);
    fRet= checkXMLQuote(szQuoteAlg, szCanonicalQuotedBody, sznonce,
                szdigest, pquoteKey, szQuoteValue);
#ifdef TEST
    if(fRet)
        fprintf(g_logFile, "VerifyAttestation passed\n");
    else
        fprintf(g_logFile, "VerifyAttestation failed\n");
    fflush(g_logFile);
#endif

done:
    if(szCanonicalQuotedBody!=NULL) {
        free(szCanonicalQuotedBody);
        szCanonicalQuotedBody= NULL;
    }
    if(szQuoteAlg!=NULL) {
        free(szQuoteAlg);
        szQuoteAlg= NULL;
    }
    if(sznonce!=NULL) {
        free(sznonce);
        sznonce= NULL;
    }
    if(szdigest!=NULL) {
        free(szdigest);
        szdigest= NULL;
    }
    if(szQuoteInfo!=NULL) {
        free(szQuoteInfo);
        szQuoteInfo= NULL;
    }
    if(szQuoteValue!=NULL) {
        free(szQuoteValue);
        szQuoteValue= NULL;
    }
    if(szQuoteKeyInfo!=NULL) {
        free(szQuoteKeyInfo);
        szQuoteKeyInfo= NULL;
    }
    if(szQuotedKeyInfo!=NULL) {
        free(szQuotedKeyInfo);
        szQuotedKeyInfo= NULL;
    }
    if(pquoteKey!=NULL) {
        // delete pquoteKey;
        // this is deleted in cert class
        pquoteKey= NULL;
    }
    return fRet;
}


// -------------------------------------------------------------------------


