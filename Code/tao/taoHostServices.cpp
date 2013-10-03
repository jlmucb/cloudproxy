//  File: taoHostServices.cpp
//      John Manferdelli
//  Description: Host interface to Tao primitives
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
#include "sha256.h"
#include "tao.h"
#include "bignum.h"
#include "mpFunctions.h"
#include "cryptoHelper.h"
#include "trustedKeyNego.h"
#include "linuxHostsupport.h"
#ifdef TPMSUPPORT
#include "TPMHostsupport.h"
#endif
#include "hashprep.h"
#ifndef TPMSUPPORT
extern int      g_policykeySize;
extern char*    g_szXmlPolicyCert;
#endif

#include <string.h>
#include <time.h>


// -------------------------------------------------------------------------


taoHostServices::taoHostServices()
{
    m_hostType= PLATFORMTYPENONE;
    m_hostValid= false;
    m_hostHandle= 0;
    m_hostCertificateValid= false;
    m_hostCertificateType= EVIDENCENONE;
    m_hostCertificateSize= 0;
    m_hostCertificate= NULL;
}


taoHostServices::~taoHostServices()
{
    m_hostType= PLATFORMTYPENONE;
    m_hostValid= false;
    m_hostHandle= 0;
}


bool taoHostServices::HostInit(u32 hostType, const char* hostProvider,
                               const char* directory, const char* subdirectory, 
                               int nParameters, const char** rgszParameter)
{
    const char*     tpmPassword= NULL;
    UNUSEDVAR(tpmPassword);

#ifdef TEST
    fprintf(g_logFile, "HostInit(%04x)\n", hostType);
    fprintf(g_logFile, "HostInit: %s, %s, %s\n", hostProvider, 
                       directory, subdirectory);
    fflush(g_logFile);
#endif

    m_hostType= hostType;
    m_hostValid= false;

    // init filenames
    if(!m_fileNames.initNames(directory, subdirectory)) {
        fprintf(g_logFile, "taoHostServices::HostInit: cant init names\n");
        return false;
    }


    switch(m_hostType) {
      default:
      case PLATFORMTYPENONE:
      case PLATFORMTYPELINUXAPP:
      case PLATFORMTYPEHYPERVISOR:
        // hostProvider not supported
        fprintf(g_logFile, "taoHostServices::HostInit: host not supported\n");
        return false;

      case PLATFORMTYPEHW:
        // hostProvider is tpm
#ifdef TPMSUPPORT
        if(nParameters>1)
            tpmPassword= rgszParameter[1];
        else
            tpmPassword= NULL;

        if(!m_oTpm.initTPM(hostProvider, m_fileNames.m_szprivateFile, tpmPassword)) {
            fprintf(g_logFile, "taoHostServices::HostInit: cant init TPM\n");
            return false;
        }
        break;
#else
        fprintf(g_logFile, "taoHostServices::HostInit: HW platform not supported\n");
        return false;
#endif
      case PLATFORMTYPEKVMHYPERVISOR:
        // hostProvider is ktciodd 
      case PLATFORMTYPEKVMHOSTEDLINUXGUESTOS:
      case PLATFORMTYPEGUESTLINUX:
      case PLATFORMTYPELINUX:
        // hostProvider is tciodd 
#ifndef TPMSUPPORT
        if(!m_linuxmyHostChannel.initLinuxService(hostProvider)) {
            fprintf(g_logFile, 
                    "taoHostServices::HostInit: cant init my host Linuxservice %s\n",
                    hostProvider);
            fflush(g_logFile);
            return false;
        }
#else
        fprintf(g_logFile, "taoHostServices::HostInit: initLinuxService not supported\n");
        fflush(g_logFile);
        return false;
#endif
        break;
    }

    // get host certs and evidence
    if(!m_fileNames.getBlobData(m_fileNames.m_szcertFile, &m_hostCertificateValid, 
                                &m_hostCertificateSize, &m_hostCertificate)) {
        fprintf(g_logFile, "taoHostServices::HostInit: cant get host cert\n");
        return false;
    }
    m_hostCertificateType= EVIDENCECERT;
    m_hostCertificateValid= true;

    m_hostEvidenceValid= m_fileNames.getBlobData(m_fileNames.m_szAncestorEvidence, 
                            &m_hostEvidenceValid, &m_hostEvidenceSize, &m_hostEvidence);
    m_hostEvidenceType= EVIDENCECERTLIST;
    m_hostValid= true;

#ifdef TEST
    fprintf(g_logFile, "HostInit succeeded.\n");
    if(m_linuxmyHostChannel.m_fChannelInitialized) {
        fprintf(g_logFile, "HostInit  channel: %d\n", m_linuxmyHostChannel.m_reqChannel.m_fd);
    }
    fflush(g_logFile);
#endif
    return true;
}


bool taoHostServices::HostClose()
{
    return true;
}


bool taoHostServices::StartHostedProgram(int an, char** av, int* phandle)
{
    switch(m_hostType) {
      default:
      case PLATFORMTYPENONE:
      case PLATFORMTYPELINUXAPP:
      case PLATFORMTYPEHYPERVISOR:
      case PLATFORMTYPEHW:
        fprintf(g_logFile, "taoHostServices::HostInit: HW StartHostedProgram not supported\n");
        return false;

      case PLATFORMTYPEKVMHYPERVISOR:
      case PLATFORMTYPEKVMHOSTEDLINUXGUESTOS:
      case PLATFORMTYPELINUX:
      case PLATFORMTYPEGUESTLINUX:
#ifndef TPMSUPPORT
        return m_linuxmyHostChannel.startAppfromDeviceDriver(phandle, an, av);
#else
        fprintf(g_logFile, 
                "taoHostServices::HostInit: linux StartHostedProgram not supported\n");
        return false;
#endif
    }
}


bool taoHostServices::GetHostedMeasurement(int* psize, u32* ptype, byte* buf)
{
    switch(m_hostType) {
      default:
      case PLATFORMTYPENONE:
      case PLATFORMTYPELINUXAPP:
      case PLATFORMTYPEHYPERVISOR:
        fprintf(g_logFile, "taoHostServices::GetHostedMeasurement: Host not supported\n");
        return false;

      case PLATFORMTYPEHW:
#ifdef TPMSUPPORT
        return m_oTpm.getMeasurementTPM(psize, buf);
#else
        fprintf(g_logFile, "taoHostServices::GetHostedMeasurement: TPM not supported\n");
        return false;
#endif

      case PLATFORMTYPEKVMHOSTEDLINUXGUESTOS:
      case PLATFORMTYPEKVMHYPERVISOR:
      case PLATFORMTYPELINUX:
      case PLATFORMTYPEGUESTLINUX:
#ifndef TPMSUPPORT
        return m_linuxmyHostChannel.getHostedMeasurementfromDeviceDriver(getpid(), ptype, 
                                                                         psize, buf);
#else
        fprintf(g_logFile, "taoHostServices::HostInit: m_linuxmyHostChannel.getHostedMeasurementfromDeviceDriver not supported\n");
        return false;
#endif
    }
}


bool taoHostServices::GetAncestorCertificates(int* psize, byte** ppbuf)
{
    int     n= 4096;
    byte    buf[4096];

    if(!m_hostEvidenceValid) {
        if(!getBlobfromFile(m_fileNames.m_szAncestorEvidence, buf, &n)) {
            return false;
        }
        m_hostEvidenceType= EVIDENCECERTLIST;
        m_hostEvidenceSize= n;
        m_hostEvidence= (byte*)malloc(n);
        if(m_hostEvidence==NULL)
            return false;
        memcpy(m_hostEvidence, buf, m_hostEvidenceSize);
        m_hostEvidenceValid= true;
    }

    *psize= m_hostEvidenceSize;
    *ppbuf= (byte*) malloc(m_hostEvidenceSize);
    if(*ppbuf==NULL)
        return false;
    memcpy(*ppbuf, m_hostEvidence, m_hostEvidenceSize);
    return true;
}


bool taoHostServices::GetAttestCertificate(int* psize, u32* ptype, byte** ppbuf)
{
    int     n= 4096;
    byte    buf[4096];

    if(!m_hostCertificateValid) {
        if(!getBlobfromFile(m_fileNames.m_szcertFile, buf, &n)) {
            fprintf(g_logFile, 
                    "GetAttestCertificate: getBlobfromFile Host Certificate failed\n");
            return false;
        }
        m_hostCertificateType= EVIDENCECERT;
        m_hostCertificateSize= n;
        m_hostCertificate= (byte*)malloc(n);
        if(m_hostCertificate==NULL) {
            fprintf(g_logFile, "GetAttestCertificate: bad malloc\n");
            return false;
        }
        memcpy(m_hostCertificate, buf, n);
        m_hostCertificateValid= true;
    }
    *ptype= m_hostCertificateType;
    *psize= m_hostCertificateSize;
    *ppbuf= (byte*) malloc(m_hostCertificateSize);
    if(*ppbuf==NULL)
        return false;
    memcpy(*ppbuf, m_hostCertificate, m_hostCertificateSize);
    return true;
}


bool taoHostServices::GetHostPolicyKey(int* psize, u32* pType, byte* buf)
{
    switch(m_hostType) {
      default:
      case PLATFORMTYPENONE:
      case PLATFORMTYPELINUXAPP:
      case PLATFORMTYPEHYPERVISOR:
      case PLATFORMTYPEHW:
        return false;
      case PLATFORMTYPEKVMHOSTEDLINUXGUESTOS:
      case PLATFORMTYPEKVMHYPERVISOR:
      case PLATFORMTYPELINUX:
      case PLATFORMTYPEGUESTLINUX:
#ifndef TPMSUPPORT
        return  m_linuxmyHostChannel.getOSMeasurementfromDeviceDriver(pType, psize, buf);
#else
        fprintf(g_logFile, "taoHostServices::HostInit: m_linuxmyHostChannel.getHostedMeasurementfromDeviceDriver not supported\n");
        return false;
#endif
    }
}


bool taoHostServices::GetEntropy(int size, byte* buf)
{
    switch(m_hostType) {
      default:
      case PLATFORMTYPENONE:
      case PLATFORMTYPELINUXAPP:
      case PLATFORMTYPEHYPERVISOR:
        fprintf(g_logFile, 
              "taoHostServices::HostInit: m_linuxmyHostChannel getEntropy not supported\n");
        return false;
      case PLATFORMTYPEHW:
#ifdef TPMSUPPORT
        return m_oTpm.getEntropyTPM(size, buf);
#else
        fprintf(g_logFile, "taoHostServices::HostInit: TPM getEntropy not supported\n");
        return false;
#endif
      case PLATFORMTYPELINUX:
      case PLATFORMTYPEGUESTLINUX:
      case PLATFORMTYPEKVMHOSTEDLINUXGUESTOS:
      case PLATFORMTYPEKVMHYPERVISOR:
#ifndef TPMSUPPORT
        return  m_linuxmyHostChannel.getEntropyfromDeviceDriver(size, buf);
#else
        fprintf(g_logFile, "taoHostServices::HostInit: linux.getEntropy not supported\n");
        return false;
#endif
    }
}


bool taoHostServices::Seal(int sizetoSeal, byte* toSeal, int* psizeSealed, byte* sealed)
{
    switch(m_hostType) {
      default:
      case PLATFORMTYPENONE:
      case PLATFORMTYPELINUXAPP:
      case PLATFORMTYPEHYPERVISOR:
        return false;

      case PLATFORMTYPEHW:
#ifdef TPMSUPPORT
        return m_oTpm.sealwithTPM(sizetoSeal, toSeal, psizeSealed, sealed);
#else
        fprintf(g_logFile, "taoHostServices::HostInit: linux seal not supported\n");
        return false;
#endif
      case PLATFORMTYPEKVMHOSTEDLINUXGUESTOS:
      case PLATFORMTYPEKVMHYPERVISOR:
      case PLATFORMTYPELINUX:
      case PLATFORMTYPEGUESTLINUX:
#ifndef TPMSUPPORT
        return  m_linuxmyHostChannel.sealfromDeviceDriver(sizetoSeal, toSeal, 
                                                          psizeSealed, sealed);
#else
        fprintf(g_logFile, "taoHostServices::HostInit: linux seal not supported\n");
        return false;
#endif
    }
}


bool taoHostServices::Unseal(int sizeSealed, byte* sealed, int *psizetoSeal, byte* toSeal)
{
#ifdef TEST
    fprintf(g_logFile, "taoHostServices::Unseal\n");
    fflush(g_logFile);
#endif
    switch(m_hostType) {
      default:
      case PLATFORMTYPENONE:
      case PLATFORMTYPELINUXAPP:
      case PLATFORMTYPEHYPERVISOR:
        fprintf(g_logFile, "taoHostServices::HostInit: linux unseal not supported\n");
        fflush(g_logFile);
        return false;
      case PLATFORMTYPEHW:
#ifdef TPMSUPPORT
        return m_oTpm.unsealwithTPM(sizeSealed, sealed, psizetoSeal, toSeal);
#else
        fprintf(g_logFile, "taoHostServices::HostInit: linux unseal not supported\n");
        fflush(g_logFile);
        return false;
#endif
      case PLATFORMTYPEKVMHOSTEDLINUXGUESTOS:
      case PLATFORMTYPEKVMHYPERVISOR:
      case PLATFORMTYPELINUX:
      case PLATFORMTYPEGUESTLINUX:
#ifndef TPMSUPPORT
        return  m_linuxmyHostChannel.unsealfromDeviceDriver(sizeSealed, sealed, 
                                                            psizetoSeal, toSeal);
#else
        fprintf(g_logFile, "taoHostServices::HostInit: linux unseal not supported\n");
        fflush(g_logFile);
        return false;
#endif
    }
}


bool taoHostServices::Attest(int sizetoAttest, byte* toAttest, 
                             int* psizeAttested, byte* attested)
{
#ifdef TEST
    fprintf(g_logFile, "taoHostServices::Attest\n");
    PrintBytes("Attest this string:\n", toAttest, sizetoAttest);
    fflush(g_logFile);
#endif
    switch(m_hostType) {
      default:
      case PLATFORMTYPENONE:
      case PLATFORMTYPELINUXAPP:
      case PLATFORMTYPEHYPERVISOR:
        fprintf(g_logFile, "taoHostServices::HostInit: Attest not supported\n");
        return false;
      case PLATFORMTYPEHW:
#ifdef TPMSUPPORT
        return m_oTpm.quotewithTPM(sizetoAttest, toAttest, psizeAttested, attested);
#else
        fprintf(g_logFile, "taoHostServices::HostInit: TPM quote not supported\n");
        return false;
#endif
      case PLATFORMTYPEKVMHOSTEDLINUXGUESTOS:
      case PLATFORMTYPEKVMHYPERVISOR:
      case PLATFORMTYPELINUX:
      case PLATFORMTYPEGUESTLINUX:
#ifndef TPMSUPPORT
        return  m_linuxmyHostChannel.quotefromDeviceDriver(sizetoAttest, toAttest, 
                                                           psizeAttested, attested);
#else
        fprintf(g_logFile, "taoHostServices::HostInit: linux quote not supported\n");
        return false;
#endif
    }
}


#ifdef TEST
void taoHostServices::printData()
{     
    if(m_hostValid)
        fprintf(g_logFile, "\ttaoHostServices valid\n");
    else
        fprintf(g_logFile, "\ttaoHostServices invalid\n");
    fprintf(g_logFile, "\ttaoHostServices type: %08x\n", m_hostType);
    m_fileNames.printAll();
    if(m_hostCertificateValid) {
        fprintf(g_logFile, "\tCert type: %08x, size: %d\n", 
                m_hostCertificateType, m_hostCertificateSize);
        fprintf(g_logFile, "\tCert:\n%s\n", m_hostCertificate);
    }
    if(m_hostEvidenceValid) {
        fprintf(g_logFile, "\tEvidence type: %08x, size: %d\n", 
                m_hostEvidenceType, m_hostEvidenceSize);
        fprintf(g_logFile, "\tEvidence:\n%s\n", m_hostEvidence);
    }
}
#endif


// --------------------------------------------------------------------------


