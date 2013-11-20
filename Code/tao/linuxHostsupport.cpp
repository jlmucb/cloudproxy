//  File: linuxHostsupport.cpp
//  Description:  Support for Linux host as trusted OS via device driver
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
#include "tcIO.h"
#include "buffercoding.h"
#include "tcService.h"
#include "linuxHostsupport.h"
#include <string.h>
#include <time.h>


// -------------------------------------------------------------------------


//
//   Service support for Linux request channel
//


linuxDeviceChannel::linuxDeviceChannel()
{
    m_fChannelInitialized= false;
    m_driverName= NULL;
    m_myPid= -1;
    m_famService= false;
}


linuxDeviceChannel::~linuxDeviceChannel()
{
    if(m_fChannelInitialized)
        closeLinuxService();
}


bool linuxDeviceChannel::initLinuxService(const char* name, bool famService)
{
#ifdef TEST1
    if(name!=NULL)
        fprintf(g_logFile, "initLinuxService started %s\n", name);
    else
        fprintf(g_logFile, "initLinuxService started no childname\n");
#endif

    m_myPid= getpid();
    if(!m_reqChannel.OpenBuf(TCDEVICEDRIVER, name, 0, NULL, 0)) {
        fprintf(g_logFile, "initLinuxService: OpenBuf returned false \n");
        return false;
    }
    m_driverName= strdup(name);
    m_fChannelInitialized= true;
    if(famService) {
        m_famService= true;
        if(!tcserviceHello()) {
            m_fChannelInitialized= false;
            fprintf(g_logFile, "initLinuxService: tcserviceHello failed\n");
            return false;
        }
    }

#ifdef TEST
    if(m_famService)
        fprintf(g_logFile, "initLinuxService returns true as a tcService\n");
    else
        fprintf(g_logFile, "initLinuxService returns true\n");
#endif
    return true;
}


bool linuxDeviceChannel::closeLinuxService()
{
    m_reqChannel.CloseBuf();
    if(m_driverName!=NULL) {
        free(m_driverName);
        m_driverName= NULL;
    }
    m_fChannelInitialized= false;
    return true;
}


bool linuxDeviceChannel::getEntropyfromDeviceDriver(int size, byte* pKey)
{
    return false;
}


bool linuxDeviceChannel::getprogramNamefromDeviceDriver(int* pSize, const char* szName)
{
    // this is done elsewhere
    return true;
}


bool linuxDeviceChannel::tcserviceGoodbye()
{
    return false;
}


bool linuxDeviceChannel::tcserviceHello()
{
#if 0
    u32         ustatus;
    u32         ureq;
    int         procid;
    int         origprocid;
    int         size= PARAMSIZE;
    byte        rgBuf[PARAMSIZE];

    if(!m_reqChannel.sendtcBuf(m_myPid, TCSERVICESERVICEHELLO, 0, 
                               m_myPid, size, rgBuf)) {
        fprintf(g_logFile, "tcserviceHello: sendtcBuf failed\n");
        return false;
    }
    size= PARAMSIZE;
    if(!m_reqChannel.gettcBuf(&procid, &ureq, &ustatus, &origprocid, &size, rgBuf)) {
        fprintf(g_logFile, "tcserviceHello: gettcBuf failed\n");
        return false;
    }

    fprintf(g_logFile, "tcserviceHello true\n");
#endif
    return true;
}


bool linuxDeviceChannel::getpolicykeyfromDeviceDriver(u32* pkeyType, int* pSize, 
                                                      byte* pKey)
{
    u32         ustatus;
    u32         ureq;
    int         procid;
    int         origprocid;
    int         size= PARAMSIZE;
    byte        rgBuf[PARAMSIZE]; 

    if(!m_reqChannel.sendtcBuf(m_myPid, TCSERVICEGETPOLICYKEYFROMAPP, 0, 
                               m_myPid, size, rgBuf)) {
        fprintf(g_logFile, "getpolicykeyfromDeviceDriver: sendtcBuf for encodeTCSERVICEPOLICYKEYFROMAPP failed\n");
        return false;
    }
    size= PARAMSIZE;
    if(!m_reqChannel.gettcBuf(&procid, &ureq, &ustatus, &origprocid, &size, rgBuf)) {
        fprintf(g_logFile, "getpolicykeyfromDeviceDriver: gettcBuf for encodeTCSERVICEPOLICYKEYFROMAPP failed\n");
        return false;
    }
    if(!decodeTCSERVICEGETPOLICYKEYFROMOS(pkeyType, pSize, pKey, rgBuf)) {
        fprintf(g_logFile, "getpolicykeyfromDeviceDriver: gettcBuf for decodeTCSERVICEPOLICYKEYFROMAPP failed\n");
        return false;
    }
#ifdef TEST1
    PrintBytes("Policy key: ", pKey, *pSize);
    fprintf(g_logFile, "getpolicykeyfromDeviceDriverOS parent returns true\n");
#endif
    return true;
}


bool linuxDeviceChannel::getOSMeasurementfromDeviceDriver(u32* phashType, 
                                                  int* pSize, byte* pHash)
{
    u32         ustatus;
    u32         ureq;
    int         procid;
    int         origprocid;
    int         size= 0;
    byte        rgBuf[PARAMSIZE];

#ifdef TEST1
    fprintf(g_logFile, "getOSMeasurementfromDeviceDriver\n");
    fflush(g_logFile);
#endif
    if(!m_reqChannel.sendtcBuf(m_myPid, TCSERVICEGETOSHASHFROMAPP, 0, 
                               m_myPid, size, rgBuf)) {
        fprintf(g_logFile, "getOSMeasurementfromDeviceDriver: sendtcBuf for encodeTCSERVICESEALFORFROMAPP failed\n");
        return false;
    }
    size= PARAMSIZE;
    if(!m_reqChannel.gettcBuf(&procid, &ureq, &ustatus, &origprocid, &size, rgBuf)) {
        fprintf(g_logFile, "getOSMeasurementfromDeviceDriver: gettcBuf for encodeTCSERVICESEALFORFROMAPP failed\n");
        return false;
    }
    if(!decodeTCSERVICEGETOSHASHFROMTCSERVICE(phashType, pSize, pHash, rgBuf)) {
        fprintf(g_logFile, "getOSMeasurementfromDeviceDriver: gettcBuf for decodeTCSERVICESEALFORFROMAPP failed\n");
        return false;
    }
#ifdef TEST
    PrintBytes("OS hash: ", pHash, *pSize);
    fprintf(g_logFile, "getOSMeasurementfromDeviceDriver OS parent returns true\n");
    fflush(g_logFile);
#endif
    return true;
}


bool linuxDeviceChannel::getHostedMeasurementfromDeviceDriver(int childproc, u32* phashType, 
                                          int* pSize, byte* pHash)
{
    u32         ustatus;
    u32         ureq;
    int         procid;
    int         origprocid;
    int         size= PARAMSIZE;
    byte        rgBuf[PARAMSIZE];

#ifdef TEST1
    fprintf(g_logFile, "getHostedMeasurementfromDeviceDriver\n");
    fflush(g_logFile);
#endif
    // Does my pid have valid hash?
    size= encodeTCSERVICEGETPROGHASHFROMAPP(childproc, 1024, rgBuf);
    if(!m_reqChannel.sendtcBuf(m_myPid, TCSERVICEGETPROGHASHFROMAPP,
                        0, m_myPid, size, rgBuf)) {
        fprintf(g_logFile, 
         "getHostedMeasurementfromDeviceDriver: sendtcBuf for TCSERVICEGETPROGHASHFROMAPP failed\n");
        return false;
    }
    size= PARAMSIZE;
    if(!m_reqChannel.gettcBuf(&procid, &ureq, &ustatus, &origprocid, &size, rgBuf)) {
        fprintf(g_logFile, "getHostedMeasurementfromDeviceDriver: gettcBuf for TCSERVICEGETPROGHASHFROMAPP failed\n");
    }
    size= PARAMSIZE;
    if(!decodeTCSERVICEGETPROGHASHFROMSERVICE(phashType, pSize, pHash, 1024, rgBuf)) {
        fprintf(g_logFile, "getHostedMeasurementfromDeviceDriver: cant decode os hash\n");
        return false;
    }

#ifdef TEST
    PrintBytes("getHostedMeasurementfromDeviceDriver prog hash: ", pHash, *pSize);
    fflush(g_logFile);
#endif
    return true;
}


bool linuxDeviceChannel::startAppfromDeviceDriver(int* ppid, int argc, char **argv)
{
    u32         ustatus;
    u32         ureq;
    int         procid;
    int         origprocid;
    int         size= PARAMSIZE;
    byte        rgBuf[PARAMSIZE];

    size= encodeTCSERVICESTARTAPPFROMAPP(argc, argv, PARAMSIZE, rgBuf);
    if(size<0) {
        fprintf(g_logFile, "startProcessLinuxService: encodeTCSERVICESTARTAPPFROMAPP failed\n");
        return false;
    }
    if(!m_reqChannel.sendtcBuf(m_myPid, TCSERVICESTARTAPPFROMAPP, 0, m_myPid, size, rgBuf)) {
        fprintf(g_logFile, "startProcessLinuxService: sendtcBuf for TCSERVICESTARTAPPFROMAPP failed\n");
        return false;
    }
    size= PARAMSIZE;
    if(!m_reqChannel.gettcBuf(&procid, &ureq, &ustatus, &origprocid, &size, rgBuf)) {
        fprintf(g_logFile, "startProcessLinuxService: gettcBuf for TCSERVICESTARTAPPFROMAPP failed\n");
        return false;
    }
    if(!decodeTCSERVICESTARTAPPFROMTCSERVICE(ppid, rgBuf)) {
        fprintf(g_logFile, "startProcessLinuxService: cant decode childproc\n");
        return false;
    }
#ifdef TEST
    fprintf(g_logFile, 
            "startProcessLinuxService: Process created: %d by servicepid %d for %d\n", 
            *ppid, m_myPid, getpid());
    fflush(g_logFile);
#endif
    return true;
}


bool linuxDeviceChannel::sealfromDeviceDriver(int inSize, byte* inData, 
                                              int* poutSize, byte* outData)
{
    u32         ustatus;
    u32         ureq;
    int         procid;
    int         origprocid;
    int         size= 0;
    byte        rgBuf[PARAMSIZE];

#ifdef TEST
    fprintf(g_logFile, "sealwithLinuxService(%d)\n", inSize);
    fflush(g_logFile);
#endif
    memset(outData, 0, *poutSize);
    size= encodeTCSERVICESEALFORFROMAPP(inSize, inData, PARAMSIZE, rgBuf);
    if(size<0) {
        fprintf(g_logFile, "sealwithLinuxService: encodeTCSERVICESEALFORFROMAPP failed\n");
        return false;
    }
    if(!m_reqChannel.sendtcBuf(m_myPid, TCSERVICESEALFORFROMAPP, 0, 
                               m_myPid, size, rgBuf)) {
        fprintf(g_logFile, "sealwithLinuxService: sendtcBuf for encodeTCSERVICESEALFORFROMAPP failed\n");
        return false;
    }
    size= PARAMSIZE;
    if(!m_reqChannel.gettcBuf(&procid, &ureq, &ustatus, &origprocid, &size, rgBuf)) {
        fprintf(g_logFile, "sealwithLinuxService: gettcBuf for encodeTCSERVICESEALFORFROMAPP failed\n");
        return false;
    }
    if(!decodeTCSERVICESEALFORFROMTCSERVICE(poutSize, outData, rgBuf)) {
        fprintf(g_logFile, "sealwithLinuxService: gettcBuf for decodeTCSERVICESEALFORFROMAPP failed\n");
        return false;
    }
#ifdef TCTEST1
    PrintBytes("To seal: ", inData, inSize);
    PrintBytes("Sealed :", outData, *poutSize);
#endif
    return true;
}


bool linuxDeviceChannel::unsealfromDeviceDriver(int inSize, byte* inData, int* poutSize, byte* outData)
{
    u32         ustatus;
    u32         ureq;
    int         procid;
    int         origprocid;
    int         size= 0;
    byte        rgBuf[PARAMSIZE];

#ifdef TEST1
    fprintf(g_logFile, "unsealwithLinuxService(%d)\n", inSize);
    fflush(g_logFile);
#endif
    memset(outData, 0, *poutSize);
    size= encodeTCSERVICEUNSEALFORFROMAPP(inSize, inData, PARAMSIZE, rgBuf);
    if(size<0) {
        fprintf(g_logFile, "unsealwithLinuxService: encodeTCSERVICEUNSEALFORFROMAPP failed\n");
        fflush(g_logFile);
        return false;
    }
    if(!m_reqChannel.sendtcBuf(m_myPid, TCSERVICEUNSEALFORFROMAPP, 0, m_myPid, size, rgBuf)) {
        fprintf(g_logFile, "unsealwithLinuxService: sendtcBuf for TCSERVICEUNSEALFORFROMAPP failed\n");
        return false;
    }
    size= PARAMSIZE;
    if(!m_reqChannel.gettcBuf(&procid, &ureq, &ustatus, &origprocid, &size, rgBuf)) {
        fprintf(g_logFile, "unsealwithLinuxService: gettcBuf for TCSERVICEUNSEALFORFROMAPP failed\n");
        fflush(g_logFile);
        return false;
    }
    if(!decodeTCSERVICEUNSEALFORFROMTCSERVICE(poutSize, outData, rgBuf)) {
        fprintf(g_logFile, "unsealwithLinuxService: gettcBuf for decodeTCSERVICESEALFORFROMTCSERVICE failed\n");
        fflush(g_logFile);
        return false;
    }
#ifdef TCTEST1
    PrintBytes("To unseal: ", inData, inSize);
    PrintBytes("Unsealed : ", outData, *poutSize);
#endif
#ifdef TEST
    fprintf(g_logFile, "unsealwithLinuxService returns true\n");
    fflush(g_logFile);
#endif
    return true;
}


bool linuxDeviceChannel::quotefromDeviceDriver(int inSize, byte* inData, 
                                               int* poutSize, byte* outData)
{
    u32         ustatus;
    u32         ureq;
    int         procid;
    int         origprocid;
    int         size= 0;
    byte        rgBuf[PARAMSIZE];

#ifdef TEST
    fprintf(g_logFile, "quotewithLinuxService(%d, %d)\n", inSize, *poutSize);
    fflush(g_logFile);
#endif
    memset(outData, 0, *poutSize);
    size= encodeTCSERVICEATTESTFORFROMAPP(inSize, inData, PARAMSIZE, rgBuf);
    if(size<0) {
        fprintf(g_logFile, "quotewithLinuxService: encodeTCSERVICEATTESTFORFROMAPP failed\n");
        return false;
    }
#ifdef TEST1
    fprintf(g_logFile, "quotewithLinuxService: sending %d\n", inSize);
    PrintBytes(" req buffer: ", inData, inSize); 
    fflush(g_logFile);
#endif
    if(!m_reqChannel.sendtcBuf(m_myPid, TCSERVICEATTESTFORFROMAPP, 0, 
                               m_myPid, size, rgBuf)) {
        fprintf(g_logFile, 
            "quotewithLinuxService: sendtcBuf for TCSERVICEATTESTFORFROMAPP failed\n"); 
        return false;
    }
    size= PARAMSIZE;
    if(!m_reqChannel.gettcBuf(&procid, &ureq, &ustatus, &origprocid, &size, rgBuf)) {
        fprintf(g_logFile, "quotewithLinuxService: gettcBuf for TCSERVICEATTESTFORFROMAPP failed\n");
        return false;
    }
#ifdef TEST1
    fprintf(g_logFile, "quotewithLinuxService: rgBufsize is %d, status: %d\n", 
            size, ustatus);
#endif
    if(!decodeTCSERVICEATTESTFORFROMTCSERVICE(poutSize, outData, rgBuf)) {
        fprintf(g_logFile, "quotewithLinuxService: gettcBuf for decodeTCSERVICEATTESTFORFROMTCSERVICEfailed\n");
        return false;
    }
#ifdef TEST1
    fprintf(g_logFile, "quotewithLinuxService: outsize is %d\n", *poutSize);
    PrintBytes("To quote: ", inData, inSize);
    PrintBytes("Quoted : ", outData, *poutSize);
    fflush(g_logFile);
#endif
    return true;
}


// -------------------------------------------------------------------------


