//  File: linuxHostsupport.cpp
//      John Manferdelli
//  Description:  Support for Linux host as trusted OS
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
#ifdef AESNIENABLED
#include "aesni.h"
#else
#include "aes.h"
#endif
#include "sha256.h"
#include "tao.h"
#include "bignum.h"
#include "mpFunctions.h"
#include "rsaHelper.h"
#include "trustedKeyNego.h"
#include "tcIO.h"
#include "buffercoding.h"
#include "tcService.h"
#include <string.h>
#include <time.h>


// -------------------------------------------------------------------------


//
//   Service support from LINUX
//


// request channel to device driver
tcChannel   g_reqChannel;
int         g_myPid= -1;


bool initLinuxService(char* name)
{
#ifdef TCTEST
    if(name!=NULL)
        fprintf(g_logFile, "initLinuxService started %s\n", name);
    else
        fprintf(g_logFile, "initLinuxService started no childname\n");
#endif

    g_myPid= getpid();
    if(!g_reqChannel.OpenBuf(TCDEVICEDRIVER, 0, name ,0)) {
        fprintf(g_logFile, "initLinuxService: OpenBuf returned false \n");
        return false;
    }

#ifdef TCTEST
    fprintf(g_logFile, "initLinuxService returns true\n");
#endif
    return true;
}


bool closeLinuxService()
{
    g_reqChannel.CloseBuf();
    return true;
}


bool getEntropyfromDeviceDriver(int size, byte* pKey)
{
    return false;
}


bool getprogramNamefromDeviceDriver(int* pSize, char* szName)
{
    // this is done elsewhere
    return true;
}


bool getpolicykeyfromDeviceDriver(u32* pkeyType, int* pSize, byte* pKey)
{
    u32         ustatus;
    u32         ureq;
    int         procid;
    int         origprocid;
    int         size= PARAMSIZE;
    byte        rgBuf[PARAMSIZE];

    if(!g_reqChannel.sendtcBuf(g_myPid, TCSERVICEGETPOLICYKEYFROMAPP, 0, 
                               g_myPid, size, rgBuf)) {
        fprintf(g_logFile, "getpolicykeyfromDeviceDriver: sendtcBuf for encodeTCSERVICEPOLICYKEYFROMAPP failed\n");
        return false;
    }
    size= PARAMSIZE;
    if(!g_reqChannel.gettcBuf(&procid, &ureq, &ustatus, &origprocid, &size, rgBuf)) {
        fprintf(g_logFile, "getpolicykeyfromDeviceDriver: gettcBuf for encodeTCSERVICEPOLICYKEYFROMAPP failed\n");
        return false;
    }
    if(!decodeTCSERVICEGETPOLICYKEYFROMOS(pkeyType, pSize, pKey, rgBuf)) {
        fprintf(g_logFile, "getpolicykeyfromDeviceDriver: gettcBuf for decodeTCSERVICEPOLICYKEYFROMAPP failed\n");
        return false;
    }
#ifdef TEST1
    PrintBytes((char*)"Policy key: ", pKey, *pSize);
#endif
    fprintf(g_logFile, "getpolicykeyfromDeviceDriverOS parent returns true\n");
    return true;
}


bool getOSMeasurementfromDeviceDriver(u32* phashType, int* pSize, byte* pHash)
{
    u32         ustatus;
    u32         ureq;
    int         procid;
    int         origprocid;
    int         size= 0;
    byte        rgBuf[PARAMSIZE];

#ifdef TEST
    fprintf(g_logFile, "getOSMeasurementfromDeviceDriver\n");
#endif
    if(!g_reqChannel.sendtcBuf(g_myPid, TCSERVICEGETOSHASHFROMAPP, 0, 
                               g_myPid, size, rgBuf)) {
        fprintf(g_logFile, "getOSMeasurementfromDeviceDriver: sendtcBuf for encodeTCSERVICESEALFORFROMAPP failed\n");
        return false;
    }
    size= PARAMSIZE;
    if(!g_reqChannel.gettcBuf(&procid, &ureq, &ustatus, &origprocid, &size, rgBuf)) {
        fprintf(g_logFile, "getOSMeasurementfromDeviceDriver: gettcBuf for encodeTCSERVICESEALFORFROMAPP failed\n");
        return false;
    }
    if(!decodeTCSERVICEGETOSHASHFROMTCSERVICE(phashType, pSize, pHash, rgBuf)) {
        fprintf(g_logFile, "getOSMeasurementfromDeviceDriver: gettcBuf for decodeTCSERVICESEALFORFROMAPP failed\n");
        return false;
    }
#ifdef TEST
    PrintBytes((char*)"OS hash: ", pHash, *pSize);
#endif
    fprintf(g_logFile, "getOSMeasurementfromDeviceDriver OS parent returns true\n");
    return true;
}


bool getHostedMeasurementfromDeviceDriver(int childproc, u32* phashType, 
                                          int* pSize, byte* pHash)
{
    u32         ustatus;
    u32         ureq;
    int         procid;
    int         origprocid;
    int         size= PARAMSIZE;
    byte        rgBuf[PARAMSIZE];

#ifdef TEST
    fprintf(g_logFile, "getHostedMeasurementfromDeviceDriver\n");
#endif
    // Does my pid have valid hash?
    size= encodeTCSERVICEGETPROGHASHFROMAPP(childproc, 1024, rgBuf);
    if(!g_reqChannel.sendtcBuf(g_myPid, TCSERVICEGETPROGHASHFROMAPP,
                        0, g_myPid, size, rgBuf)) {
        fprintf(g_logFile, "getHostedMeasurementfromDeviceDriver: sendtcBuf for TCSERVICEGETPROGHASHFROMAPP failed\n");
        return false;
    }
    size= PARAMSIZE;
    if(!g_reqChannel.gettcBuf(&procid, &ureq, &ustatus, &origprocid, &size, rgBuf)) {
        fprintf(g_logFile, "getHostedMeasurementfromDeviceDriver: gettcBuf for TCSERVICEGETPROGHASHFROMAPP failed\n");
    }
    size= PARAMSIZE;
    if(!decodeTCSERVICEGETPROGHASHFROMSERVICE(phashType, pSize, pHash, 1024, rgBuf)) {
        fprintf(g_logFile, "getHostedMeasurementfromDeviceDriver: cant decode os hash\n");
        return false;
    }

#ifdef TEST
    PrintBytes((char*)"getHostedMeasurementfromDeviceDriver prog hash: ", pHash, *pSize);
#endif
    return true;
}


bool startAppfromDeviceDriver(char* szexecFile, int* ppid)
{
    u32         ustatus;
    u32         ureq;
    int         procid;
    int         origprocid;
    int         size= PARAMSIZE;
    byte        rgBuf[PARAMSIZE];
    int         an;
    char**      av;

    size= encodeTCSERVICESTARTAPPFROMAPP(szexecFile, an, av, PARAMSIZE, rgBuf);
    if(size<0) {
        fprintf(g_logFile, "startProcessLinuxService: encodeTCSERVICESTARTAPPFROMAPP failed\n");
        return false;
    }
    if(!g_reqChannel.sendtcBuf(g_myPid, TCSERVICESTARTAPPFROMAPP, 0, g_myPid, size, rgBuf)) {
        fprintf(g_logFile, "startProcessLinuxService: sendtcBuf for TCSERVICESTARTAPPFROMAPP failed\n");
        return false;
    }
    size= PARAMSIZE;
    if(!g_reqChannel.gettcBuf(&procid, &ureq, &ustatus, &origprocid, &size, rgBuf)) {
        fprintf(g_logFile, "startProcessLinuxService: gettcBuf for TCSERVICESTARTAPPFROMAPP failed\n");
        return false;
    }
    if(!decodeTCSERVICESTARTAPPFROMTCSERVICE(ppid, rgBuf)) {
        fprintf(g_logFile, "startProcessLinuxService: cant decode childproc\n");
        return false;
    }
#ifdef TEST
    fprintf(g_logFile, "startProcessLinuxService: Process created: %d by servicepid %d\n", 
            *ppid, g_myPid);
#endif
    return true;
}


bool sealfromDeviceDriver(int inSize, byte* inData, int* poutSize, byte* outData)
{
    u32         ustatus;
    u32         ureq;
    int         procid;
    int         origprocid;
    int         size= 0;
    byte        rgBuf[PARAMSIZE];

#ifdef TEST
    fprintf(g_logFile, "sealwithLinuxService(%d)\n", inSize);
#endif
    memset(outData, 0, *poutSize);
    size= encodeTCSERVICESEALFORFROMAPP(inSize, inData, PARAMSIZE, rgBuf);
    if(size<0) {
        fprintf(g_logFile, "sealwithLinuxService: encodeTCSERVICESEALFORFROMAPP failed\n");
        return false;
    }
    if(!g_reqChannel.sendtcBuf(getpid(), TCSERVICESEALFORFROMAPP, 0, 
                               getpid(), size, rgBuf)) {
        fprintf(g_logFile, "sealwithLinuxService: sendtcBuf for encodeTCSERVICESEALFORFROMAPP failed\n");
        return false;
    }
    size= PARAMSIZE;
    if(!g_reqChannel.gettcBuf(&procid, &ureq, &ustatus, &origprocid, &size, rgBuf)) {
        fprintf(g_logFile, "sealwithLinuxService: gettcBuf for encodeTCSERVICESEALFORFROMAPP failed\n");
        return false;
    }
    if(!decodeTCSERVICESEALFORFROMTCSERVICE(poutSize, outData, rgBuf)) {
        fprintf(g_logFile, "sealwithLinuxService: gettcBuf for decodeTCSERVICESEALFORFROMAPP failed\n");
        return false;
    }
#ifdef TCTEST1
    PrintBytes((char*)"To seal: ", inData, inSize);
    PrintBytes((char*)"Sealed :", outData, *poutSize);
#endif
    return true;
}


bool unsealfromDeviceDriver(int inSize, byte* inData, int* poutSize, byte* outData)
{
    u32         ustatus;
    u32         ureq;
    int         procid;
    int         origprocid;
    int         childproc;
    int         size= 0;
    byte        rgBuf[PARAMSIZE];

#ifdef TEST
    fprintf(g_logFile, "unsealwithLinuxService(%d)\n", inSize);
#endif
    memset(outData, 0, *poutSize);
    size= encodeTCSERVICEUNSEALFORFROMAPP(inSize, inData, PARAMSIZE, rgBuf);
    if(size<0) {
        fprintf(g_logFile, "unsealwithLinuxService: encodeTCSERVICEUNSEALFORFROMAPP failed\n");
        return false;
    }
    if(!g_reqChannel.sendtcBuf(getpid(), TCSERVICEUNSEALFORFROMAPP, 0, getpid(), size, rgBuf)) {
        fprintf(g_logFile, "unsealwithLinuxService: sendtcBuf for TCSERVICEUNSEALFORFROMAPP failed\n");
        return false;
    }
    size= PARAMSIZE;
    if(!g_reqChannel.gettcBuf(&procid, &ureq, &ustatus, &origprocid, &size, rgBuf)) {
        fprintf(g_logFile, "unsealwithLinuxService: gettcBuf for TCSERVICEUNSEALFORFROMAPP failed\n");
        return false;
    }
    if(!decodeTCSERVICEUNSEALFORFROMTCSERVICE(poutSize, outData, rgBuf)) {
        fprintf(g_logFile, "unsealwithLinuxService: gettcBuf for decodeTCSERVICESEALFORFROMTCSERVICE failed\n");
        return false;
    }
#ifdef TCTEST1
    PrintBytes((char*)"To unseal: ", inData, inSize);
    PrintBytes((char*)"Unsealed : ", outData, *poutSize);
#endif
    return true;
}


bool quotefromDeviceDriver(int inSize, byte* inData, int* poutSize, byte* outData)
{
    u32         ustatus;
    u32         ureq;
    int         procid;
    int         origprocid;
    int         size= 0;
    byte        rgBuf[PARAMSIZE];

#ifdef TEST
    fprintf(g_logFile, "quotewithLinuxService(%d, %d)\n", inSize, *poutSize);
#endif
    memset(outData, 0, *poutSize);
    size= encodeTCSERVICEATTESTFORFROMAPP(inSize, inData, PARAMSIZE, rgBuf);
    if(size<0) {
        fprintf(g_logFile, "quotewithLinuxService: encodeTCSERVICEATTESTFORFROMAPP failed\n");
        return false;
    }
#ifdef TEST1
    fprintf(g_logFile, "quotewithLinuxService: sending %d\n", inSize);
    PrintBytes((char*)" req buffer: ", inData, inSize); 
    fflush(g_logFile);
#endif
    if(!g_reqChannel.sendtcBuf(g_myPid, TCSERVICEATTESTFORFROMAPP, 0, procid, size, rgBuf)) {
        fprintf(g_logFile, "quotewithLinuxService: sendtcBuf for TCSERVICEATTESTFORFROMAPP failed\n");
        return false;
    }
    size= PARAMSIZE;
    if(!g_reqChannel.gettcBuf(&procid, &ureq, &ustatus, &origprocid, &size, rgBuf)) {
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
    PrintBytes((char*)"To quote: ", inData, inSize);
    PrintBytes((char*)"Quoted : ", outData, *poutSize);
    fflush(g_logFile);
#endif
    return true;
}


// -------------------------------------------------------------------------


