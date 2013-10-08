//  File: linuxHostsupport.h
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
#include "tcIO.h"
#include "buffercoding.h"
#include <string.h>
#include <time.h>



#ifndef _LINUXHOSTSUPPORT__H
#define _LINUXHOSTSUPPORT__H


//
//   Service support from LINUX
//


// Class supporting request channel to device driver

class  linuxDeviceChannel {
public:
    tcChannel   m_reqChannel;
    bool        m_fChannelInitialized;
    char*       m_driverName;
    int         m_myPid;
    bool        m_famService;

    linuxDeviceChannel();
    ~linuxDeviceChannel();

    bool    initLinuxService(const char* name, bool fService);
    bool    closeLinuxService();
    bool    tcserviceHello();
    bool    tcserviceGoodbye();

    bool    getEntropyfromDeviceDriver(int size, byte* pKey);
    bool    getprogramNamefromDeviceDriver(int* pSize, const char* szName);
    bool    getpolicykeyfromDeviceDriver(u32* pkeyType, int* pSize, byte* pKey);
    bool    getOSMeasurementfromDeviceDriver(u32* phashType, int* pSize, byte* pHash);
    bool    getHostedMeasurementfromDeviceDriver(int childproc, u32* phashType, 
                                                 int* pSize, byte* pHash);
    bool    startAppfromDeviceDriver(int* ppid, int argc, char **argv);
    bool    sealfromDeviceDriver(int inSize, byte* inData, int* poutSize, byte* outData);
    bool    unsealfromDeviceDriver(int inSize, byte* inData, int* poutSize, byte* outData);
    bool    quotefromDeviceDriver(int inSize, byte* inData, int* poutSize, byte* outData);
};


#endif


// -------------------------------------------------------------------------


