//  File: taoSetupglobals.h
//      John Manferdelli
//
//  Description: globals to init tao host and environment
//
//  Copyright (c) 2011, Intel Corporation. Some contributions 
//    (c) John Manferdelli.  All rights reserved.
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


// ------------------------------------------------------------------------


#include "jlmTypes.h"


extern const char* g_progDirectory;
const char* g_hostDirectory= "/home/jlm/jlmcrypt";


#ifdef KVMTCSERVICE
const u32   g_hostplatform= PLATFORMTYPEHW;
const u32   g_envplatform= PLATFORMTYPEKVMHYPERVISOR;
const char* g_hostProvider= "/dev/tpm0";
const char* g_serviceProvider= "/dev/kvmtciodd0";
const char* g_progName= "KvmHost";
const char* g_serviceexecFile= "./tcKvmHostService.exe";
const char* g_logName= "tcKvmHostService.log";
const char* g_hostsubDirectory= "HWRoot";
const char* g_clientsubDirectory= "KvmHost";
const char* g_myServiceName= "tcKvmHostService.exe";
#endif

#ifdef LINUXTCSERVICE 
const u32   g_hostplatform= PLATFORMTYPEHW;
const u32   g_envplatform= PLATFORMTYPELINUX;
const char* g_hostProvider= "/dev/tpm0";
const char* g_serviceProvider= "/dev/tcioDD0";
const char* g_progName= "TrustedOS";
const char* g_serviceexecFile= "./tcService.exe";
const char* g_logName= "tcService.log";
const char* g_hostsubDirectory= "HWRoot";
const char* g_clientsubDirectory= "TrustedOS";
const char* g_myServiceName= "tcService.exe";
#endif

#ifdef KVMGUESTOSTCSERVICE 
const char* g_hostProvider= "/dev/ktciodd0";
const char* g_serviceProvider= "/dev/tcioDD0";
const u32   g_hostplatform= PLATFORMTYPEKVMHYPERVISOR;
const u32   g_envplatform= PLATFORMTYPEKVMHOSTEDLINUXGUESTOS;
const char* g_progName= "KvmGuest";
const char* g_serviceexecFile= "./tcKvmGuestOsService.exe";
const char* g_logName=  "tcKvmGuestOsService.log";
const char* g_hostsubDirectory= "KvmHost";
const char* g_clientsubDirectory= "GuestOS";
const char* g_myServiceName= "tcKvmGuestOSService.exe";
#endif


// ------------------------------------------------------------------------


