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



#ifdef LINUXHOSTSERVICE
const u32   g_hostplatform= PLATFORMTYPELINUX;
const u32   g_envplatform= PLATFORMTYPELINUXAPP;
const char* g_hostProvider= "/dev/tcioDD0";
const char* g_serviceProvider= "/dev/tcioDD0";
const char* g_serviceexecFile= "./tcService.exe";
const char* g_logName= "tcService.log";
const char* g_hostDirectory= "/home/jlm/jlmcrypt";
const char* g_hostsubDirectory= "TrustedOS";
#endif

#ifdef LINUXGUESTSERVICE
const u32   g_hostplatform= PLATFORMTYPEGUESTLINUX;
const u32   g_envplatform= PLATFORMTYPELINUXAPP;
const char* g_hostProvider= "/dev/ktciodd0";
const char* g_serviceProvider= "/dev/tcioDD0";
const char* g_serviceexecFile= "./tcGuestService.exe";
const char* g_logName= "tcGuestService.log";
const char* g_hostDirectory= "/home/jlm/jlmcrypt";
const char* g_hostsubDirectory= "TrustedOS";
#endif


// ------------------------------------------------------------------------


