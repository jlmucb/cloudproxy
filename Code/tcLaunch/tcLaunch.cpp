//  File: tcLaunch.cpp
//      John Manferdelli
//
//  Description: Client for fileServer.
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
#include "jlmUtility.h"
#include "logging.h"
#include "channel.h"
#include "tinyxml.h"
#include "request.h"
#include "linuxHostsupport.h"
#include "kvmHostsupport.h"
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <dirent.h>

#include <string>
#include <iostream>
#include <fstream>
#include <sstream>
using std::string;
using std::ifstream;
using std::ofstream;
using std::stringstream;
const char* szServerHostAddr= "127.0.0.1";

#ifdef KVMTCSERVICE
const char* g_tcioDDName= "kvmtciodd0";
#endif
#ifdef KVMGUESTOSTCSERVICE 
const char* g_tcioDDName= "ktciodd0";
#endif
#ifdef LINUXTCSERVICE 
const char* g_tcioDDName= "tcioDD0";
#endif


// ------------------------------------------------------------------------



bool startAsVm(int an, char** av)
{
    int     n= 0;

    UNUSEDVAR(n);
//    if(!initLinuxService(g_tcioDDName))
//        return false;
 //   if(!startAppfromDeviceDriver(av[0], &n, an, av))
  //      return false;
    return true;
}


bool startAsMeasuredProgram(int an, char** av)
{
    int     n= 0;

    if(!initLinuxService(g_tcioDDName))
        return false;
    if(!startAppfromDeviceDriver(av[0], &n, an, av))
        return false;
    return true;
}


// ------------------------------------------------------------------------


int main(int an, char** av)
{
    int             i;
    const char*     directory= NULL;
    char*           szPort= (char*)"";
    char*           szAddress= (char*)"";
    char*           parameter= (char*)"";
    char*           program= (char*)"";

#ifdef  TEST
    initLog(NULL);
    fprintf(g_logFile, "tcLaunch test\n");
    fflush(g_logFile);
#endif
    UNUSEDVAR(directory);
    UNUSEDVAR(szPort);
    UNUSEDVAR(szAddress);
    if(an>1) {
        for(i=0;i<an;i++) {
            if(strcmp(av[i],"-port")==0 && an>(i+1)) {
                szPort= strdup(av[++i]);
            }
            if(strcmp(av[i],"-address")==0) {
                szAddress= strdup(av[++i]);
            }
            if (strcmp(av[i],"-directory")==0) {
                directory= strdup(av[++i]);
            }
        }
    }

    initLog("tcLaunch.log");

#ifdef  TEST
    fprintf(g_logFile, "tcLaunch main starting measured %s\n", av[0]);
#endif

     if(!initLinuxService(parameter)) {
        fprintf(g_logFile, "taoHostServices::HostInit: cant init Linuxservice\n");
        return false;
    }
    int   handle= 0;

    startAppfromDeviceDriver(program, &handle, an, av);

#ifdef TEST
    fprintf(g_logFile, "main: measured program started, exiting\n");
    fflush(g_logFile);
#endif
    closeLog();
    return 0;
}


// ------------------------------------------------------------------------


