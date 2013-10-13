//  File: kvmncp.cpp
//      John Manferdelli
//
//  Description: Node control program for KVM host
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
#include "logging.h"

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
const char* szPolictHostAddr= "127.0.0.1";


// ------------------------------------------------------------------------


//
//  For now just start the designated partitions
//


#define BUFSIZE 2048


int main(int an, char** av)
{
    int             i;
    bool            fImageVms= false;
    bool            fMeasuredVms= false;
    int             numtoStart= 0;
    char            buf[BUFSIZE];
    const char**    nav= NULL;

    const char*     progDirectory= "/home/jlm/jlmcrypt";
    const char*     definedprogDirectory= getenv("CPProgramDirectory");

    if(definedprogDirectory!=NULL) {
        progDirectory= definedprogDirectory;
    }

    initLog(NULL);
    fprintf(g_logFile, "kvmncp.exe, %d args\n", an);
    for(i=0; i<an; i++) {
        fprintf(g_logFile, "\t%s\n", av[i]);
    }
    fflush(g_logFile);

    if(an<2 ||an>30 || strcmp(av[1],"-help")==0) {
        fprintf(g_logFile, "\tkvmncp.exe -ParitionImages  number-of-images programname1 xml-file1 image-file1 ... \n");
        fprintf(g_logFile, "\tkvmncp.exe -MeasuredPartitions  programname1 xml-file1 kernel-file1 initram-file1 image-file1 ... \n");
        return 1;
    }

    if(strcmp(av[1],"-PartitionImages")==0) {
        if(an<4) {
            fprintf(g_logFile, "kvmncp: launch images, wrong number of arguments\n");
            return 1;
        }
        int m= atoi(av[++i]);
        int k= an-i+1;
        if((k%3)!=0 || m!=(k/3)) {
            fprintf(g_logFile, "kvmncp: launch images, wrong number of arguments\n");
            return 1;
        }
        numtoStart= m;
        fprintf(g_logFile, "kvmncp: launch %d images\n", numtoStart);
        fImageVms= true;
        nav= (const char**) &av[++i];
    }
    else if(strcmp(av[1],"-MeasuredPartitions")==0) {
        if(an<4) {
            fprintf(g_logFile, "kvmncp: launch measured partitions, wrong number of arguments\n");
            return 1;
        }
        int m= atoi(av[++i]);
        int k= an-i+1;
        if((k%5)!=0 || m!=(k/5)) {
            fprintf(g_logFile, "kvmncp: launch measured partitions, wrong number of arguments\n");
            return 1;
        }
        numtoStart= k/5;
        fprintf(g_logFile, "kvmncp: launch %d measured partitions\n", numtoStart);
        fMeasuredVms= true;
        nav= (const char**) &av[++i];
    }
    else {
        fprintf(g_logFile, "kvmncp: unknown option\n");
        return 1;
    }

    for(i=0; i<numtoStart; i++) {
        if(fMeasuredVms) {
            // programname xml-file kernel-file initram-file image-file
            sprintf(buf, "%s/tcLaunch.exe -KVMLinux %s %s %s %s %s\n", progDirectory,
                    nav[5*i], nav[5*i+1], nav[5*i+2], nav[5*i+3], nav[5*i+4]);
        }
        else if(fImageVms) {
            // programname xml-file image-file \n");
            sprintf(buf, "%s/tcLaunch.exe -KVMImage %s %s %s\n", progDirectory,
                    nav[3*i], nav[3*i+1], nav[3*i+2]);
        }
        else {
            fprintf(g_logFile, "kvmncp: shouldn't happen\n");
            return 1;
        }
        if(system(buf)<0) {
            fprintf(g_logFile, "kvmncp: partition %d failed to launch\n");
            return 1;
        }
    }

    //
    //   Todo:  Programs should now open command channel and wait for
    //   signed requests from fabric controller

    fprintf(g_logFile, "kvmncp: all partitions successfully launched\n");
    closeLog();
    return 0;
}


// ------------------------------------------------------------------------


