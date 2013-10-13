//  File: kvmHostsupport.cpp
//      John Manferdelli
//  Description:  Support for KVM host
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
#include "kvmHostsupport.h"

#include <libvirt/libvirt.h>
#include <libvirt/virterror.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>



//  Config
//      listen_tls= 0
//      listen_tcp= 1
//      auth_tcp= "sasl"
//      mech_list: digest-md5


// reset from environment variable CPProgramDirectory, if defined
extern const char* g_progDirectory;


// -------------------------------------------------------------------------


#define BUFSIZE 2048
#define NAMESIZE 256

char *nextline(char* start, char* end)
{
    while(start<end) {
        if(*start=='\n') {
            start++;
            if(start<end && *start!='\0')
                return start;
            else
                return NULL;
        }
        start++;
    }
    return NULL;
}


int  getmysyspid(const char* name)
{
    char    buf[BUFSIZE];
    char    fileName[256];
    char    line[BUFSIZE];
    int     mypid= getpid();
    int     newpid= -1;
    int     size= -1;
    char*   beginline= line;

    sprintf(fileName, "%s/tmp%d.tmp", g_progDirectory, mypid);
    sprintf(buf, "ps ax | grep \"%s\"|awk '{print $1}'>%s",
            name, fileName);
#ifdef TEST
    fprintf(g_logFile, "getmysyspid command: %s\n", buf);
    fflush(g_logFile);
#endif
#if 0
    if(system(buf)<0) {
        fprintf(g_logFile, "getmysyspid: system command failed\n");
        return -1;
    }
#else
    size= system(buf);
    size= -1;
#endif
    // open the logfile and get the pid
    int fd= open(fileName, O_RDONLY);
    if(fd<0) {
        fprintf(g_logFile, "getmysyspid: cant open file\n");
        return -1;
    }
    if((size=read(fd, line, BUFSIZE))<0) {
        fprintf(g_logFile, "getmysyspid: read failed\n");
        return -1;
    }
    while(beginline!=NULL) {
	// the following line is a cludge.  First one is tcLaunch.
        beginline= nextline(beginline, &line[size-1]);
        sscanf(beginline, "%d", &newpid);
        if(newpid!=mypid)
            break;
        newpid= -1;
        beginline= nextline(beginline, &line[size-1]);
    }
    close(fd);
#ifndef TEST1
    unlink(fileName);
#endif
    // TODO: hack fix later (see tcLaunch)
    return newpid+2;
}


void printVirtlibError()
{
    virError*    err;

    err= virGetLastError();
    fprintf(g_logFile, "Error: %s\n", err->message);
    fflush(g_logFile);
}


int startKvmVM(const char* programname, const char* systemname, const char* xmldomainstring, 
                virConnectPtr* ppvmconnection,
                virDomainPtr*  ppvmdomain)
// returns -1 if error, pid otherwise
{
#ifdef TEST
    fprintf(g_logFile, "startKvmVM: %s\n%s\n",
            systemname, xmldomainstring);
    fflush(g_logFile);
#endif

#ifdef KVMTCSERVICE
    int     pid= -1;

#ifdef TEST
    fprintf(g_logFile, "startKvmVM service code included\n");
    fflush(g_logFile);
#endif

    if(systemname==NULL || xmldomainstring==NULL) {
        fprintf(g_logFile, "startKvm: Bad input arguments\n");
        return -1;
    }

    // Replace later with virConnectOpenAuth(name, virConnectAuthPtrDefault, 0)
    *ppvmconnection= virConnectOpen(systemname);
    if(*ppvmconnection==NULL) {
        fprintf(g_logFile, "startKvm: couldn't connect\n");
         printVirtlibError();
        return -1;
    }
#ifdef TEST
    fprintf(g_logFile, "startKvm: connection succeeded\n");
    fflush(g_logFile);
#endif

#ifdef TEST1
    char*   szCap= virConnectGetCapabilities(*ppvmconnection);
    fprintf(g_logFile, "VM Host capabilities:\n%s\n", szCap);
    fflush(g_logFile);
    free(szCap);
    char*   szHostname= virConnectGetHostname(*ppvmconnection);
    fprintf(g_logFile, "Host name: %s\n", szHostname);
    fflush(g_logFile);
    free(szHostname);
    int ncpus= virConnectGetMaxVcpus(*ppvmconnection, NULL);
    fprintf(g_logFile, "Virtual cpus: %d\n", ncpus);
    fflush(g_logFile);
    virNodeInfo oInfo;
    virNodeGetInfo(*ppvmconnection, &oInfo);
    fprintf(g_logFile, "\tModel : %s\n", oInfo.model);
    fprintf(g_logFile, "\tMemory size: %d\n", oInfo.memory);
    fprintf(g_logFile, "\tNum cpus: %d\n", oInfo.cpus);
    fflush(g_logFile);
#endif
   
    *ppvmdomain= virDomainCreateXML(*ppvmconnection, xmldomainstring, 0); 
    if(*ppvmdomain==NULL) {
        fprintf(g_logFile, "startKvm: couldn't start domain\n");
         printVirtlibError();
        return -1;
    }
#ifdef TEST
    fprintf(g_logFile, "startKvm: virDomainCreateXML succeeded\n");
    fflush(g_logFile);
#endif
#ifdef TEST
    int     vmid= 0;
    int     ndom= virConnectNumOfDomains(*ppvmconnection);
    fprintf(g_logFile, "%d domains\n", ndom);

    int*    rgactiveDomains= (int*)malloc(sizeof(int)*ndom);
    int     i;
    ndom= virConnectListDomains(*ppvmconnection, rgactiveDomains, ndom);
    fprintf(g_logFile, "active domains\n");
    for(i=0; i<ndom; i++) {
        fprintf(g_logFile, "\t%d\n", rgactiveDomains[i]);
    }
    fflush(g_logFile);
    vmid= (int)virDomainGetID(*ppvmdomain);
    fprintf(g_logFile, "vmid: %d\n", vmid);
#endif
    pid= getmysyspid(programname);
#ifdef TEST
    fprintf(g_logFile, "startKvm: programname: %s, pid: %d\n", programname, pid);
    fflush(g_logFile);
#endif
    return pid;

#else       // KVMTCSERVICE
#ifdef TEST
    fprintf(g_logFile, "startKvmVM service code NOT included\n");
    fflush(g_logFile);
#endif
    return -1;
#endif      // KVMTCSERVICE
}


// -------------------------------------------------------------------------


