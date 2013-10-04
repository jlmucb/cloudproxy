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
#include <stdlib.h>
#include <time.h>
#include <time.h>


//  Config
//      listen_tls= 0
//      listen_tcp= 1
//      auth_tcp= "sasl"
//      mech_list: digest-md5


// -------------------------------------------------------------------------


void printVirtlibError()
{
    virError*    err;

    err= virGetLastError();
    fprintf(g_logFile, "Error: %s\n", err->message);
    fflush(g_logFile);
}


int startKvmVM(const char* systemname, const char* xmldomainstring, 
                virConnectPtr* ppvmconnection,
                virDomainPtr*  ppvmdomain)
// returns -1 if error, vmid otherwise
{
#ifdef TEST
    fprintf(g_logFile, "startKvmVM: %s\n%s\n",
            systemname, xmldomainstring);
    fflush(g_logFile);
#endif

#ifdef KVMTCSERVICE
    int     vmid= 0;

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

#ifdef TEST
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
#endif
    vmid= (int)virDomainGetID(*ppvmdomain);
    return vmid;

#else       // KVMTCSERVICE
#ifdef TEST
    fprintf(g_logFile, "startKvmVM service code NOT included\n");
    fflush(g_logFile);
#endif
    return -1;
#endif      // KVMTCSERVICE
}


// -------------------------------------------------------------------------


