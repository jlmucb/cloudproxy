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
#include "kvmHostsupport.h"
#include "kvmHostsupport.h"
#include <libvirt/libvirt.h>
#include <string.h>
#include <time.h>


//  Config
//      listen_tls= 0
//      listen_tcp= 1
//      auth_tcp= "sasl"
//      mech_list: digest-md5


// -------------------------------------------------------------------------


int startKvmVM(const char* szvmimage, const char* systemname,
                const char* xmldomainstring, const char* szdomainName,
		tcServiceInterface* ptc)

// returns -1 if error, vmid otherwise

{
#ifdef KVMTCSERVICE
    int     vmid= 0;  //TODO
    if(szvmimage==NULL || systemname==NULL || xmldomainstring==NULL ||
                          szdomainName==NULL) {
        fprintf(g_logFile, "startKvm: Bad input arguments\n");
        return -1;
    }

#ifdef TEST
    fprintf(g_logFile, "startKvm: %s, %s, %s %s\n", 
               szvmimage, systemname, xmldomainstring, szdomainName);
#endif

    // Replace later with virConnectOpenAuth(name, virConnectAuthPtrDefault, 0)
    ptc->m_vmconnection= virConnectOpen(systemname);
    if(ptc->m_vmconnection==NULL) {
        fprintf(g_logFile, "startKvm: couldn't connect\n");
        return -1;
    }

#ifdef TEST
    char*   szCap= virConnectGetCapabilities(ptc->m_vmconnection);
    fprintf(g_logFile, "VM Host capabilities:\n%s\n", szCap);
    free(szCap);
    char*   szHostname= virConnectGetHostname(ptc->m_vmconnection);
    fprintf(g_logFile, "Host name: %s\n", szHostname);
    free(szszHostname);
    int ncpus= virConnectGetMaxVcpus(ptc->m_vmconnection);
    fprintf(g_logFile, "Virtual cpus: %d\n", ncpus);
    virNodeInfo oInfo;
    virNodeGetInfo(ptc->m_vmconnection, &oInfo);
    fprintf(g_logFile, "\tModel : %s\n", oInfo.model);
    fprintf(g_logFile, "\tMemory size: %d\n", oInfo.memory);
    fprintf(g_logFile, "\tNum cpus: %d\n", oInfo.cpus);
#if 0
    virErrorPtr  err;
    err= virGetLastError();
    fprintf(g_logFile, "Error: %s\n", err->message);
#endif
#endif
   
    ptc->m_vmdomain= virDomainCreateXML(ptc->m_vmconnection, xmldomainstring, 0); 
    if(ptc->m_vmdomain==NULL) {
        fprintf(g_logFile, "startKvm: couldn't start domain\n");
        return -1;
    }
#ifdef TEST
    int     ndom= virConnectNumDomains(ptc->m_vmconnection);
    fprintf(g_logFile, "%d domains\n", ndom);

    int*    rgactiveDomains= malloc(sizeof(int)*ndom);
    int     i;
    ndom= virConnectListDomains(ptc->m_vmconnection, rgactiveDomains, ndom);
    fprintf(g_logFile, "active domains\n");
    for(i=0; i<ndom; i++) {
        fprintf(g_logFile, "\t%d\n", activeDomains[i]);
    }
#endif

    return vmid;
#else
    return -1;
#endif
}


// -------------------------------------------------------------------------


