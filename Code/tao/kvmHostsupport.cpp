//  File: kvmHostsupport.cpp
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


#include <dirent.h>


bool isnum(const char* p)
{
    if(p==NULL)
        return false;
    while(*p!='\0') {
        if(*p<'0' || *p>'9')
            return false;
        p++;
    }
    return true;
}


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


pidMapper::pidMapper()
{
    m_numrefpids= 0;
    const char* defDir= getenv(ENVDEFINEDQEMUDIR);
    if(defDir!=NULL)
        m_qemudir= defDir;
    else
        m_qemudir= QEMUPIDIR;
}


pidMapper::~pidMapper()
{
    m_numrefpids= 0;
}


bool pidMapper::addbasepid(int mainpid, int numrefs, int* rgrefs)
{
    int     j, k;

    if(m_numrefpids>=MAXPIDS)
        return false;
    k= m_numrefpids;
    m_basepid[k]= mainpid;
    m_refpid[k]= mainpid;
    m_numrefpids++;

    for(j=0;j<numrefs;j++) {
        if(m_numrefpids>=MAXPIDS)
            return false;
        k= m_numrefpids;
        m_basepid[k]= mainpid;
        m_refpid[k]= rgrefs[j];
        m_numrefpids++;
    }

    return true;
}


int pidMapper::getbasepid(int apid)
{
    int i;

    for(i=0; i<m_numrefpids; i++) {
        if(apid==m_refpid[i])
            return m_basepid[i];
    }
    return -1;
}


bool pidMapper::getkvmpids(const char* name, int* pmainpid, int* pnvcpus, int* rgpids)
{
    char            buf[BUFSIZE];
    char            line[BUFSIZE];
    int             mainpid= -1;
    char*           beginline= line;
    char*           szpidFile= NULL;
    char*           sztaskDir= NULL;
    int             numlines= 0;
    int             size= 0;
    struct dirent*  pent= NULL;
    DIR*            dent= NULL;
    int             numCPUs= 0;
    bool            fRet= false;

#ifdef TEST
    fprintf(g_logFile, "getkvmpids(%s), %s\n", name, m_qemudir);
#endif

    // pid file name
    sprintf(buf, "%s/%s.pid", m_qemudir, name);
    szpidFile= strdup(buf);

    // open the logfile and get the pid
    int fd= open(szpidFile, O_RDONLY);
    if(fd<0) {
        fprintf(g_logFile, "getkvmpids: cant open pid file %s\n", szpidFile);
        return false;
    }
    if((size=read(fd, line, BUFSIZE))<0) {
        fprintf(g_logFile, "getkvmpids: read failed\n");
        close(fd);
        return false;
    }
    while(beginline!=NULL) {
        sscanf(beginline, "%d", &mainpid);
        numlines++;
        beginline= nextline(beginline, &line[size-1]);
    }
    close(fd);

    if(mainpid<0) {
        fprintf(g_logFile, "getkvmpids: main pid failed\n");
        return false;
    }

    sprintf(buf, "/proc/%d/task", mainpid);
    sztaskDir= strdup(buf);

    dent= opendir(sztaskDir);

    while((pent=readdir(dent))!=NULL && numCPUs<*pnvcpus) {
        if(!isnum(pent->d_name))
            continue;
        rgpids[numCPUs]= atoi(pent->d_name);
        numCPUs++;
    }
    closedir(dent);
    fRet= true;

    *pmainpid= mainpid;
    *pnvcpus= numCPUs;

#ifdef TEST
    fprintf(g_logFile, "\ngetkvmpids\nmain pid: %d\n", mainpid);
    fprintf(g_logFile, "num pids: %d\n\t", numCPUs);
    for(int i=0; i<numCPUs; i++) {
        fprintf(g_logFile, "%d ", rgpids[i]);
    }
    fprintf(g_logFile, "\n");
#endif

// done:
    if(szpidFile!=NULL) {
        free(szpidFile);
        szpidFile= NULL;
    }
    if(sztaskDir!=NULL) {
        free(sztaskDir);
        sztaskDir= NULL;
    }
    return fRet;
}



int pidMapper::initKvm(const char* name)
{
    int         mainpid= 0;
    int         nvcpus= NUMVCPUS;
    int         rgpids[NUMVCPUS];

#ifdef TEST
    fprintf(g_logFile, "initKvm(%s)\n", name);
#endif

    if(!getkvmpids(name, &mainpid, &nvcpus, rgpids)) {
        fprintf(g_logFile, "initKvm: getkvmpids failed\n");
        return -1;
    }

    if(!addbasepid(mainpid, nvcpus, rgpids)) {
        fprintf(g_logFile, "initKvm: addbasepid failed\n");
        return -1;
    }
    return mainpid;
}


void printVirtlibError()
{
    virError*    err;

    err= virGetLastError();
    fprintf(g_logFile, "Error: %s\n", err->message);
    fflush(g_logFile);
}


bool startKvmVM(const char* programname, const char* systemname, 
               const char* xmldomainstring, 
               virConnectPtr* ppvmconnection, virDomainPtr*  ppvmdomain)
{
#ifdef TEST
    fprintf(g_logFile, "startKvmVM: %s\n%s\n",
            systemname, xmldomainstring);
    fflush(g_logFile);
#endif

#ifdef KVMTCSERVICE
#ifdef TEST
    fprintf(g_logFile, "startKvmVM service code included\n");
    fflush(g_logFile);
#endif

    if(systemname==NULL || xmldomainstring==NULL) {
        fprintf(g_logFile, "startKvm: Bad input arguments\n");
        return false;
    }

    // Replace later with virConnectOpenAuth(name, virConnectAuthPtrDefault, 0)
    *ppvmconnection= virConnectOpen(systemname);
    if(*ppvmconnection==NULL) {
        fprintf(g_logFile, "startKvm: couldn't connect\n");
        printVirtlibError();
        return false;
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
        return false;
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
#ifdef TEST
    fprintf(g_logFile, "startKvm: programname: %s\n", programname);
    fflush(g_logFile);
#endif
    return true;

#else       // KVMTCSERVICE
#ifdef TEST
    fprintf(g_logFile, "startKvmVM service code NOT included\n");
    fflush(g_logFile);
#endif
    return false;
#endif      // KVMTCSERVICE
}


// -------------------------------------------------------------------------


