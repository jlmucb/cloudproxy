//  File: testKvmLaunch.cpp
//      John Manferdelli
//
//  Description: Stand alone launch of measured programs
//               and partitions.
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


#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <dirent.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

#include <string>
#include <iostream>
#include <fstream>
#include <sstream>
using std::string;
using std::ifstream;
using std::ofstream;
using std::stringstream;


// ------------------------------------------------------------------------


#include <dirent.h>
#define QEMUPIDIR "/var/lib/libvirt/qemu"
#define ENVDEFINEDQEMUDIR "CPQemuDir"


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


class pidMapper {
public:
    enum    {MAXPIDS=1000, NUMVCPUS= 64};


    int         m_numrefpids;
    int         m_basepid[MAXPIDS];
    int         m_refpid[MAXPIDS];
    const char* m_qemudir;

                pidMapper();
                ~pidMapper();

    bool        addbasepid(int mainpid, int numrefs, int* rgrefs);
    int         getbasepid(int apid);
    bool        getkvmpids(const char* name, int* pmainpid, 
                           int* pnvcpus, int* rgpids);
    bool        initKvm(const char* name);
};


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
    printf("getkvmpids(%s)\n", name);
#endif

    // pid file name
    // sprintf(buf, "%s/%s.pid", m_qemudir, name);
    sprintf(buf, "/Users/jlm/jlmcrypt/testKvm/%s.pid", name);
    szpidFile= strdup(buf);

    // open the logfile and get the pid
    int fd= open(szpidFile, O_RDONLY);
    if(fd<0) {
        printf("getkvmpids: cant open pid file %s\n", szpidFile);
        return false;
    }
    if((size=read(fd, line, BUFSIZE))<0) {
        printf("getkvmpids: read failed\n");
        close(fd);
        return false;
    }
    while(beginline!=NULL) {
        sscanf(beginline, "%d", &mainpid);
        numlines++;
        beginline= nextline(beginline, &line[size-1]);
    }
    close(fd);

    // sprintf(buf, "/proc/%d/task", mainpid);
    sprintf(buf, "/Users/jlm/jlmcrypt/testKvm/%d/task", mainpid);
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
    printf("\ngetkvmpids\nmain pid: %d\n", mainpid);
    printf("num pids: %d\n\t", numCPUs);
    for(int i=0; i<numCPUs; i++) {
        printf("%d ", rgpids[i]);
    }
    printf("\n");
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



bool pidMapper::initKvm(const char* name)
{
    int         mainpid= 0;
    int         nvcpus= NUMVCPUS;
    int         rgpids[NUMVCPUS];

#ifdef TEST
    printf("initKvm(%s)\n", name);
#endif

    if(!getkvmpids(name, &mainpid, &nvcpus, rgpids)) {
        printf("initKvm: getkvmpids failed\n");
        return false;
    }

    if(!addbasepid(mainpid, nvcpus, rgpids)) {
        printf("initKvm: addbasepid failed\n");
        return false;
    }
    return true;
}


// ------------------------------------------------------------------------


int main(int an, char** av)
{
    int         j,k;
    const char* name= NULL;
    pidMapper   pidMap;

    printf("testKvmLaunch.exe, %d args\n", an);
    for(int i=0; i<an; i++) {
        printf("\t%s\n", av[i]);
    }
    name= av[1];

    if(an<2 || strcmp(av[1],"-help")==0) {
        printf("\ttestKvmLaunch.exe vmName\n");
        return 1;
    }

    if(!pidMap.initKvm(name)) {
        printf("initKvm failed\n");
    }
    printf("initKvm succeeded\n");

    j= 6;
    k= pidMap.getbasepid(j);
    printf("base[%d]: %d\n", j, k);
    j= 22;
    k= pidMap.getbasepid(j);
    printf("base[%d]: %d\n", j, k);
    j= 26;
    k= pidMap.getbasepid(j);
    printf("base[%d]: %d\n", j, k);
    j= 25;
    k= pidMap.getbasepid(j);
    printf("base[%d]: %d\n", j, k);

    return 0;
}


// ------------------------------------------------------------------------


