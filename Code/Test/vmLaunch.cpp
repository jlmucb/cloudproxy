//  File: vmLaunch.cpp
//      John Manferdelli
//
//  Description: Test for vmLaunch
//
//  Copyright (c) 2013, Intel Corporation. Some contributions 
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
#include "tinyxml.h"
#include "kvmHostsupport.h"
#include "fileHash.h"
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

int         g_myPid;


// -------------------------------------------------------------------------


#define MAXPROGNAME 512


char* programNamefromFileName(const char* fileName)
{
    char*   p= (char*) fileName;
    char*   q;
    char*   r;
    char    progNameBuf[MAXPROGNAME];

    if(fileName==NULL)
        return NULL;
#ifdef TEST
    fprintf(g_logFile, "fileName: %s\n", fileName);
#endif
    while(*p!='\0')
        p++;
    q= p-1;
    while((--p)!=fileName) {
        if(*p=='/') {
            break;
        }
        if(*p=='.') {
            break;
        }
    }

    if(*p=='/') {
        r= p+1;
    }
    else if(*p=='.') {
        q= p-1;
        r= q;
        while(r>=fileName) {
            if(*r=='/')
                break;
            r--;
        }
    }
    else {
        r= (char*)fileName-1;
    }
    if((q-r)>=(MAXPROGNAME-1))
        return NULL;
    r++;
    p= progNameBuf;
    while(r<=q)
        *(p++)= *(r++);
    *p= '\0';
    q= strdup(progNameBuf);
#ifdef TEST
    fprintf(g_logFile, "fileName: %s, progname: %s\n", fileName, q);
#endif
    return q;
}


// template vm xml
const char* g_imagetemplatexml=
"<domain type='kvm'>\n"\
"  <name>%s</name>\n"\
"  <uuid>ee344f89-40bc-47a9-3b53-b911e32c61ff</uuid>\n"\
"  <memory>1048576</memory>\n"\
"  <currentMemory>1048576</currentMemory>\n"\
"  <vcpu>1</vcpu>\n"\
"  <os>\n"\
"    <type arch='x86_64' machine='pc-1.0'>hvm</type>\n"\
"    <boot dev='hd'/>\n"\
"  </os>\n"\
"  <features>\n"\
"    <acpi/>\n"\
"    <apic/>\n"\
"    <pae/>\n"\
"  </features>\n"\
"  <clock offset='utc'/>\n"\
"  <on_poweroff>destroy</on_poweroff>\n"\
"  <on_reboot>restart</on_reboot>\n"\
"  <on_crash>restart</on_crash>\n"\
"  <devices>\n"\
"    <emulator>/usr/bin/kvm</emulator>\n"\
"    <disk type='file' device='disk'>\n"\
"      <driver name='qemu' type='raw'/>\n"\
"      <source file='%s'/>\n"\
"      <target dev='hda' bus='ide'/>\n"\
"      <address type='drive' controller='0' bus='0' unit='0'/>\n"\
"    </disk>\n"\
"    <disk type='file' device='cdrom'>\n"\
"      <driver name='qemu' type='raw'/>\n"\
"      <source file='/home/jlm/tmp/ubuntu-12.04.2-desktop-amd64.iso'/>\n"\
"      <target dev='hdc' bus='ide'/>\n"\
"      <readonly/>\n"\
"      <address type='drive' controller='0' bus='1' unit='0'/>\n"\
"    </disk>\n"\
"    <controller type='ide' index='0'>\n"\
"      <address type='pci' domain='0x0000' bus='0x00' slot='0x01' function='0x1'/>\n"\
"    </controller>\n"\
"    <interface type='bridge'>\n"\
"      <mac address='52:54:00:82:22:a8'/>\n"\
"      <source bridge='virbr0'/>\n"\
"      <address type='pci' domain='0x0000' bus='0x00' slot='0x03' function='0x0'/>\n"\
"    </interface>\n"\
"    <serial type='pty'>\n"\
"      <target port='0'/>\n"\
"    </serial>\n"\
"    <console type='pty'>\n"\
"      <target type='serial' port='0'/>\n"\
"    </console>\n"\
"    <input type='mouse' bus='ps2'/>\n"\
"    <graphics type='vnc' port='-1' autoport='yes'/>\n"\
"    <sound model='ich6'>\n"\
"      <address type='pci' domain='0x0000' bus='0x00' slot='0x04' function='0x0'/>\n"\
"    </sound>\n"\
"    <video>\n"\
"      <model type='cirrus' vram='9216' heads='1'/>\n"\
"      <address type='pci' domain='0x0000' bus='0x00' slot='0x02' function='0x0'/>\n"\
"    </video>\n"\
"    <memballoon model='virtio'>\n"\
"      <address type='pci' domain='0x0000' bus='0x00' slot='0x05' function='0x0'/>\n"\
"    </memballoon>\n"\
"  </devices>\n"\
"</domain>\n";


#define MAXMLBUF 4096



bool uidfrompid(int pid, int* puid)
{
    char        szfileName[256];
    struct stat fattr;

    sprintf(szfileName, "/proc/%d/stat", pid);
    if((lstat(szfileName, &fattr))!=0) {
        printf("uidfrompid: stat failed\n");
        return false;
    } 
    *puid= fattr.st_uid;
    return true;
}


// ---------------------------------------------------------------------------


bool startLinuxvm(const char* ramName, const char* kernelName) 
{
    return false;
}


bool startImagevm(const char* imageName) 
{
    char*   szProgName= NULL;
    int     procid= getpid();
    int     vmid= -1;

    if(imageName==NULL) {
        fprintf(g_logFile, "startImagevm error: empty image name\n");
        return false;
    }
    szProgName= programNamefromFileName(imageName);

    // lock file
    int             fd= open(imageName, O_RDONLY);
    int             uid= 0;
    u32             uType= 0;
    int             size;
    byte            rgHash[64];

#ifdef TEST
    fprintf(g_logFile, "startImagevm(%s)\n", imageName);
    fflush(g_logFile);
#endif

    if(fd<0) {
        fprintf(g_logFile, "startImagevm error: cant measure %s\n", imageName);
        return false;
    }

#ifdef LOCKFILE
    struct flock    lock;
    // F_UNLCK
    lock.l_type= F_WRLCK;
    lock.l_start= 0;
    lock.l_len= SEEK_SET;
    lock.l_pid= procid;
    int     ret= fcntl(fd, F_SETLK, &lock);
    if(ret<0)
        return false;
#endif

    if(!getfileHash(imageName, &uType, &size, rgHash)) {
        fprintf(g_logFile, "startImagevm error: getfilehash failed %s\n",imageName);
        return false;
    }

    // look up uid for procid
    if(!uidfrompid(procid, &uid)) {
        fprintf(g_logFile, "startImagevm error: cant get uid from procid\n");
        return false;
    }

#ifdef TEST
    fprintf(g_logFile, "uid of VM is %d\n", uid);
    PrintBytes((char*)"Hash of image is: ", rgHash, 32);
    fprintf(g_logFile, "\n");
    fflush(g_logFile);
#endif

    {
        const char*     szsys= "qemu:///system";
        char            buf[MAXMLBUF];

       sprintf(buf, g_imagetemplatexml, szProgName, imageName);
       virConnectPtr    vmconnection= NULL;
       virDomainPtr     vmdomain= NULL;

#ifdef TEST
        fprintf(g_logFile, "xml to start vm:\n%s\n", buf);
        fflush(g_logFile);
#endif

       if((vmid=startKvmVM(imageName, szsys,  buf, szProgName, &vmconnection, &vmdomain))<0) {
           fprintf(g_logFile, "startImagevm: cant start VM\n");
           return false;
       }
    }

    fprintf(g_logFile, "\tvmid: %d\n", vmid);
#ifdef LOCKFILE
    close(fd);
#endif

    return true;
}


int main(int an, char** av)
{
    int         i;
    bool        fImageLaunch= false;
    bool        fLinuxLaunch= false;
    bool        fSucceed= false;
    const char* initramImage= NULL;
    const char* kernelImage= NULL;
    const char* diskImage= NULL;

    initLog(NULL);
    for(i=0;i<an;i++) {
      if(strcmp(av[i],"-help")==0) {
        fprintf(g_logFile, 
         "vmLaunch.exe [-ImageLaunch ProcessImage |-LinuxLaunch initramImage kernelimage]\n");
        return 0;
      }
      if(strcmp(av[i],"-ImageLaunch")==0) {
        if(an>(i+1)) {
            diskImage= av[++i];
            fImageLaunch= true;
            fSucceed= true;
        }
      }
      else if(strcmp(av[i],"-LinuxLaunch")==0) {
        if(an>(i+2)) {
            initramImage= av[++i];
            kernelImage= av[++i];
            fLinuxLaunch= true;
            fSucceed= true;
        }
      }
    }

    if(!fSucceed) {
        fprintf(g_logFile, "vmLaunch: error called with no flag\n");
        return 1;
    }
    
    g_myPid= getpid();

    if(fLinuxLaunch) {
        fprintf(g_logFile, "Linux launch.  initram: %s, kernel: %s\n",
            initramImage, kernelImage);
        if(startLinuxvm(initramImage, kernelImage) ) {
            fprintf(g_logFile, "Linux launch succeeds\n");
        }
        else {
            fprintf(g_logFile, "Linux launch fails\n");
        }
    }
    if(fImageLaunch) {
        fprintf(g_logFile, "Image launch.  Image: %s\n", diskImage);
        if(startImagevm(diskImage)) {
            fprintf(g_logFile, "Image launch succeeds\n");
        }
        else {
            fprintf(g_logFile, "Image launch fails\n");
        }
    }

    closeLog();
    return 0;
}


// ------------------------------------------------------------------------


