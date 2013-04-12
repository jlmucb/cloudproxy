//  File: fileServices.cpp
//      John Manferdelli
//
//  Description: file Services
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


#define MAXNAME 2048


// -----------------------------------------------------------------------------


#include "jlmTypes.h"
#include "logging.h"
#include "jlmcrypto.h"
#include "algs.h"
#include "keys.h"
#include "session.h"
#include "channel.h"
#include "safeChannel.h"
#include "jlmUtility.h"
#include "fileServices.h"
#include "encryptedblockIO.h"
#include "vault.h"

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
#include <errno.h>


// ------------------------------------------------------------------------


fileServices::fileServices()
{
}


fileServices::~fileServices()
{
}

// ------------------------------------------------------------------------


#ifdef SERVER

//  Server services


bool fileServices::validateCreatefileServices(char** pszFile, resource** ppResource)
{
    resource*               pResource= NULL;
    bool                    fAllowed= false;
    accessfileServices           oAR;
    char                    szBuf[MAXNAME];

#ifdef TEST
    fprintf(g_logFile, "validateCreatefileServices\n");
#endif
    if(m_poAG==NULL) {
        fprintf(g_logFile, "fileServices::validateCreatefileServices: access guard not initialiized\n");
        return false;
    }

    // Fixed?: this is certainly a bug and potentially a vulnerability in the code,
    szBuf[MAXNAME-1]= '\0';
    strncpy(szBuf, m_szResourceName, MAXNAME-1);
    char* p= szBuf;
    while(*p!=0)
        p++;
    p--;
    while(*p!='/' && p>szBuf)
        p--;
    if(*p!='/') {
        fprintf(g_logFile, "fileServices::validateCreatefileServices: Bad resource name\n");
        return false;
    }
    *p= 0; 

    oAR.m_szSubject= strdup(m_szSubjectName);
    oAR.m_ifileServicesType= m_ifileServicesType;
    oAR.m_szResource= strdup(szBuf);
    fAllowed= m_poAG->permitAccess(oAR, m_szEvidence);
    if(!fAllowed) {
        fprintf(g_logFile, "fileServices::validateCreatefileServices: permitAccess returns false\n");
        return false;
    }
#ifdef  TEST
    fprintf(g_logFile, "permitAccess returns true in createResource adding %s\n", m_szResourceName);
#endif

    pResource= new resource();
    if(pResource==NULL) {
        fprintf(g_logFile, "fileServices::validateCreatefileServices: can't new resource\n");
        return false;
    }
    pResource->m_szResourceName= strdup(m_szResourceName);
    pResource->m_uType= RESOURCEFILE;
    pResource->m_iSize= m_iResourceLength;
    if(!g_theVault.addResource(pResource)) {
        fprintf(g_logFile, "fileServices::validateCreatefileServices: can't add resource to table\n");
        return false;
    }
    if(!translateResourceNametoLocation(m_szResourceName, szBuf, 
                      MAXREQUESTSIZE)) {
        fprintf(g_logFile, "fileServices::validateCreatefileServices: translateResourceName failed\n");
        return false;
    }
    pResource->m_szLocation= strdup(szBuf);
    *pszFile= pResource->m_szLocation;
    *ppResource= pResource;
    return fAllowed;
}


bool  fileServices::validateGetSendDeletefileServices(char** pszFile, resource** ppResource)
{
    resource*               pResource= NULL;
    accessfileServices      oAR;

    if(m_poAG==NULL) {
        fprintf(g_logFile, "fileServices::validateGetSendDeletefileServices: access guard not initialiized\n");
        fflush(g_logFile);
        return false;
    }
#ifdef TEST
    fprintf(g_logFile, "looking for resource %s\n", m_szResourceName);
#endif
    pResource= g_theVault.findResource(m_szResourceName);
    if(pResource==NULL) {
        fprintf(g_logFile, "fileServices::validateGetSendDeletefileServices: GetSendDelete pResource NULL, %s\n", m_szResourceName);
        fflush(g_logFile);
        return false;
    }
    if(pResource->m_szLocation==NULL) {
        fprintf(g_logFile, "fileServices::validateGetSendDeletefileServices: location NULL\n");
        return false;
    }

    // Get file location
    *pszFile= pResource->m_szLocation;
    *ppResource= pResource;

    // Access allowed?
    if(m_szSubjectName==NULL)
        oAR.m_szSubject= NULL;
    else
        oAR.m_szSubject= strdup(m_szSubjectName);
    oAR.m_ifileServicesType= m_ifileServicesType;
    oAR.m_szResource= strdup(m_szResourceName);
    return m_poAG->permitAccess(oAR, m_szEvidence);
}


bool  fileServices::validateAddOwnerfileServices(char** pszFile, resource** ppResource)
                    
{
    resource*               pResource= NULL;
    accessfileServices           oAR;

    if(m_poAG==NULL) {
        fprintf(g_logFile, "fileServices::validateAddOwnerfileServices: access guard not initialiized\n");
        return false;
    }
    pResource= g_theVault.findResource(m_szResourceName);
    if(pResource==NULL) {
        fprintf(g_logFile, "fileServices::validateAddOwnerfileServices: AddOwner pResource NULL, %s\n", m_szResourceName);
        return false;
    }
    if(pResource->m_szLocation==NULL) {
        fprintf(g_logFile, "fileServices::validateAddOwnerfileServices: location NULL\n");
        return false;
    }

    // Get file location
    *pszFile= pResource->m_szLocation;
    *ppResource= pResource;

    // Access allowed?
    if(m_szSubjectName==NULL)
        oAR.m_szSubject= NULL;
    else
        oAR.m_szSubject= strdup(m_szSubjectName);
    oAR.m_ifileServicesType= m_ifileServicesType;
    oAR.m_szResource= strdup(m_szResourceName);
    return m_poAG->permitAccess(oAR, m_szEvidence);
}


bool  fileServices::validateAddPrincipalfileServices(char** pszFile, resource** ppResource)
{
    return false;
}


bool  fileServices::validateDeletePrincipalfileServices(char** pszFile, resource** ppResource)
{
    return false;
}


bool  fileServices::validateRemoveOwnerfileServices(char** pszFile, resource** ppResource)
{
    resource*               pResource= NULL;
    accessfileServices      oAR;

    if(m_poAG==NULL) {
        fprintf(g_logFile, "fileServices::validateRemoveOwnerfileServices: access guard not initialiized\n");
        return false;
    }
    pResource= g_theVault.findResource(m_szResourceName);
    if(pResource==NULL) {
        fprintf(g_logFile, "fileServices::validateRemoveOwnerfileServices: RemoveOwner pResource NULL, %s\n", m_szResourceName);
        return false;
    }
    if(pResource->m_szLocation==NULL) {
        fprintf(g_logFile, "fileServices::validateRemoveOwnerfileServices: location NULL\n");
        return false;
    }

    // Get file location
    *pszFile= pResource->m_szLocation;
    *ppResource= pResource;

    // Access allowed?
    if(m_szSubjectName==NULL)
        oAR.m_szSubject= NULL;
    else
        oAR.m_szSubject= strdup(m_szSubjectName);
    oAR.m_ifileServicesType= m_ifileServicesType;
    oAR.m_szResource= strdup(m_szResourceName);
    return m_poAG->permitAccess(oAR, m_szEvidence);
}

 
bool  fileServices::validatefileServices(char** pszFile, resource** ppResource)
{
#ifdef TEST
    fprintf(g_logFile, "\nvalidatefileServices\n");
    fflush(g_logFile);
#endif

    if(m_szResourceName==NULL) {
        fprintf(g_logFile, "fileServices::validatefileServices: validatefileServices returning false\n");
        fflush(g_logFile);
        return false;
    }

#ifdef TEST
    fprintf(g_logFile, "switching on request type\n");
#endif
    bool    fAllowed;
    switch(m_ifileServicesType) {
      case CREATERESOURCE:
        fAllowed= validateCreatefileServices(pszFile, ppResource);
        break;
      case DELETERESOURCE:
      case GETRESOURCE:
      case SENDRESOURCE:
        fAllowed= validateGetSendDeletefileServices(pszFile, ppResource);
        break;
      case ADDOWNER:
        fAllowed= validateAddOwnerfileServices(pszFile, ppResource);
        break;
      case REMOVEOWNER:
        fAllowed= validateRemoveOwnerfileServices(pszFile, ppResource);
        break;
      case ADDPRINCIPAL:
      case REMOVEPRINCIPAL:
      case GETOWNER:
      default:
        fAllowed= false;
        break;
    }

#ifdef TEST
    if(fAllowed) 
        fprintf(g_logFile, "validatefileServices returning true\n\n");
    else 
        fprintf(g_logFile, "validatefileServices returning false\n\n");
#endif
    return fAllowed;
}


const char* g_szPrefix= "//www.manferdelli.com/Gauss/";


bool fileServices::translateLocationtoResourceName(const char* szLocation, const char* szResourceName, 
                                     int size)
{
    // Fix 
    return false;
}


bool fileServices::translateResourceNametoLocation(const char* szResourceName, char* szLocation, 
                                     int size)
{
    int         n;
    const char*       p= szResourceName;

#ifdef TEST
    fprintf(g_logFile, "translate %s\n", p);
#endif
    // strip prefix
    n= strlen(g_szPrefix);
   if(strncmp(p, g_szPrefix, n)!=0) {
        return false;
    } 

    p+= n;
    if((int)strlen(p)>=size) {
        return false;
    }

    strcpy(szLocation, p);
#ifdef TEST
    fprintf(g_logFile, "size: %d %s\n", size, szLocation);
#endif
    return true;
}


bool fileServices::serversendResourcetoclient(safeChannel& fc, fileServices& oReq, 
            int encType, byte* key, timer& accessTimer, timer& decTimer)
{
    bool        fError;
    int         iRead= 0;
    int         filesize= 0;
    int         datasize= 0;
    byte        szBuf[MAXREQUESTSIZEWITHPAD];
    int         iLeft= MAXREQUESTSIZE;
    char*       p= (char*)szBuf;
    char*       szFile= NULL;
    const char* szError= NULL;
    int         type= CHANNEL_RESPONSE;
    byte        multi= 0;
    byte        final= 0;
    resource*   pResource= NULL;

#ifdef  TEST
    fprintf(g_logFile, "serversendResourcetoclient\n");
#endif
    // validate request (including access check) and get file location
    accessTimer.Start();
    fError= !oReq.validatefileServices(&szFile, &pResource);
    accessTimer.Stop();

    // open File (if no Error)
    if(!fError) {
        iRead= openFile(szFile, &filesize);
        if(iRead<0) {
            fError= true;
            szError= "serversendResourcetoclient: Cant open file";
            fprintf(g_logFile, "serversendResourcetoclient: Open file error %s\n", szFile);
        }
    }

    if (!fError) {	
        datasize= pResource->m_iSize;
    }

    // construct response
    if(!constructResponse(fError, &p, &iLeft, oReq.m_szResourceName, datasize, szError)) {
        fprintf(g_logFile, "serversendResourcetoclient: constructResponse error\n");
        return false;
    }

    // send response
    fc.safesendPacket(szBuf, (int)strlen(reinterpret_cast<char*>(szBuf))+1, type, multi, final);

    // if we sent an error to the client, then return false
    if (fError) return false;

    // send file
    if(!sendFile(fc, iRead, filesize, datasize, encType, key, decTimer)) {
        fprintf(g_logFile, "serversendResourcetoclient: sendFile error\n");
        close(iRead);
        return false;
    }

#ifdef  TEST
    fprintf(g_logFile, "serversendResourcetoclient returns true\n");
#endif
    close(iRead);
    return true;
}


bool fileServices::servercreateResourceonserver(safeChannel& fc, fileServices& oReq,
                                  int encType, byte* key, timer& accessTimer)
{
    bool            fAllowed;
    bool            fError;
    char            szBuf[MAXREQUESTSIZEWITHPAD];
    int             iLeft= MAXREQUESTSIZE;
    char*           p= (char*)szBuf;
    char*           szFile= NULL;
    const char*     szError= NULL;
    int             type= CHANNEL_RESPONSE;
    byte            multi= 0;
    byte            final= 0;
    resource*       pResource= NULL;
    resource*       pOwnerResource= NULL;
    accessPrincipal* pSubject= NULL;
    accessPrincipal* pOwnerPrincipal= NULL;

#ifdef  TEST
    fprintf(g_logFile, "servercreateResourceonserver\n");
    oReq.printMe();
#endif
    // Does owner resource exist?
    if(strlen(oReq.m_szResourceName)>=MAXREQUESTSIZEWITHPAD) {
        fprintf(g_logFile, "servercreateResourceonserver: requested resource name too long\n");
        return false;
    }

    strcpy(szBuf, oReq.m_szResourceName);
    while(*p!=0)
        p++;
    p--;
    while(*p!='/' && p>szBuf)
        p--;
    if(*p!='/') {
        fprintf(g_logFile, "servercreateResourceonserver: bad resource name\n");
        return false;
    }
    *p= 0; 
    pOwnerResource= g_theVault.findResource(szBuf);
    if(pOwnerResource==NULL) {
#ifdef  TEST
        fprintf(g_logFile, "parent resource doesnt exist: %s\n", szBuf);
        fflush(g_logFile);
#endif
        pOwnerResource= new resource();
        if(pOwnerResource==NULL) {
            fprintf(g_logFile, "servercreateResourceonserver: can't new resource\n");
            return false;
        }
        pOwnerResource->m_szResourceName= strdup(szBuf);
        pOwnerResource->m_uType= RESOURCEDIRECTORY;
        if(!g_theVault.addResource(pOwnerResource)) {
            fprintf(g_logFile, "servercreateResourceonserver: can't add resource to table\n");
            return false;
        }

        // owner is the policy principal
        pOwnerPrincipal= g_policyAccessPrincipal;
        if(pOwnerPrincipal==NULL) {
            fprintf(g_logFile, "servercreateResourceonserver: can't get owner principal\n");
            return false;
        }
        pOwnerResource->m_myOwners.append(pOwnerPrincipal);

        if(!translateResourceNametoLocation(pOwnerResource->m_szResourceName, szBuf,
                          MAXREQUESTSIZE)) {
            fprintf(g_logFile, "servercreateResourceonserver: translateResourceName failed %s\n", 
                    pOwnerResource->m_szResourceName);
            return false;
        }
        pOwnerResource->m_szLocation= strdup(szBuf);
        // Create directory if it doesn't exist
        struct stat  sb;
        if(stat(pOwnerResource->m_szLocation, &sb)!=0) {
            if(mkdir(pOwnerResource->m_szLocation, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH)!=0) {
                fprintf(g_logFile, "servercreateResourceonserver: can't make directory %s\n", pOwnerResource->m_szLocation);
                return false;
            }
            stat(pOwnerResource->m_szLocation, &sb);
        }
        if(!S_ISDIR(sb.st_mode)) {
            fprintf(g_logFile, "servercreateResourceonserver: no directory node\n");
            return false;
        }
    }

    if(oReq.m_szSubjectName==NULL) {
        fprintf(g_logFile, "servercreateResourceonserver: createResource must have subject\n");
        return false;
    }
#ifdef TEST
    fprintf(g_logFile, "servercreateResourceonserver: find printcipal %s\n", 
            oReq.m_szSubjectName);
    fflush(g_logFile);
#endif
    pSubject= g_theVault.findPrincipal(oReq.m_szSubjectName);
    if(pSubject==NULL) {
        fprintf(g_logFile, "servercreateResourceonserver: Subject principal doesn't exist %s\n", oReq.m_szSubjectName);
        return false;
    }
    if(!pSubject->m_fValidated) {
        fprintf(g_logFile, "servercreateResourceonserver: Subject principal not validated\n");
        return false;
    }

    fError= false;
    // does it already exist?
#ifdef TEST
    fprintf(g_logFile, "servercreateResourceonserver: find resource %s\n", 
            oReq.m_szResourceName);
    fflush(g_logFile);
#endif
    pResource= g_theVault.findResource(oReq.m_szResourceName);
    if(pResource!=NULL) {
        fError= true;
        szError= "servercreateResourceonserver: Resource exists";
    }

    if(!fError) {
        accessTimer.Start();
        fAllowed= oReq.validatefileServices(&szFile, &pResource);
        accessTimer.Stop();
        if(fAllowed) {
            pResource->m_myOwners.append(pSubject);
        }
        else {
            fError= true;
            szError= "servercreateResourceonserver: create disallowed";
        }
    }

    // send response
    p= (char*)szBuf;
    if(!constructResponse(fError, &p, &iLeft, oReq.m_szResourceName, 0, szError)) {
        fprintf(g_logFile, "servercreateResourceonserver: constructResponse failed\n");
        return false;
    }
    fc.safesendPacket((byte*)szBuf, strlen(szBuf)+1, type, multi, final);

    // Should pResource be deleted?
#ifdef  TEST
    fprintf(g_logFile, "servercreateResourceonserver returning true\n");
    fflush(g_logFile);
#endif
    return !fError;
}


bool fileServices::servergetResourcefromclient(safeChannel& fc, fileServices& oReq, 
                                 int encType, byte* key, timer& accessTimer, timer& encTimer)
{
    bool        fError;
    int         iWrite= 0;
    int         size= 0;
    byte        szBuf[MAXREQUESTSIZEWITHPAD];
    int         iLeft= MAXREQUESTSIZE;
    char*       p= (char*)szBuf;
    const char*       szError= NULL;
    int         type= CHANNEL_RESPONSE;
    byte        multi= 0;
    byte        final= 0;
    char*       szOutFile= NULL;
    resource*   pResource= NULL;

#ifdef  TEST
    fprintf(g_logFile, "servergetResourcefromclient %d\n", size);
    fflush(g_logFile);
#endif
    // validate request (including access check) and get file location
    accessTimer.Start();
    fError= !oReq.validatefileServices(&szOutFile, &pResource);
    accessTimer.Stop();
    fprintf(g_logFile, "Got fError %s\n", fError ? "true" : "false");	
    fflush(g_logFile);
    if (!fError) {	
        size= oReq.m_iResourceLength;
        pResource->m_iSize= size;
    }

    // open for writing
    if(!fError) {
        fprintf(g_logFile, "servergetResourcefromclient opening file %s\n", szOutFile);	
        fflush(g_logFile);
        iWrite= open(szOutFile, O_WRONLY | O_CREAT | O_TRUNC, 0666);
        if(iWrite<0) {
            fError= true;
            szError= "servergetResourcefromclient: Cant open file for writing\n";
            fprintf(g_logFile, "servergetResourcefromclient: Cant open file %s for writing\n", szOutFile);
        }
    }

    // send response
    if(!constructResponse(fError, &p, &iLeft, oReq.m_szResourceName, size, szError)) {
        fprintf(g_logFile, "servergetResourcefromclient: constructResponse failed\n");
        return false;
    } else {
        fprintf(g_logFile, "Constructed a response\n");
        fflush(g_logFile);
    }
    fc.safesendPacket(szBuf, strlen(reinterpret_cast<char*>(szBuf))+1, type, multi, final);

    // if the reply was that there was an error, then return false
    if (fError) return false;

#ifdef  TEST
    fprintf(g_logFile, "servergetResourcefromclient getting file, %d\n", size);
    fflush(g_logFile);
#endif
    // read file
    if(!getFile(fc, iWrite, size, size, encType, key, encTimer)) {
        fprintf(g_logFile, "servergetResourcefromclient: getFile failed\n");
        close(iWrite);
        return false;
    }
    if(pResource!=NULL) {
        pResource->m_fIsPresent= true;
    }
    close(iWrite);

#ifdef  TEST
    fprintf(g_logFile, "servergetResourcefromclient returns true\n");
    fflush(g_logFile);
#endif
    return true;
}


bool fileServices::serverchangeownerofResource(safeChannel& fc, fileServices& oReq, 
                                 int encType, byte* key, timer& accessTimer)
// includes delete
{
    resource*           pResource= NULL;
    accessPrincipal*    pPrinc= NULL;
    char*               szFile= NULL;

#ifdef  TEST
    fprintf(g_logFile, "serverchangeownerofResource\n");
    fflush(g_logFile);
#endif
    accessTimer.Start();
    if(!oReq.validatefileServices(&szFile, &pResource))
        return false;
    accessTimer.Stop();

    if(oReq.m_ifileServicesType==ADDOWNER) {
        pPrinc= g_theVault.findPrincipal(oReq.m_szResourceName);
        if(pPrinc==NULL)
            return false;
        return pResource->m_myOwners.append(pPrinc);
        
    }

    if(oReq.m_ifileServicesType==REMOVEOWNER) {
        pPrinc= g_theVault.findPrincipal(oReq.m_szResourceName);
        if(pPrinc==NULL)
            return false;
        return pResource->m_myOwners.deletenode(pPrinc);
    }

    return false;
}


bool fileServices::serverdeleteResource(safeChannel& fc, fileServices& oReq,
                          int encType, byte* key, timer& accessTimer)
{
    resource*   pResource= NULL;
    char*       szFile= NULL;
    bool        fError;
    int         size= 0;
    char*       szError= NULL;
    char        szBuf[MAXREQUESTSIZEWITHPAD];
    int         type= CHANNEL_RESPONSE;
    byte        multi= 0;
    byte        final= 0;
    int         iLeft= MAXREQUESTSIZE;
    char*       p= szBuf;

#ifdef  TEST
    fprintf(g_logFile, "serverdeleteResource\n");
    fflush(g_logFile);
#endif
    accessTimer.Start();
    fError= !oReq.validatefileServices(&szFile, &pResource);
    accessTimer.Stop();

    if(!fError) {
        // delete resource
#ifdef TEST
        fprintf(g_logFile, "serverdeleteResource: deleting %s\n", szFile);
        fflush(g_logFile);
#endif
        unlink(szFile); 
        // remove nodes on owner list and delete from resource table
        pResource->m_fIsDeleted= true;
    }
    else {
        szError= (char*)"serverDeleteResource: authorization error";
    }
    // send response
    if(!constructResponse(fError, &p, &iLeft, oReq.m_szResourceName, size, szError)) {
        fprintf(g_logFile, "servergetResourcefromclient: constructResponse failed\n");
        return false;
    }
    fc.safesendPacket((byte*)szBuf, strlen(reinterpret_cast<char*>(szBuf))+1, type, multi, final);
    return !fError;
}


#else  // end of server fileServices, beginning of client services


//  Client fileServices


bool fileServices::clientgetResourcefromserver(safeChannel& fc, const char* szResourceName, 
            const char* szEvidence, const char* szOutFile, int encType, byte* key, timer& encTimer)
{
    char        szBuf[MAXREQUESTSIZEWITHPAD];
    int         iLeft= MAXREQUESTSIZE;
    char*       p= szBuf;
    Response    oResponse;
    int         n= 0;
    int         type= CHANNEL_REQUEST;
    byte        multi=0;
    byte        final= 0;

#ifdef  TEST
    fprintf(g_logFile, "clientgetResourcefromserver(%s, %s)\n", szResourceName, szOutFile);
#endif
    // send request
    if(!constructfileServices(&p, &iLeft, "getResource", NULL, szResourceName, 0, szEvidence)) {
        return false;
    }
    if((n=fc.safesendPacket((byte*)szBuf, strlen(szBuf)+1, CHANNEL_REQUEST, 0, 0)) <0) {
        return false;
    }

    // should be a CHANNEL_RESPONSE, not multipart
    n= fc.safegetPacket((byte*)szBuf, MAXREQUESTSIZE, &type, &multi, &final);
    if(n<0) {
        fprintf(g_logFile, "clientgetResourcefromserver: getResource error %d\n", n);
        fprintf(g_logFile, "clientgetResourcefromserver: clientgetResourcefromserver %s\n", szBuf);
        return false;
    }
    szBuf[n]= 0;
    oResponse.getDatafromDoc(szBuf);

    // check response
    if(strcmp(oResponse.m_szAction, "accept")!=0) {
        fprintf(g_logFile, "Error: %s\n", oResponse.m_szErrorCode);
        return false;
    }

    // read and write file
    int         iWrite= open(szOutFile, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if(iWrite<0) {
        emptyChannel(fc, oResponse.m_iResourceLength, 0, NULL, 0, NULL);
        fprintf(g_logFile, "clientgetResourcefromserver: Cant open out file\n");
        return false;
    }
    if(!getFile(fc, iWrite, oResponse.m_iResourceLength, oResponse.m_iResourceLength, 
                encType, key, encTimer)) {
        fprintf(g_logFile, "clientgetResourcefromserver: Can't get file\n");
        return false;
    }

    close(iWrite);
#ifdef  TEST
    fprintf(g_logFile, "clientgetResourcefromserver returns true\n");
#endif
    return true;
}


bool fileServices::clientcreateResourceonserver(safeChannel& fc, const char* szResourceName, 
           const char* szSubject, const char* szEvidence, int encType, byte* key)
{
    char        szBuf[MAXREQUESTSIZEWITHPAD];
    int         iLeft= MAXREQUESTSIZE;
    char*       p= szBuf;
    Response    oResponse;
    int         n= 0;
    int         type= CHANNEL_REQUEST;
    byte        multi=0;
    byte        final= 0;

#ifdef  TEST
    fprintf(g_logFile, "clientcreateResourceonserver(%s)\n", szResourceName);
#endif
    // send request
    if(!constructfileServices(&p, &iLeft, "createResource", szSubject, 
                                    szResourceName, 0, szEvidence)) {
        fprintf(g_logFile, "clientcreateResourceonserver: constructfileServices returns false\n");
        return false;
    }
    if((n=fc.safesendPacket((byte*)szBuf, strlen(szBuf)+1, CHANNEL_REQUEST, 0, 0)) <0) {
        fprintf(g_logFile, "clientcreateResourceonserver: safesendPacket after constructfileServices returns false\n");
        return false;
    }

    // should be a CHANNEL_RESPONSE, not multipart
    n= fc.safegetPacket((byte*)szBuf, MAXREQUESTSIZE, &type, &multi, &final);
    if(n<0) {
        fprintf(g_logFile, "clientcreateResourceonserver: createResource error %d\n", n);
        return false;
    }
    szBuf[n]= 0;
#ifdef  TEST
    fprintf(g_logFile, "clientcreateResourceonserver got response\n%s\n", szBuf);
    fflush(g_logFile);
#endif
    oResponse.getDatafromDoc(szBuf);

    // check to see if the resource already exists or if it was successfully created. 
    // Either case is success.
    bool success = false;
    if (oResponse.m_szAction != NULL) {
        if (strcmp(oResponse.m_szAction, "accept") == 0) {
            success = true;
        } else if (strcmp(oResponse.m_szErrorCode, "servercreateResourceonserver: Resource exists") == 0) {
            // then the resource already exists, so this is also success
            success = true;
#ifdef TEST
            fprintf(g_logFile, "Success in creation because the resource already exists\n");
#endif
        }
    }

#ifdef TEST
    // check response
    if(!success) {
        fprintf(g_logFile, "clientcreateResourceonserver: response is false\n");
        oResponse.printMe();
    }
#endif

    return success;
}


bool fileServices::clientsendResourcetoserver(safeChannel& fc, const char* szSubject, 
    const char* szResourceName, const char* szEvidence, const char* szInFile, 
    int encType, byte* key, timer& decTimer)
{
    char        szBuf[MAXREQUESTSIZEWITHPAD];
    int         iLeft= MAXREQUESTSIZE;
    char*       p= szBuf;
    Response    oResponse;
    int         n= 0;
    int         filesize= 0;
    int         datasize= 0;
    int         type= CHANNEL_REQUEST;
    byte        multi=0;
    byte        final= 0;
    int         iRead= 0;

#ifdef  TEST
    fprintf(g_logFile, "clientsendResourcetoserver(%s, %s)\n", szResourceName, szInFile);
    fflush(g_logFile);
#endif

    // named owner should be in evidence.  If evidence is empty, pick first user
    // principal as user.   Later: compound principal?
    // Fix: Subject

    // open file and get size
    iRead= openFile(szInFile, &filesize);
    if(iRead<0) {
        fprintf(g_logFile, "clientsendResourcetoserver: Can't open file %s\n", szInFile);
        return false;
    }
    datasize= filesize;

    // send request
    if(!constructfileServices(&p, &iLeft, "sendResource", szSubject, szResourceName, 
                         filesize, szEvidence)) {
        fprintf(g_logFile, "clientsendResourcetoserver: constructfileServices returns false\n");
        return false;
    }
    if((n=fc.safesendPacket((byte*)szBuf, strlen(szBuf)+1, CHANNEL_REQUEST, 0, 0)) <0) {
        fprintf(g_logFile, "clientsendResourcetoserver: safesendPacket after constructfileServices returns false\n");
        return false;
    }

    // should be a CHANNEL_RESPONSE, not multipart
    n= fc.safegetPacket((byte*)szBuf, MAXREQUESTSIZE, &type, &multi, &final);
    if(n<0) {
        fprintf(g_logFile, "clientsendResourcetoserver: sendResource error %d\n", n);
        return false;
    }
    szBuf[n]= 0;
    oResponse.getDatafromDoc(szBuf);

    // check response
    if(oResponse.m_szAction==NULL || strcmp(oResponse.m_szAction, "accept")!=0) {
        fprintf(g_logFile, "clientsendResourcetoserver: response is false\n");
#ifdef TEST
        oResponse.printMe();
#endif
        // fprintf(g_logFile, "Error: %s\n", oResponse.szErrorCode);
        return false;
    }

#ifdef  TEST
    fprintf(g_logFile, "clientsendResourcetoserver sending file\n");
    fflush(g_logFile);
#endif
    // send file
    if(!sendFile(fc, iRead, filesize, datasize, encType, key, decTimer)) {
        close(iRead);
        return false;
    }
    close(iRead);   

#ifdef  TEST
    fprintf(g_logFile, "clientsendResourcetoserver returns true\n");
    fflush(g_logFile);
#endif
    return true;
}


bool fileServices::clientchangeownerResource(safeChannel& fc, const char* szAction, const char* szResourceName,
                               const char* szEvidence, const char* szOutFile, int encType, byte* key)
{
    char        szBuf[MAXREQUESTSIZEWITHPAD];
    int         iLeft= MAXREQUESTSIZE;
    char*       p= (char*)szBuf;
    Response    oResponse;
    int         n= 0;
    int         type= CHANNEL_REQUEST;
    byte        multi=0;
    byte        final= 0;

#ifdef  TEST
    fprintf(g_logFile, "clientchangeownerofResource(%s, %s)\n", szResourceName, szOutFile);
    fflush(g_logFile);
#endif

    // send request
    if(!constructfileServices(&p, &iLeft, szAction, NULL, szResourceName, 0, szEvidence)) {
        fprintf(g_logFile, "clientchangeownerResource: constructfileServices returns false\n");
        return false;
    }
    if((n=fc.safesendPacket((byte*)szBuf, strlen(szBuf)+1, CHANNEL_REQUEST, 0, 0)) <0) {
        return false;
    }

    // should be a CHANNEL_RESPONSE, not multipart
    n= fc.safegetPacket((byte*)szBuf, MAXREQUESTSIZE, &type, &multi, &final);
    if(n<0) {
        fprintf(g_logFile, "clientchangeownerResource: sendResource error %d\n", n);
        return false;
    }
    szBuf[n]= 0;
    oResponse.getDatafromDoc(szBuf);
    if(strcmp(oResponse.m_szAction, "accept")==0)
        return true;
    if(oResponse.m_szErrorCode!=NULL)
        fprintf(g_logFile, "Error in %s: %s\n", oResponse.m_szAction, oResponse.m_szErrorCode);

#ifdef  TEST
    fprintf(g_logFile, "clientchangeownerofResource returns false\n");
#endif
    return false;
}


bool fileServices::clientdeleteResource(safeChannel& fc, const char* szResourceName,
                          const char* szEvidence, const char* szFile, int encType, byte* key)
{
    char        szBuf[MAXREQUESTSIZEWITHPAD];
    int         iLeft= MAXREQUESTSIZE;
    char*       p= (char*)szBuf;
    Response    oResponse;
    int         n= 0;
    int         type= CHANNEL_REQUEST;
    byte        multi=0;
    byte        final= 0;

#ifdef  TEST
    fprintf(g_logFile, "clientdeleteResource(%s, %s)\n", szResourceName, szFile);
    fflush(g_logFile);
#endif
    // send request
    if(!constructfileServices(&p, &iLeft, "deleteResource", NULL, szResourceName, 0, szEvidence)) {
        fprintf(g_logFile, "clientdeleteResource: constructfileServices returns false\n");
        return false;
    }
#ifdef  TEST1
    fprintf(g_logFile, "clientdeleteResource request\n%s\n", szBuf);
    fflush(g_logFile);
#endif
    if((n=fc.safesendPacket((byte*)szBuf, strlen(szBuf)+1, CHANNEL_REQUEST, 0, 0)) <0) {
        return false;
    }

    // should be a CHANNEL_RESPONSE, not multipart
    n= fc.safegetPacket((byte*)szBuf, MAXREQUESTSIZE, &type, &multi, &final);
    if(n<0) {
        fprintf(g_logFile, "clientdeleteResource: sendResource error %d\n", n);
        return false;
    }
    szBuf[n]= 0;
    oResponse.getDatafromDoc(szBuf);
    if(strcmp(oResponse.m_szAction, "accept")==0)
        return true;
    if(oResponse.m_szErrorCode!=NULL)
        fprintf(g_logFile, "Error in %s: %s\n", oResponse.m_szAction, oResponse.m_szErrorCode);

#ifdef  TEST
    fprintf(g_logFile, "clientdeleteResource returns false\n");
    fflush(g_logFile);
#endif
    return false;
}

#endif // client interfaces


// ---------------------------------------------------------------------------------


