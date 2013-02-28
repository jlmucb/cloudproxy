//  File: request.cpp
//      John Manferdelli
//
//  Description: file action request object
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
#include "vault.h"
#include "request.h"
#include "encryptedblockIO.h"

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


#define DEBUGPRINT


const char*   szRequest1a= "<Request>\n";
const char*   szRequest1b=  "</Request>\n";

const char*   szRequest2a= "     <Action>";
const char*   szRequest2b= "</Action>\n";

const char*   szRequest3= "    <EvidenceCollection count='0'/>\n";
const char*   szRequest3a= "    <EvidenceCollection count='%d'>\n";
const char*   szRequest3b= "    </EvidenceCollection>\n";

const char*   szRequest4a= "     <ResourceName>";
const char*   szRequest4b= "</ResourceName>\n";

const char*   szRequest5a= "    <ResourceLength>";
const char*   szRequest5b=  "</ResourceLength>\n";

const char*   szRequest6a= "    <SubjectName>";
const char*   szRequest6b=  "</SubjectName>\n";


const char*   szResponse1= "<Response>\n  <Action>";
const char*   szResponse2= "</Action>\n  <ErrorCode>";
const char*   szResponse3= " </ErrorCode>\n  <ResourceName>";
const char*   szResponse4= " </ResourceName>\n <ResourceLength>";
const char*   szResponse5= " </ResourceLength>\n </Response>\n";


// ------------------------------------------------------------------------



Request::Request()
{
    m_iRequestType= 0;
    m_iResourceLength= 0;
    m_szSubjectName= NULL;
    m_szAction= NULL;
    m_szResourceName= NULL;
    m_szEvidence= NULL;
    m_poAG= NULL;
}


Request::~Request()
{
    if(m_szResourceName!=NULL) {
        free(m_szResourceName);
        m_szResourceName= NULL;
    }
    if(m_szEvidence!=NULL) {
        free(m_szEvidence);
        m_szEvidence= NULL;
    }
    if(m_szAction!=NULL) {
        free(m_szAction);
        m_szAction= NULL;
    }
    if(m_szSubjectName!=NULL) {
        free(m_szSubjectName);
        m_szSubjectName= NULL;
    }
    m_poAG= NULL;
}


bool  Request::getDatafromDoc(const char* szRequest)
{
    TiXmlDocument   doc;
    TiXmlElement*   pRootElement;
    TiXmlNode*      pNode;
    TiXmlNode*      pNode1;

    const char*           szAction= NULL;
    const char*           szResourceName= NULL;
    const char*           szResourceLength= NULL;
    const char*           szSubjectName= NULL;
    const char*           szEvidence= NULL;

    if(szRequest==NULL)
        return false;

    if(!doc.Parse(szRequest)) {
        fprintf(g_logFile, "Request::getDatafromDoc: Cant parse request\n");
        return false;
    }

    pRootElement= doc.RootElement();
    if(strcmp(pRootElement->Value(),"Request")!=0) {
        fprintf(g_logFile, "Request::getDatafromDoc: Should be request\n");
        return false;
    }
    
    pNode= pRootElement->FirstChild();
    while(pNode!=NULL) {
        if(pNode->Type()==TiXmlNode::TINYXML_ELEMENT) {
            if(strcmp(((TiXmlElement*)pNode)->Value(),"Action")==0) {
                pNode1= pNode->FirstChild();
                if(pNode1) {
                    szAction= pNode1->Value();
                }
            }
            if(strcmp(((TiXmlElement*)pNode)->Value(),"ResourceName")==0) {
                pNode1= pNode->FirstChild();
                if(pNode1!=NULL) {
                    szResourceName= pNode1->Value();
                }
            }
            if(strcmp(((TiXmlElement*)pNode)->Value(),"SubjectName")==0) {
                pNode1= pNode->FirstChild();
                if(pNode1!=NULL) {
                    szSubjectName= pNode1->Value();
                }
            }
            if(strcmp(((TiXmlElement*)pNode)->Value(),"ResourceLength")==0) {
                pNode1= pNode->FirstChild();
                if(pNode1!=NULL) {
                    szResourceLength= pNode1->Value();
                }
            }
            if(strcmp(((TiXmlElement*)pNode)->Value(),"EvidenceCollection")==0) {
                szEvidence= canonicalize(pNode);
            }
        }
        pNode= pNode->NextSibling();
    }

    if(szAction==NULL || szResourceName==NULL)
        return false;

    if(szAction!=NULL)
        m_szAction= strdup(szAction);
    if(szResourceName!=NULL)
        m_szResourceName= strdup(szResourceName);
    if(szSubjectName!=NULL)
        m_szSubjectName= strdup(szSubjectName);
    if(szEvidence!=NULL)
        m_szEvidence= strdup(szEvidence);
    if(szResourceLength!=NULL)
        sscanf(szResourceLength, "%d", &m_iResourceLength);

    if(strcmp(m_szAction, "createResource")==0)
        m_iRequestType= CREATERESOURCE;
    else if(strcmp(m_szAction, "getResource")==0)
        m_iRequestType= GETRESOURCE;
    else if(strcmp(m_szAction, "sendResource")==0)
        m_iRequestType= SENDRESOURCE;
    else if(strcmp(m_szAction, "addOwner")==0)
        m_iRequestType= ADDOWNER;
    else if(strcmp(m_szAction, "removeOwner")==0)
        m_iRequestType= REMOVEOWNER;
    else if(strcmp(m_szAction, "deleteResource")==0)
        m_iRequestType= DELETERESOURCE;
    else
        m_iRequestType= 0;

#ifdef  TEST1
    fprintf(g_logFile, "Response getdata\n");
    printMe();
#endif
    return true;
}


void Request::printMe()
{
    fprintf(g_logFile, "\n\tRequest type: %d\n", m_iRequestType);
    if(m_szResourceName==NULL)
        fprintf(g_logFile, "\tm_szResourceName is NULL\n");
    else
        fprintf(g_logFile, "\tm_szResourceName: %s \n", m_szResourceName);
    if(m_szSubjectName==NULL)
        fprintf(g_logFile, "\tm_szSubjectName is NULL\n");
    else
        fprintf(g_logFile, "\tm_szSubjectName: %s \n", m_szSubjectName);
    if(m_szEvidence==NULL)
        fprintf(g_logFile, "\tm_szEvidence is NULL\n");
    else
        fprintf(g_logFile, "\tm_szEvidence: %s \n", m_szEvidence);
    fprintf(g_logFile, "\tResourcelength: %d\n", m_iResourceLength);
}


bool Request::validateCreateRequest(sessionKeys& oKeys, char** pszFile,
                                    resource** ppResource)
{
    resource*               pResource= NULL;
    bool                    fAllowed= false;
    accessRequest           oAR;
    char                    szBuf[MAXNAME];

#ifdef TEST
    fprintf(g_logFile, "validateCreateRequest\n");
#endif
    if(m_poAG==NULL) {
        fprintf(g_logFile, "Request::validateCreateRequest: access guard not initialiized\n");
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
        fprintf(g_logFile, "Request::validateCreateRequest: Bad resource name\n");
        return false;
    }
    *p= 0; 

    oAR.m_szSubject= strdup(m_szSubjectName);
    oAR.m_iRequestType= m_iRequestType;
    oAR.m_szResource= strdup(szBuf);
    fAllowed= m_poAG->permitAccess(oAR, m_szEvidence);
    if(!fAllowed) {
        fprintf(g_logFile, "Request::validateCreateRequest: permitAccess returns false\n");
        return false;
    }
#ifdef  TEST
    fprintf(g_logFile, "permitAccess returns true in createResource adding %s\n", m_szResourceName);
#endif

    pResource= new resource();
    if(pResource==NULL) {
        fprintf(g_logFile, "Request::validateCreateRequest: can't new resource\n");
        return false;
    }
    pResource->m_szResourceName= strdup(m_szResourceName);
    pResource->m_uType= RESOURCEFILE;
    pResource->m_iSize= m_iResourceLength;
    if(!g_theVault.addResource(pResource)) {
        fprintf(g_logFile, "Request::validateCreateRequest: can't add resource to table\n");
        return false;
    }
    if(!translateResourceNametoLocation(m_szResourceName, szBuf, 
                      MAXREQUESTSIZE)) {
        fprintf(g_logFile, "Request::validateCreateRequest: translateResourceName failed\n");
        return false;
    }
    pResource->m_szLocation= strdup(szBuf);
    *pszFile= pResource->m_szLocation;
    *ppResource= pResource;
    return fAllowed;
}


bool  Request::validateGetSendDeleteRequest(sessionKeys& oKeys, char** pszFile, 
                                    resource** ppResource)
{
    resource*               pResource= NULL;
    accessRequest           oAR;

    if(m_poAG==NULL) {
        fprintf(g_logFile, "Request::validateGetSendDeleteRequest: access guard not initialiized\n");
        return false;
    }
    pResource= g_theVault.findResource(m_szResourceName);
    if(pResource==NULL) {
        fprintf(g_logFile, "Request::validateGetSendDeleteRequest: GetSendDelete pResource NULL, %s\n", m_szResourceName);
        return false;
    }
    if(pResource->m_szLocation==NULL) {
        fprintf(g_logFile, "Request::validateGetSendDeleteRequest: location NULL\n");
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
    oAR.m_iRequestType= m_iRequestType;
    oAR.m_szResource= strdup(m_szResourceName);
    return m_poAG->permitAccess(oAR, m_szEvidence);
}


bool  Request::validateAddOwnerRequest(sessionKeys& oKeys, char** pszFile, 
                                    resource** ppResource)
                    
{
    resource*               pResource= NULL;
    accessRequest           oAR;

    if(m_poAG==NULL) {
        fprintf(g_logFile, "Request::validateAddOwnerRequest: access guard not initialiized\n");
        return false;
    }
    pResource= g_theVault.findResource(m_szResourceName);
    if(pResource==NULL) {
        fprintf(g_logFile, "Request::validateAddOwnerRequest: AddOwner pResource NULL, %s\n", m_szResourceName);
        return false;
    }
    if(pResource->m_szLocation==NULL) {
        fprintf(g_logFile, "Request::validateAddOwnerRequest: location NULL\n");
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
    oAR.m_iRequestType= m_iRequestType;
    oAR.m_szResource= strdup(m_szResourceName);
    return m_poAG->permitAccess(oAR, m_szEvidence);
}


bool  Request::validateAddPrincipalRequest(sessionKeys& oKeys, char** pszFile, 
                                    resource** ppResource)
{
    return false;
}


bool  Request::validateDeletePrincipalRequest(sessionKeys& oKeys, char** pszFile, 
                                    resource** ppResource)
{
    return false;
}


bool  Request::validateRemoveOwnerRequest(sessionKeys& oKeys, char** pszFile, 
                                    resource** ppResource)
{
    resource*               pResource= NULL;
    accessRequest           oAR;

    if(m_poAG==NULL) {
        fprintf(g_logFile, "Request::validateRemoveOwnerRequest: access guard not initialiized\n");
        return false;
    }
    pResource= g_theVault.findResource(m_szResourceName);
    if(pResource==NULL) {
        fprintf(g_logFile, "Request::validateRemoveOwnerRequest: RemoveOwner pResource NULL, %s\n", m_szResourceName);
        return false;
    }
    if(pResource->m_szLocation==NULL) {
        fprintf(g_logFile, "Request::validateRemoveOwnerRequest: location NULL\n");
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
    oAR.m_iRequestType= m_iRequestType;
    oAR.m_szResource= strdup(m_szResourceName);
    return m_poAG->permitAccess(oAR, m_szEvidence);
}

 
bool  Request::validateRequest(sessionKeys& oKeys, char** pszFile, 
                                    resource** ppResource)
{
#ifdef TEST
    fprintf(g_logFile, "\nvalidateRequest\n");
#endif

    if(m_szResourceName==NULL) {
        fprintf(g_logFile, "Request::validateRequest: validateRequest returning false\n");
        return false;
    }

    bool    fAllowed;
    switch(m_iRequestType) {
      case CREATERESOURCE:
        fAllowed= validateCreateRequest(oKeys, pszFile, ppResource);
        break;
      case DELETERESOURCE:
      case GETRESOURCE:
      case SENDRESOURCE:
        fAllowed= validateGetSendDeleteRequest(oKeys, pszFile, ppResource);
        break;
      case ADDOWNER:
        fAllowed= validateAddOwnerRequest(oKeys, pszFile, ppResource);
        break;
      case REMOVEOWNER:
        fAllowed= validateRemoveOwnerRequest(oKeys, pszFile, ppResource);
        break;
      case ADDPRINCIPAL:
      case REMOVEPRINCIPAL:
      case GETOWNER:
      default:
        fAllowed= false;
        break;
    }

#ifdef TEST1
    if(fAllowed) 
        fprintf(g_logFile, "validateRequest returning true\n\n");
    else 
        fprintf(g_logFile, "validateRequest returning false\n\n");
#endif
    return fAllowed;
}


// ------------------------------------------------------------------------


Response::Response()
{
    m_iRequestType= 0;
    m_iResourceLength= 0;
    m_szAction= NULL;
    m_szErrorCode= NULL;
    m_szResourceName= NULL;
    m_szEvidence= NULL;
}


Response::~Response()
{
    if(m_szAction!=NULL) {
        free(m_szAction);
        m_szAction= NULL;
    }
    if(m_szErrorCode!=NULL) {
        free(m_szErrorCode);
        m_szErrorCode= NULL;
    }
    if(m_szEvidence!=NULL) {
        free(m_szEvidence);
        m_szEvidence= NULL;
    }
    if(m_szResourceName!=NULL) {
        free(m_szResourceName);
        m_szResourceName= NULL;
    }
}


void Response::printMe()
{
    fprintf(g_logFile, "\tRequestType: %d\n", m_iRequestType);
    if(m_szAction==NULL)
        fprintf(g_logFile, "\tm_szAction is NULL\n");
    else
        fprintf(g_logFile, "\tm_szAction: %s \n", m_szAction);
    if(m_szResourceName==NULL)
        fprintf(g_logFile, "\tm_szResourceName is NULL\n");
    else
        fprintf(g_logFile, "\tm_szResourceName: %s \n", m_szResourceName);
    if(m_szErrorCode==NULL)
        fprintf(g_logFile, "\tm_szErrorCode is NULL\n");
    else
        fprintf(g_logFile, "\tm_szErrorCode: %s \n", m_szErrorCode);
    if(m_szEvidence==NULL)
        fprintf(g_logFile, "\tm_szEvidence is NULL\n");
    else
        fprintf(g_logFile, "\tm_szEvidence: %s \n", m_szEvidence);
    fprintf(g_logFile, "\tresourcelength: %d\n", m_iResourceLength);
}



bool  Response::getDatafromDoc(char* szResponse)
{
    TiXmlDocument   doc;
    TiXmlElement*   pRootElement;
    TiXmlNode*      pNode;
    TiXmlNode*      pNode1;

#ifdef  TEST1
    fprintf(g_logFile, "Response::getDatafromDoc\n%s\n", szResponse);
#endif
    if(!doc.Parse(szResponse)) {
        fprintf(g_logFile, "Response::getDatafromDoc: cant parse response\n");
        return false;
    }

    pRootElement= doc.RootElement();
    if(strcmp(pRootElement->Value(),"Response")!=0) {
        fprintf(g_logFile, "Response::getDatafromDoc: Should be response\n");
        return false;
    }

    m_iResourceLength= 0;
    
    pNode= pRootElement->FirstChild();
    while(pNode) {
        if(pNode->Type()==TiXmlNode::TINYXML_ELEMENT) {
            if(strcmp(((TiXmlElement*)pNode)->Value(),"Action")==0) {
                pNode1= pNode->FirstChild();
                if(pNode1!=NULL)
                    m_szAction= strdup(pNode1->Value());
            }
            if(strcmp(((TiXmlElement*)pNode)->Value(),"ResourceName")==0) {
                pNode1= pNode->FirstChild();
                if(pNode1!=NULL)
                    m_szResourceName= strdup(pNode1->Value());
            }
            if(strcmp(((TiXmlElement*)pNode)->Value(),"ResourceLength")==0) {
                pNode1= pNode->FirstChild();
                if(pNode1!=NULL) {
                    const char* szResourceLength= pNode1->Value();
                    if(szResourceLength!=NULL)
                        sscanf(szResourceLength,"%d", &m_iResourceLength);
                }
            }
            if(strcmp(((TiXmlElement*)pNode)->Value(),"ErrorCode")==0) {
                pNode1= pNode->FirstChild();
                if(pNode1!=NULL)
                    m_szErrorCode= strdup(pNode1->Value());
            }
            if(strcmp(((TiXmlElement*)pNode)->Value(),"EvidenceCollection")==0) {
                m_szEvidence= canonicalize(pNode);
            }
        }
        pNode= pNode->NextSibling();
    }

#ifdef  TEST1
    fprintf(g_logFile, "Response getdata\n");
    printMe();
#endif
    return true;
}


// -------------------------------------------------------------------------


const char* g_szPrefix= "//www.manferdelli.com/Gauss/";


bool translateLocationtoResourceName(const char* szLocation, const char* szResourceName, 
                                     int size)
{
    // Fix 
    return false;
}


bool translateResourceNametoLocation(const char* szResourceName, char* szLocation, 
                                     int size)
{
    int         n;
    const char*       p= szResourceName;

#ifdef  TEST1
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
#ifdef  TEST1
    fprintf(g_logFile, "size: %d %s\n", size, szLocation);
#endif
    return true;
}


int openFile(const char* szInFile, int* psize)
{
    struct stat statBlock;
    int         iRead= -1;

    iRead= open(szInFile, O_RDONLY);
    if(iRead<0) {
        return -1;
    }
    if(stat(szInFile, &statBlock)<0) {
        return -1;
    }
    *psize= statBlock.st_size;

    return iRead;
}

bool emptyChannel(safeChannel& fc, int size, int enckeyType, byte* enckey,
             int intkeyType, byte* intkey)
{
    int         type= CHANNEL_REQUEST;
    byte        multi=0;
    byte        final= 0;
    byte        fileBuf[MAXREQUESTSIZEWITHPAD];

    while(fc.safegetPacket(fileBuf, MAXREQUESTSIZE, &type, &multi, &final)>0);
    return true;
}


bool getFile(safeChannel& fc, int iWrite, int filesize, int datasize, 
             int encType, byte* enckey)
{
    int                 type= CHANNEL_RESPONSE;
    byte                multi, final;
    int                 n= 0;
    byte                fileBuf[MAXREQUESTSIZEWITHPAD];
    encryptedFilewrite  encFile;

#ifdef  TEST
    fprintf(g_logFile, "getFile %d %d\n", filesize, datasize);
    fflush(g_logFile);
#endif

    // Fix: Initialize file Encryption keys
    if(encType==NOENCRYPT) {
        if(!encFile.initEnc(filesize, datasize, 0, 0, 0, NOALG)) {
            fprintf(g_logFile, "getFile: Cant init initialize file keys\n");
            return false;
        }
    }
    else if(encType==DEFAULTENCRYPT) {
        if(!encFile.initEnc(filesize, datasize, enckey, 256, 
                        AES128, SYMPAD, CBCMODE, HMACSHA256)) {
            fprintf(g_logFile, "getFile: Cant init initialize file keys\n");
            return false;
        }
    }
    else {
        fprintf(g_logFile, "getFile: invalid encryption\n");
        return false;
    }

    // read file and write channel
    type= CHANNEL_TRANSFER;
    multi= 1;
    final= 0;
#ifdef  TEST
    fprintf(g_logFile, "getFile: receiving encrypted file \n");
    fflush(g_logFile);
#endif
    for(;;) {
        n= fc.safegetPacket(fileBuf, MAXREQUESTSIZE, &type, &multi, &final);
#ifdef  TEST
        fprintf(g_logFile, "getFile: received %d bytes\n", n);
        fflush(g_logFile);
#endif
        if(encFile.EncWrite(iWrite, fileBuf, n)<0) {
            fprintf(g_logFile, "getFile: bad write in fileTransfer\n");
        }
        if(final>0)
            break;
    }
#ifdef  TEST
    fprintf(g_logFile, "getFile returns true\n");
    fflush(g_logFile);
#endif
    return true;
}


bool sendFile(safeChannel& fc, int iRead, int filesize, int datasize, 
              int encType, byte* enckey)
{
    int                 type= CHANNEL_RESPONSE;
    byte                multi, final;
    int                 n= 0;
    byte                fileBuf[MAXREQUESTSIZEWITHPAD];
    encryptedFileread   encFile;

#ifdef  TEST
    fprintf(g_logFile, "sendFile: %d %d %d\n", 
            filesize, datasize, encType);
    fflush(g_logFile);
#endif
    if(encType==NOENCRYPT) {
        if(!encFile.initDec(filesize, datasize, 0, 0, 0, NOALG)) {
            fprintf(g_logFile, "sendFile: Cant init initialize file keys\n");
            return false;
        }
    }
    else if(encType==DEFAULTENCRYPT) {
        if(!encFile.initDec(filesize, datasize, enckey, 256, 
                        AES128, SYMPAD, CBCMODE, HMACSHA256)) {
            fprintf(g_logFile, "sendFile: Cant init initialize file keys\n");
            return false;
        }
    }
    else {
        fprintf(g_logFile, "sendFile: invalid encryption\n");
        return false;
    }

    // read file and write channel
    type= CHANNEL_TRANSFER;
    multi= 1;
    final= 0;
#ifdef  TEST
    fprintf(g_logFile, "sendFile: sending file\n"); 
    fflush(g_logFile);
#endif
    for(;;) {
        n= encFile.EncRead(iRead, fileBuf, MAXREQUESTSIZE);
        if(n<=0)
            break;
        datasize-= n;
        if(datasize<=0)
            final= 1;
#ifdef  TEST
        fprintf(g_logFile, "sendFile: safesend %d bytes\n", n);
        fflush(g_logFile);
#endif
        fc.safesendPacket(fileBuf, n, type, multi, final);
        if(final>0)
            break;
    }
#ifdef  TEST
    fprintf(g_logFile, "sendFile returns true\n");
#endif
    return true;
}


bool  constructRequest(char** pp, int* piLeft, const char* szAction, const char* szSubjectName,
                       const char* szResourceName, int size, const char* szEvidence)
{
#ifdef  TEST1
    char*p= *pp;
#endif

    if(!safeTransfer(pp, piLeft, szRequest1a))
        return false;
    if(!safeTransfer(pp, piLeft, szRequest2a))
        return false;
    if(!safeTransfer(pp, piLeft, szAction))
        return false;
    if(!safeTransfer(pp, piLeft, szRequest2b))
        return false;

    if(szEvidence==NULL) {
        if(!safeTransfer(pp, piLeft, szRequest3))
            return false;
    }
    else {
        if(!safeTransfer(pp, piLeft, szEvidence))
            return false;
    }

    if(!safeTransfer(pp, piLeft, szRequest4a))
        return false;
    if(!safeTransfer(pp, piLeft, szResourceName))
        return false;
    if(!safeTransfer(pp, piLeft, szRequest4b))
        return false;

    if(!safeTransfer(pp, piLeft, szRequest5a))
        return false;
    if(size>0) {
        sprintf(*pp,"%d", size);
        int k= strlen(*pp);
        *pp+= k;
        *piLeft-= k;
    }
    if(!safeTransfer(pp, piLeft, szRequest5b))
        return false;

    if(szSubjectName!=NULL) {
        if(!safeTransfer(pp, piLeft, szRequest6a))
            return false;
        if(!safeTransfer(pp, piLeft, szSubjectName))
            return false;
        if(!safeTransfer(pp, piLeft, szRequest6b))
            return false;
    }

    if(!safeTransfer(pp, piLeft, szRequest1b))
        return false;

#ifdef  TEST1
    fprintf(g_logFile, "constructRequest completed\n%s\n", p);
#endif
    return true;
}


bool  constructResponse(bool fError, char** pp, int* piLeft, const char* szResourceName, 
                        int size, const char* szChannelError)
{
    bool    fRet= true;
    int     n= 0;

#ifdef  TEST1
    char*   p= *pp;
#endif
    try {
        if(!safeTransfer(pp, piLeft, szResponse1))
            throw "constructResponse: Can't construct response\n";
        if(fError) {
            if(!safeTransfer(pp, piLeft, "reject"))
                throw "constructResponse: Can't construct response\n";
        }
        else {
            if(!safeTransfer(pp, piLeft, "accept"))
                throw "constructResponse: Can't construct response\n";
        }
        if(!safeTransfer(pp, piLeft, szResponse2))
            throw "Can't construct response\n";
        if(szChannelError!=NULL) {
            if(!safeTransfer(pp, piLeft, szChannelError))
                throw "constructResponse: Can't construct response\n";
        }
        if(!safeTransfer(pp, piLeft, szResponse3))
            throw "constructResponse: Can't construct response\n";
        if(szResourceName!=NULL) {
            if(!safeTransfer(pp, piLeft, szResourceName))
                throw "Can't construct response\n";
        }
        if(!safeTransfer(pp, piLeft, szResponse4))
            throw "constructResponse: Can't construct response\n";
        if(!fError) {
            if(*piLeft<10)
                throw "constructResponse: Can't construct response\n";
            sprintf(*pp, "%d", size);
            n= strlen(*pp);
            *piLeft-= n;
            *pp+= n;
        }
        if(!safeTransfer(pp, piLeft, szResponse5))
            throw "constructResponse: Can't construct response\n";
    }
    catch(const char* szConstructError) {
        fRet= false;
        fprintf(g_logFile, "%s", szConstructError);
    }

#ifdef  TEST1
    fprintf(g_logFile, "constructResponse completed\n%s\n", p);
#endif
    return fRet;
}


// -------------------------------------------------------------------------


bool clientgetResourcefromserver(safeChannel& fc, const char* szResourceName, 
            const char* szEvidence, const char* szOutFile, int encType, byte* key)
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
    if(!constructRequest(&p, &iLeft, "getResource", NULL, szResourceName, 0, NULL)) {
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
                encType, key)) {
        fprintf(g_logFile, "clientgetResourcefromserver: Can't get file\n");
        return false;
    }

    close(iWrite);
#ifdef  TEST
    fprintf(g_logFile, "clientgetResourcefromserver returns true\n");
#endif
    return true;
}


bool serversendResourcetoclient(safeChannel& fc, Request& oReq, sessionKeys& oKeys, int encType, byte* key)
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
    fError= !oReq.validateRequest(oKeys, &szFile, &pResource);

    // open File (if no Error)
    if(!fError) {
        iRead= openFile(szFile, &filesize);
        if(iRead<0) {
            fError= true;
            szError= "serversendResourcetoclient: Cant open file";
            fprintf(g_logFile, "serversendResourcetoclient: Open file error %s\n", szFile);
        }
    }
    datasize= pResource->m_iSize;

    // construct response
    if(!constructResponse(fError, &p, &iLeft, oReq.m_szResourceName, datasize, szError)) {
        fprintf(g_logFile, "serversendResourcetoclient: constructResponse error\n");
        return false;
    }

    // send response
    fc.safesendPacket(szBuf, (int)strlen(reinterpret_cast<char*>(szBuf))+1, type, multi, final);

    // send file
    if(!sendFile(fc, iRead, filesize, datasize, encType, key)) {
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


bool clientcreateResourceonserver(safeChannel& fc, const char* szResourceName, const char* szSubject, 
                                  const char* szEvidence, int encType, byte* key)
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
    if(!constructRequest(&p, &iLeft, "createResource", szSubject, 
                                    szResourceName, 0, szEvidence)) {
        fprintf(g_logFile, "clientcreateResourceonserver: constructRequest returns false\n");
        return false;
    }
    if((n=fc.safesendPacket((byte*)szBuf, strlen(szBuf)+1, CHANNEL_REQUEST, 0, 0)) <0) {
        fprintf(g_logFile, "clientcreateResourceonserver: safesendPacket after constructRequest returns false\n");
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

    // check response
    if(oResponse.m_szAction==NULL || strcmp(oResponse.m_szAction, "accept")!=0) {
        fprintf(g_logFile, "clientcreateResourceonserver: response is false\n");
        oResponse.printMe();
    }

#ifdef  TEST
    fprintf(g_logFile, "clientcreateResourceonserver returns true\n");
#endif
    return true;
}


bool servercreateResourceonserver(safeChannel& fc, Request& oReq, sessionKeys& oKeys, 
                                  int encType, byte* key)
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
        fprintf(g_logFile, "tmroeder: using location %s\n", pOwnerResource->m_szLocation);
        // Create directory if it doesn't exist
        struct stat  sb;
        if(stat(pOwnerResource->m_szLocation, &sb)!=0) {
            if(mkdir(pOwnerResource->m_szLocation, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH)!=0) {
                fprintf(g_logFile, "servercreateResourceonserver: can't make directory\n");
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
        fAllowed= oReq.validateRequest(oKeys, &szFile, &pResource);
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
    return true;
}


bool clientsendResourcetoserver(safeChannel& fc, const char* szSubject, const char* szResourceName, const char* szEvidence, 
                                const char* szInFile, int encType, byte* key)
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
    if(!constructRequest(&p, &iLeft, "sendResource", szSubject, szResourceName, 
                         filesize, NULL)) {
        fprintf(g_logFile, "clientsendResourcetoserver: constructRequest returns false\n");
        return false;
    }
    if((n=fc.safesendPacket((byte*)szBuf, strlen(szBuf)+1, CHANNEL_REQUEST, 0, 0)) <0) {
        fprintf(g_logFile, "clientsendResourcetoserver: safesendPacket after constructRequest returns false\n");
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
        oResponse.printMe();
        // fprintf(g_logFile, "Error: %s\n", oResponse.szErrorCode);
        return false;
    }

#ifdef  TEST
    fprintf(g_logFile, "clientsendResourcetoserver sending file\n");
    fflush(g_logFile);
#endif
    // send file
    if(!sendFile(fc, iRead, filesize, datasize, encType, key)) {
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


bool servergetResourcefromclient(safeChannel& fc, Request& oReq, sessionKeys& oKeys, 
                                 int encType, byte* key)
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
    fError= !oReq.validateRequest(oKeys, &szOutFile, &pResource);
    size= oReq.m_iResourceLength;
    pResource->m_iSize= size;

    // open for writing
    if(!fError) {
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
    }
    fc.safesendPacket(szBuf, strlen(reinterpret_cast<char*>(szBuf))+1, type, multi, final);

#ifdef  TEST
    fprintf(g_logFile, "servergetResourcefromclient getting file, %d\n", size);
    fflush(g_logFile);
#endif
    // read file
    if(!getFile(fc, iWrite, size, size, encType, key)) {
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


bool clientchangeownerResource(safeChannel& fc, const char* szAction, const char* szResourceName,
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
    if(!constructRequest(&p, &iLeft, szAction, NULL, szResourceName, 0, szEvidence)) {
        fprintf(g_logFile, "clientchangeownerResource: constructRequest returns false\n");
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


bool serverchangeownerofResource(safeChannel& fc, Request& oReq, sessionKeys& oKeys, 
                                 int encType, byte* key)
// includes delete
{
    resource*           pResource= NULL;
    accessPrincipal*    pPrinc= NULL;
    char*               szFile= NULL;

#ifdef  TEST
    fprintf(g_logFile, "serverchangeownerofResource\n");
    fflush(g_logFile);
#endif
    if(!oReq.validateRequest(oKeys, &szFile, &pResource))
        return false;

    if(oReq.m_iRequestType==ADDOWNER) {
        pPrinc= g_theVault.findPrincipal(oReq.m_szResourceName);
        if(pPrinc==NULL)
            return false;
        return pResource->m_myOwners.append(pPrinc);
        
    }

    if(oReq.m_iRequestType==REMOVEOWNER) {
        pPrinc= g_theVault.findPrincipal(oReq.m_szResourceName);
        if(pPrinc==NULL)
            return false;
        return pResource->m_myOwners.deletenode(pPrinc);
    }

    return false;
}


bool clientdeleteResource(safeChannel& fc, const char* szResourceName,
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
    if(!constructRequest(&p, &iLeft, "deleteResource", NULL, szResourceName, 0, szEvidence)) {
        fprintf(g_logFile, "clientdeleteResource: constructRequest returns false\n");
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


bool serverdeleteResource(safeChannel& fc, Request& oReq, sessionKeys& oKeys, 
                          int encType, byte* key)
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
    fError= !oReq.validateRequest(oKeys, &szFile, &pResource);

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
    return true;
}


// ---------------------------------------------------------------------------------


