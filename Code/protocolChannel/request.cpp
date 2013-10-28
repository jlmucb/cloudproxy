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
// #include "vault.h"
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
const char*   szResponse3= "</ErrorCode>\n  <ResourceName>";
const char*   szResponse4= "</ResourceName>\n <ResourceLength>";
const char*   szResponse5= "</ResourceLength>\n </Response>\n";


// ------------------------------------------------------------------------


Request::Request()
{
    m_iResourceLength= 0;
    m_szSubjectName= NULL;
    m_szAction= NULL;
    m_szResourceName= NULL;
    m_szEvidence= NULL;
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
}


bool  Request::getDatafromDoc(const char* szRequest)
{
    TiXmlDocument   doc;
    TiXmlElement*   pRootElement= NULL;
    TiXmlNode*      pNode= NULL;
    TiXmlNode*      pNode1= NULL;

    const char*     szAction= NULL;
    const char*     szResourceName= NULL;
    const char*     szResourceLength= NULL;
    const char*     szSubjectName= NULL;
    const char*     szEvidence= NULL;

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

#ifdef TEST
    fprintf(g_logFile, "Response getdata\n");
    printMe();
    fflush(g_logFile);
#endif
    return true;
}


#ifdef TEST
void Request::printMe()
{
    fprintf(g_logFile, "\n\tRequest action: %s\n", m_szAction);
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
#endif


// ------------------------------------------------------------------------


Response::Response()
{
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


#ifdef TEST
void Response::printMe()
{
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
#endif


bool  Response::getDatafromDoc(char* szResponse)
{
    TiXmlDocument   doc;
    TiXmlElement*   pRootElement= NULL;
    TiXmlNode*      pNode= NULL;
    TiXmlNode*      pNode1= NULL;

#ifdef TEST
    fprintf(g_logFile, "Response::getDatafromDoc\n%s\n", szResponse);
    fflush(g_logFile);
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

#ifdef TEST
    fprintf(g_logFile, "Response getdata\n");
    printMe();
    fflush(g_logFile);
#endif
    return true;
}


// -------------------------------------------------------------------------



int openFile(const char* szInFile, int* psize)
{
    struct stat statBlock;
    int         iRead= -1;

#ifdef TEST
    fprintf(g_logFile, "openFile: %s\n", szInFile);
    fflush(g_logFile);
#endif

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
             int encType, byte* enckey, timer& encTimer)
{
    int                 type= CHANNEL_RESPONSE;
    byte                multi, final;
    int                 n= 0;
    byte                fileBuf[MAXREQUESTSIZEWITHPAD];
    encryptedFilewrite  encFile;

#ifdef TEST
    fprintf(g_logFile, "getFile %d %d, enc is %d\n", filesize, datasize, encType);
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
#ifdef TEST
    fprintf(g_logFile, "getFile: receiving encrypted file \n");
    fflush(g_logFile);
#endif
    for(;;) {
        n= fc.safegetPacket(fileBuf, MAXREQUESTSIZE, &type, &multi, &final);
#ifdef TEST
        fprintf(g_logFile, "getFile: received %d bytes\n", n);
        fflush(g_logFile);
#endif
        encTimer.Start();
        if(encFile.EncWrite(iWrite, fileBuf, n)<0) {
            fprintf(g_logFile, "getFile: bad write in fileTransfer\n");
        }
        encTimer.Stop();
        if(final>0)
            break;
    }
#ifdef TEST
    fprintf(g_logFile, "getFile returns true\n");
    fflush(g_logFile);
#endif
    return true;
}


bool sendFile(safeChannel& fc, int iRead, int filesize, int datasize, 
              int encType, byte* enckey, timer& decTimer)
{
    int                 type= CHANNEL_RESPONSE;
    byte                multi, final;
    int                 n= 0;
    byte                fileBuf[MAXREQUESTSIZEWITHPAD];
    encryptedFileread   encFile;

#ifdef TEST
    fprintf(g_logFile, "sendFile: %d %d %d\n", filesize, datasize, encType);
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
        decTimer.Start();
        n= encFile.EncRead(iRead, fileBuf, MAXREQUESTSIZE);
        decTimer.Stop();
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


bool  constructRequest(char** pp, int* piLeft, const char* szAction, 
                       const char* szSubjectName, const char* szResourceName, 
                       int size, const char* szEvidence)
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


bool  constructResponse(bool fError, char** pp, int* piLeft, 
                        const char* szResourceName, int size, 
                        const char* szChannelError)
{
    bool    fRet= true;
    int     n= 0;

#ifdef  TEST
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

#ifdef  TEST
    fprintf(g_logFile, "constructResponse completed\n%s\n", p);
#endif
    return fRet;
}


// -------------------------------------------------------------------------


