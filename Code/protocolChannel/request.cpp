//  File: request.cpp
//  Description: cloudProxy request response objects
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


const char*   s_szRequestTemplate=
"<Request>\n"\
"  <Action> %s </Action>\n"\
"%s"\
"    <ResourceName> %s </ResourceName>\n"\
"    <ResourceLength> %d </ResourceLength>\n"\
"%s"\
"</Request>\n";


const char*   s_szResponseTemplate=
"<Response>\n"\
"  <Action> %s </Action>\n"\
"  %s"\
"  <ResourceName> %s </ResourceName>\n"\
"  <ResourceLength> %d </ResourceLength>\n"\
"%s"\
"</Response>\n";


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

#ifdef TEST1
    fprintf(g_logFile, "Request getdata\n");
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
    m_szProtectedElement= NULL;
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
    if(m_szProtectedElement!=NULL) {
        free(m_szProtectedElement);
        m_szProtectedElement= NULL;
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

#ifdef TEST1
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
                else
                    m_szErrorCode= NULL;
            }
            if(strcmp(((TiXmlElement*)pNode)->Value(),"EvidenceCollection")==0) {
                m_szEvidence= canonicalize(pNode);
            }
            if(strcmp(((TiXmlElement*)pNode)->Value(),"ProtectedElement")==0) {
                m_szProtectedElement= canonicalize(pNode);
            }
        }
        pNode= pNode->NextSibling();
    }

#ifdef TEST1
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

#ifdef TEST1
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
#ifdef TEST1
    fprintf(g_logFile, "getFile: receiving encrypted file \n");
    fflush(g_logFile);
#endif
    for(;;) {
        n= fc.safegetPacket(fileBuf, MAXREQUESTSIZE, &type, &multi, &final);
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
#ifdef  TEST1
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
                       int resSize, const char* szEvidence)
{
#ifdef  TEST1
    char* p= *pp;
    fprintf(g_logFile, "constructRequest started %s %s %s %d %s\n",
             szAction, szSubjectName, szResourceName, resSize, szEvidence);
    fflush(g_logFile);
#endif
    const char*   szNoEvidence= "  <EvidenceCollection count='0'/>\n";
    const char*   szSubjTemplate= "    <SubjectName> %s </SubjectName>\n";
    char          szSubjectElement[512];
    int           size= strlen(s_szRequestTemplate)+strlen(szAction)+strlen(szResourceName);

    if(szEvidence==NULL) {
        szEvidence= szNoEvidence;
    }
    size+= strlen(szEvidence);
    if(szSubjectName!=NULL) {
        if((strlen(szSubjTemplate)+strlen(szSubjectName)+4)>512) {
            fprintf(g_logFile, "constructRequest: subject name too large\n");
            fflush(g_logFile);
            return false;
        }
        sprintf(szSubjectElement, szSubjTemplate, szSubjectName);
    }
    else {
        szSubjectElement[0]= 0;
    }
    size+= strlen(szSubjectElement);

    if((size+8)>*piLeft) {
        fprintf(g_logFile, "constructRequest: request too large %d %d\n", size, *piLeft);
        fflush(g_logFile);
        return false;
    }    
    sprintf(*pp, s_szRequestTemplate, szAction, szEvidence, szResourceName, 
            resSize, szSubjectElement);
    int len= strlen(*pp);
    *piLeft-= len;
    *pp+= len;
#ifdef  TEST1
    fprintf(g_logFile, "constructRequest completed\n%s\n", p);
    fflush(g_logFile);
#endif
    return true;
}


bool  constructResponse(bool fError, char** pp, int* piLeft, 
                        const char* szResourceName, int resSize, 
                        const char* szExtraResponseElements,
                        const char* szChannelError)
{
/*
 * <Response>
 *   %s
 *   <ResourceName> %s </ResourceName>
 *   <ResourceLength> %d </ResourceLength>
 * %s        Extra
 * </Response>
 */
#ifdef  TEST
    char* p= *pp;
#endif
    const char*   szErrorFormat= " <ErrorCode> %s </ErrorCode>\n";
    char          szErrorElement[256];
    const char*   szRes= NULL;

    int size= strlen(s_szResponseTemplate)+strlen(szResourceName);
    if(fError)
        szRes= "reject";
    else
        szRes= "accept";
    size+= strlen(szRes);
    if(szExtraResponseElements!=NULL)
        size+= strlen(szExtraResponseElements);
    else
        szExtraResponseElements= "";
    if(szChannelError!=NULL) {
        if((strlen(szErrorFormat)+strlen(szChannelError)+8)>256) {
            fprintf(g_logFile, "constructResponse: too large\n");
            return false;
        }
        sprintf(szErrorElement, szErrorFormat, szChannelError);
        size+= strlen(szErrorElement);
    }
    else {
        szErrorElement[0]= 0;
    }
    if((size+16)>*piLeft) {
        fprintf(g_logFile, "constructResponse: response too large\n");
        return false;
    }
    sprintf(*pp, s_szResponseTemplate,  szRes, szErrorElement, szResourceName, 
            resSize, szExtraResponseElements);
    int len= strlen(*pp);
    *piLeft-= len;
    *pp+= len;
#ifdef TEST
    fprintf(g_logFile, "constructResponse completed\n%s\n", p);
    fflush(g_logFile);
#endif
    return true;
}


// -------------------------------------------------------------------------


