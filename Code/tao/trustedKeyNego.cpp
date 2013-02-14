//
//  File: trustedKeyNego.cpp
//      John Manferdelli
//
//  Description: trusted key negotiation and key storage
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


#include "jlmTypes.h"
#include "logging.h"
#include "jlmcrypto.h"
#include "keys.h"
#include "jlmUtility.h"
#include "channel.h"
#include "trustedKeyNego.h"

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


#define MAXTRY 30

#define KEYSERVERPORT  6001


// -------------------------------------------------------------------------


/*
 *      Key Nego protocol
 *
 *      C-->S: Key sign request, initProxyCert, quotest info for
 *              client generated private key (includes client hash),
 *              certificate chain for platform key signing
 *
 *      S-->C: success/fail, EvidenceList supporting signed client cert(included
 *              in evidenceList)
 *
 */


const char* g_szRequestSig=
    "<clientCertNego phase='1'>\n    <policyKeyId> %s </policyKeyId>\n"\
    "    <signedRequest> %s </signedRequest>\n"\
    "    %s\n</clientCertNego>\n";


bool clientCertNegoMessage1(char* buf, int maxSize, const char* szpolicyKeyId, 
                           const char* szQuoted, const char* szEvidenceList)
{
#ifdef  TEST1
    fprintf(g_logFile, "clientCertNegoMessage1 %d %s %s %s\n", maxSize, 
            szpolicyKeyId, szQuoted, szEvidenceList);
#endif
    int iSize= strlen(g_szRequestSig)+ strlen(szpolicyKeyId)+
               strlen(szQuoted)+strlen(szEvidenceList);

    if(iSize>=maxSize) {
        fprintf(g_logFile, "Request too large\n");
        return false;
    }
    sprintf(buf, g_szRequestSig, szpolicyKeyId, szQuoted, szEvidenceList);
#ifdef  TEST1
    fprintf(g_logFile, "\n%s\n", buf);
#endif
    return true;
}


bool getDatafromServerCertMessage1(const char* response, char** pszstatus, 
        char** pszerrorCode, char** pszCert)
{
    TiXmlDocument   doc;
    TiXmlNode*      pNode;
    TiXmlNode*      pNode1;
    TiXmlElement*   pRootElement= NULL;
    const char*           szLabel= NULL;
    const char*           szStatus= NULL;
    const char*           szErrorCode= NULL;
    int             phase;
    bool            fRet= true;

#ifdef  TEST1
    fprintf(g_logFile, "getDatafromServerkeyMessage1\n%s\n", response);
#endif
    try {

        // Parse document
        if(!doc.Parse(response)) 
            throw "Message 1 parse failure in key Nego\n";
        pRootElement= doc.RootElement();
        if(pRootElement==NULL) 
            throw "Cant find root\n";
        szLabel= pRootElement->Value();
        if(szLabel==NULL || strcmp("serverCertNego", szLabel)!=0)
            throw "Bad response format (no serverCertNego)\n";
            
        pRootElement->QueryIntAttribute("phase", &phase);

        // Status
        pNode= Search((TiXmlNode*) pRootElement, "Status");
        if(pNode==NULL)
            throw "Cant find status in server message 1\n";
        pNode1= pNode->FirstChild();
        if(pNode1==NULL)
            throw "Bad status in server message";
        szStatus=  pNode1->Value();
        if(szStatus==NULL)
            throw "Bad status value in server message";
        *pszstatus= strdup(szStatus);

        // Error Code
        pNode= Search((TiXmlNode*) pRootElement, "ErrorCode");
        if(pNode==NULL)
            throw "Cant find error code in server message 1\n";
        pNode1= pNode->FirstChild();
        if(pNode1==NULL) {
            *pszerrorCode= NULL;
        }
        else {
            szErrorCode= pNode1->Value();
            if(szErrorCode==NULL)
                *pszerrorCode= NULL;
            else
                *pszerrorCode= strdup(szErrorCode);
        }

        // Cert
        pNode= Search((TiXmlNode*) pRootElement, "Cert");
        if(pNode==NULL)
            throw "Cant find cert in server message 1\n";
        pNode1= pNode->FirstChild();
        if(pNode1==NULL) {
            *pszCert= NULL;
        }
        else {
            *pszCert= canonicalize(pNode1);
        }
    }
    catch(const char* szError) {
        fRet= false;
        fprintf(g_logFile, "%s", szError);
    }

#ifdef  TEST
    fprintf(g_logFile, "getDatafromServerkeyMessage1 returning true\n");
#endif
    return fRet;
}


bool validateResponse(const char* szStatus, const char* szErrorCode, const char* szCert)
{
#ifdef  TEST1
    fprintf(g_logFile, "validateResponse %s\n", szStatus);
#endif
    if(strcmp(szStatus, "accept")!=0)
        return false;
    return true;
}


// ------------------------------------------------------------------------


bool KeyNego(const char* szQuote, const char* szEvidenceList, char** pszCert)
{
    bool                fRet= true;
    int                 iError= 0;
    int                 fd= 0;
    struct sockaddr_in  server_addr;
    int                 slen= sizeof(struct sockaddr_in);
    char                rgBuf[MAXREQUESTSIZE];
    int                 n= 0;
    int                 type= 0;
    byte                multi= 0;
    byte                final= 0;

    RSAKey*             pKey= NULL;
    char*               szMyPrivateKey= NULL;
    const char*         szpolicyKeyId= NULL;
    char*               szMySignedInfo= NULL;
    char*               szStatus= NULL;
    char*               szErrorCode= NULL;
    char*               szCert= NULL;

#ifdef TEST
    fprintf(g_logFile, "KeyNego()\n");
#endif
#ifdef TEST1
    fprintf(g_logFile, "Quote:\n%s\n", szQuote);
    fprintf(g_logFile, "EvidenceList:\n%s\n", szEvidenceList);
#endif

    try {
    
        // open socket
        fd= socket(AF_INET, SOCK_STREAM, 0);
        if(fd<0) 
            throw  "Can't get socket\n";
        memset((void*) &server_addr, 0, sizeof(struct sockaddr_in));

#ifdef  TEST
        fprintf(g_logFile, "KeyNego: socket opened\n");
#endif
        server_addr.sin_family= AF_INET;
        server_addr.sin_addr.s_addr= htonl(INADDR_ANY);
        server_addr.sin_port= htons(KEYSERVERPORT);
    
#ifdef  TEST
        fprintf(g_logFile, "KeyNego: about to connect\n");
#endif

        iError= connect(fd, (const struct sockaddr*) &server_addr, (socklen_t) slen);
        if(iError<0)
            throw  "initializeKeys: can't connect";

        szpolicyKeyId= "Key1";
#ifdef  TEST
        fprintf(g_logFile, "initialize keys connect completed\n");
#endif

        // construct and send request
        if(!clientCertNegoMessage1(rgBuf, MAXREQUESTSIZE, szpolicyKeyId,
                           szQuote, szEvidenceList))
            throw  "Can't construct request";
        if((n=sendPacket(fd, (byte*)rgBuf, strlen(rgBuf)+1, CHANNEL_NEGO, 0, 1))<0)
            throw  "Can't send Packet 1 in certNego\n";

        // get and interpret response
         if((n=getPacket(fd, (byte*)rgBuf, MAXREQUESTSIZE, &type, &multi, &final))<0)
            throw  "Can't get packet 1 certNego\n";
        if(!getDatafromServerCertMessage1(rgBuf, &szStatus, &szErrorCode, &szCert))
            throw  "server response invalid\n";

        // everything OK?
        if(!validateResponse(szStatus, szErrorCode, szCert))
            throw  "server response invalid\n";

        // cert
        *pszCert= szCert;
#ifdef TEST1
        fprintf(g_logFile, "Cert: %s\n", szCert);
#endif
    }
    catch(const char* szError) {
        fRet= false;
        fprintf(g_logFile, "Error: %s\n", szError);
    }

    // clean up
    if(szMySignedInfo!=NULL) {
        free(szMySignedInfo);
        szMySignedInfo= NULL;
    }
    if(szMyPrivateKey!=NULL) {
        free(szMyPrivateKey);
        szMyPrivateKey= NULL;
    }
    if(pKey!=NULL) {
        delete pKey;
        pKey= NULL;
    }

    return fRet;
}


// ------------------------------------------------------------------------


