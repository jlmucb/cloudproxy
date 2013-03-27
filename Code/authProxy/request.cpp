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
#include "request.h"
#include "encryptedblockIO.h"
#include "claims.h"
#include "bignum.h"
#include "mpFunctions.h"

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

const char*   szRequest2a= "<Action>";
const char*   szRequest2b= "</Action>\n";

const char*   szRequest3a= "    <SubjectName>";
const char*   szRequest3b=  "</SubjectName>\n";

const char*   szRequest4a= "<CredentialType>";
const char*   szRequest4b= "</CredentialType>\n";

const char*   szRequest5a= "    <IdentityCertificate>";
const char*   szRequest5b=  "</IdentityCertificate>\n";

const char*   szRequest6= "    <EvidenceCollection count='0'/>\n";
const char*   szRequest6a= "    <EvidenceCollection count='%d'>\n";
const char*   szRequest6b= "    </EvidenceCollection>\n";

const char*   szRequest7a= "<PublicKey>";
const char*   szRequest7b= "</PublicKey>\n";


const char*   szResponse1= "<Response>\n";
const char*   szResponse2= "<ErrorCode>";
const char*   szResponse3= "</ErrorCode>\n  <CredentialName>";
const char*   szResponse4= "</CredentialName>\n <Credential>";
const char*   szResponse5= "</Credential>\n </Response>\n";


// ------------------------------------------------------------------------



Request::Request()
{
    m_iRequestType= 0;
    m_szSubjectName= NULL;
    m_szAction= NULL;
    m_szCredentialType= NULL;
    m_szEvidence= NULL;
    // m_poAG= NULL;
}


Request::~Request()
{
    if(m_szCredentialType!=NULL) {
        free(m_szCredentialType);
        m_szCredentialType= NULL;
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
    // m_poAG= NULL;
}


bool  Request::getDatafromDoc(const char* szRequest)
{
    TiXmlDocument   doc;
    TiXmlElement*   pRootElement;
    TiXmlNode*      pNode;
    TiXmlNode*      pNode1;

    const char*           szAction= NULL;
    const char*           szCredentialType= NULL;
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
            if(strcmp(((TiXmlElement*)pNode)->Value(),"PublicKey")==0) {
                pNode1= pNode->FirstChild();
                if(pNode1!=NULL) {
                    m_szPublicKey= canonicalize(pNode1);
                }
            }
            if(strcmp(((TiXmlElement*)pNode)->Value(),"CredentialType")==0) {
                pNode1= pNode->FirstChild();
                if(pNode1!=NULL) {
                    szCredentialType= pNode1->Value();
                }
            }
            if(strcmp(((TiXmlElement*)pNode)->Value(),"SubjectName")==0) {
                pNode1= pNode->FirstChild();
                if(pNode1!=NULL) {
                    szSubjectName= pNode1->Value();
                }
            }
            if(strcmp(((TiXmlElement*)pNode)->Value(),"EvidenceCollection")==0) {
                szEvidence= canonicalize(pNode);
            }
        }
        pNode= pNode->NextSibling();
    }

    if(szAction==NULL || szCredentialType==NULL)
        return false;

    if(szAction!=NULL)
        m_szAction= strdup(szAction);
    if(szCredentialType!=NULL)
        m_szCredentialType= strdup(szCredentialType);
    if(szSubjectName!=NULL)
        m_szSubjectName= strdup(szSubjectName);
    if(szEvidence!=NULL)
        m_szEvidence= strdup(szEvidence);

    else if(strcmp(m_szAction, "GetToken")==0)
        m_iRequestType= GETTOKEN;
    else
        m_iRequestType= 0;

#ifdef TEST
    fprintf(g_logFile, "Response getdata\n");
    printMe();
#endif
    return true;
}


#ifdef TEST
void Request::printMe()
{
    fprintf(g_logFile, "\n\tRequest type: %d\n", m_iRequestType);
    if(m_szCredentialType==NULL)
        fprintf(g_logFile, "\tm_szCredentialType is NULL\n");
    else
        fprintf(g_logFile, "\tm_szCredentialType: %s \n", m_szCredentialType);
    if(m_szSubjectName==NULL)
        fprintf(g_logFile, "\tm_szSubjectName is NULL\n");
    else
        fprintf(g_logFile, "\tm_szSubjectName: %s \n", m_szSubjectName);
    if(m_szEvidence==NULL)
        fprintf(g_logFile, "\tm_szEvidence is NULL\n");
    else
        fprintf(g_logFile, "\tm_szEvidence: %s \n", m_szEvidence);
    if(m_szPublicKey==NULL)
        fprintf(g_logFile, "\tm_szPublicKey is NULL\n");
    else
        fprintf(g_logFile, "\tm_szPublicKey: %s \n", m_szPublicKey);
}
#endif


bool  Request::validateCredentialRequest(sessionKeys& oKeys, char* szCredType,
                            char* szSubject, char* szEvidence)
{
    // Access allowed?
    return true;
}

 
// ------------------------------------------------------------------------


Response::Response()
{
    m_iRequestType= 0;
    m_szAction= NULL;
    m_szErrorCode= NULL;
    m_szCredentialType= NULL;
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
    if(m_szCredentialType!=NULL) {
        free(m_szCredentialType);
        m_szCredentialType= NULL;
    }
}


#ifdef TEST
void Response::printMe()
{
    fprintf(g_logFile, "\tRequestType: %d\n", m_iRequestType);
    if(m_szAction==NULL)
        fprintf(g_logFile, "\tm_szAction is NULL\n");
    else
        fprintf(g_logFile, "\tm_szAction: %s \n", m_szAction);
    if(m_szCredentialType==NULL)
        fprintf(g_logFile, "\tm_szCredentialType is NULL\n");
    else
        fprintf(g_logFile, "\tm_szCredentialType: %s \n", m_szCredentialType);
    if(m_szErrorCode==NULL)
        fprintf(g_logFile, "\tm_szErrorCode is NULL\n");
    else
        fprintf(g_logFile, "\tm_szErrorCode: %s \n", m_szErrorCode);
    if(m_szEvidence==NULL)
        fprintf(g_logFile, "\tm_szEvidence is NULL\n");
    else
        fprintf(g_logFile, "\tm_szEvidence: %s \n", m_szEvidence);
    if(m_szToken==NULL)
        fprintf(g_logFile, "\tm_szToken is NULL\n");
    else
        fprintf(g_logFile, "\tm_szToken: %s \n", m_szToken);
}
#endif


bool  Response::getDatafromDoc(char* szResponse)
{
    TiXmlDocument   doc;
    TiXmlElement*   pRootElement;
    TiXmlNode*      pNode;
    TiXmlNode*      pNode1;

#ifdef TEST
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

    pNode= pRootElement->FirstChild();
    while(pNode) {
        if(pNode->Type()==TiXmlNode::TINYXML_ELEMENT) {
            if(strcmp(((TiXmlElement*)pNode)->Value(),"Action")==0) {
                pNode1= pNode->FirstChild();
                if(pNode1!=NULL)
                    m_szAction= strdup(pNode1->Value());
            }
            if(strcmp(((TiXmlElement*)pNode)->Value(),"CredentialType")==0) {
                pNode1= pNode->FirstChild();
                if(pNode1!=NULL)
                    m_szCredentialType= strdup(pNode1->Value());
            }
            if(strcmp(((TiXmlElement*)pNode)->Value(),"ErrorCode")==0) {
                pNode1= pNode->FirstChild();
                if(pNode1!=NULL)
                    m_szErrorCode= strdup(pNode1->Value());
            }
            if(strcmp(((TiXmlElement*)pNode)->Value(),"Token")==0) {
                pNode1= pNode->FirstChild();
                if(pNode1!=NULL)
                    m_szToken= canonicalize(pNode1);
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
#endif
    return true;
}


// -------------------------------------------------------------------------


const char* g_szPrefix= "//www.manferdelli.com/Gauss/";


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



bool  constructRequest(char** pp, int* piLeft, const char* szAction, const char* szSubjectName,
                       const char* szCredentialType, const char* szIdentityCert, const char* szEvidence,
                       const char* szKeyinfo)

{
#ifdef  TEST
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

    if(!safeTransfer(pp, piLeft, szRequest4a))
        return false;
    if(!safeTransfer(pp, piLeft, szCredentialType))
        return false;
    if(!safeTransfer(pp, piLeft, szRequest4b))
        return false;

    if(szSubjectName!=NULL) {
        if(!safeTransfer(pp, piLeft, szRequest3a))
            return false;
        if(!safeTransfer(pp, piLeft, szSubjectName))
            return false;
        if(!safeTransfer(pp, piLeft, szRequest3b))
            return false;
    }

    if(!safeTransfer(pp, piLeft, szRequest5a))
        return false;
    if(!safeTransfer(pp, piLeft, szIdentityCert))
        return false;
    if(!safeTransfer(pp, piLeft, szRequest5b))
        return false;

    if(szEvidence!=NULL) {
        if(!safeTransfer(pp, piLeft, szEvidence))
            return false;
    }

    if(!safeTransfer(pp, piLeft, szRequest7a))
        return false;
    if(!safeTransfer(pp, piLeft, szKeyinfo))
        return false;
    if(!safeTransfer(pp, piLeft, szRequest7b))
        return false;

    if(!safeTransfer(pp, piLeft, szRequest1b))
        return false;

#ifdef  TEST
    fprintf(g_logFile, "constructRequest completed\n%s\n", p);
#endif
    return true;
}


bool  constructResponse(bool fError, char** pp, int* piLeft, const char* szCredentialName, 
                        const char* szCredential, const char* szChannelError)
{
    bool    fRet= true;
    // int     n= 0;

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
        if(szCredentialName!=NULL) {
            if(!safeTransfer(pp, piLeft, szCredentialName))
                throw "Can't construct response\n";
        }
        if(!safeTransfer(pp, piLeft, szResponse4))
            throw "constructResponse: Can't construct response\n";
        if(!safeTransfer(pp, piLeft, szCredential))
            throw "constructResponse: Can't construct response\n";
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


//
//      Applicatiion logic
//

bool clientgetCredentialfromserver(safeChannel& fc, 
                const char* szSubjectName, const char* szCredentialType, 
                const char* szIdentityCert, const char* szEvidence, 
                const char* szKeyinfo, const char* szOutFile, int encType, byte* key, 
                timer& encTimer)
{
    char        szBuf[MAXREQUESTSIZEWITHPAD];
    int         iLeft= MAXREQUESTSIZE;
    char*       p= szBuf;
    Response    oResponse;
    int         n= 0;
    int         type= CHANNEL_REQUEST;
    byte        multi=0;
    byte        final= 0;
    const char* szAction= "GetToken";

#ifdef  TEST
    fprintf(g_logFile, "clientgetCredentialfromserver(%s, %s)\n", szCredentialType, szOutFile);
#endif
    // send request
    if(!constructRequest(&p, &iLeft, szAction, szSubjectName, szCredentialType, 
                         szIdentityCert, szEvidence, szKeyinfo)) {
        return false;
    }
#ifdef  TEST
    fprintf(g_logFile, "clientgetCredentialfromserver request\n%s\n", szBuf);
#endif
    if((n=fc.safesendPacket((byte*)szBuf, strlen(szBuf)+1, CHANNEL_REQUEST, 0, 0)) <0) {
        return false;
    }

    // should be a CHANNEL_RESPONSE, not multipart
    n= fc.safegetPacket((byte*)szBuf, MAXREQUESTSIZE, &type, &multi, &final);
    if(n<0) {
        fprintf(g_logFile, "clientgetCredentialfromserver: getCredential error %d\n", n);
        fprintf(g_logFile, "clientgetCredentialfromserver: server response %s\n", szBuf);
        return false;
    }
    szBuf[n]= 0;
    oResponse.getDatafromDoc(szBuf);

    // check response
    if(strcmp(oResponse.m_szAction, "accept")!=0) {
        fprintf(g_logFile, "Error: %s\n", oResponse.m_szErrorCode);
        return false;
    }

    // save credential
    int     iWrite= open(szOutFile, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if(iWrite<0) {
        // emptyChannel(fc, oResponse.m_iCredentialLength, 0, NULL, 0, NULL);
        fprintf(g_logFile, "clientgetCredentialfromserver: Cant open out file\n");
        return false;
    }
    if(write(iWrite, oResponse.m_szToken, strlen(oResponse.m_szToken))<0) {
        fprintf(g_logFile, "clientgetCredentialfromserver: Cant write token\n");
        return false;
    }
    close(iWrite);
#ifdef  TEST
    fprintf(g_logFile, "clientgetCredentialfromserver returns true\n");
#endif
    return true;
}


char*  constructCert(Request& oReq, RSAKey* signingKey)
{
    char*   szAlg= NULL;
    char*   szNonce= NULL;
    char*   szSignedInfo= NULL;
    char*   szCert= NULL;
    Sha256  oHash;
    byte    rgHash[SHA256_DIGESTSIZE_BYTES];
    byte    rgPadded[1024];
    int     base64Size= 1024;
    char    szbase64[1024];

    char*   szCertid= (char*)"00002";
    int     serialNo= 0;
    char*   szPrincipalType= (char*)"Security Principal";
    char*   szIssuerName= (char*) "AuthProxy Issuing Service";
    char*   szIssuerID= (char*) "AuthProxy";
    // FIX:  these should be short term keys!
    char*   szNotBefore= (char*)"2012-01-01Z00:00.00";
    char*   szNotAfter= (char*)"2021-01-01Z00:00.00";
    char*   szSubjName= oReq.m_szSubjectName;
    char*   szSubjKeyID= oReq.m_szSubjectName;

    RSAKey* signedKey= NULL;

    bnum    bnMsg(128);
    bnum    bnOut(128);

    bool    fRet= true;

    signedKey= keyfromkeyInfo((char*) oReq.m_szPublicKey);
    if(signedKey==NULL) {
        fprintf(g_logFile, "validateRequestandIssue: cant generate SignedInfo\n");
        fRet= false;
        goto cleanup;
    }

    // encode signed body
    szSignedInfo= formatSignedInfo(signedKey, szCertid, serialNo, szPrincipalType, 
            szIssuerName, szIssuerID, szNotBefore, szNotAfter,
            szSubjName, (char*)"", (char*)"", szSubjKeyID);
    if(szSignedInfo==NULL) {
        fprintf(g_logFile, "validateRequestandIssue: cant generate SignedInfo\n");
        fRet= false;
        goto cleanup;
    }

#ifdef  TEST
    fprintf(g_logFile, "hashing\n");
#endif
    // hash, pad, sign
    oHash.Init();
    oHash.Update((byte*) szSignedInfo, strlen(szSignedInfo));
    oHash.Final();
    oHash.GetDigest(rgHash);

#ifdef  TEST
    fprintf(g_logFile, "padding\n");
#endif
    if(!emsapkcspad(SHA256HASH, rgHash, signingKey->m_iByteSizeM, rgPadded)) {
        fprintf(g_logFile, "constructCert: bad pad\n");
        fRet= false;
        goto cleanup;
    }

#ifdef  TEST
    fprintf(g_logFile, "signing\n");
#endif
    memset(bnMsg.m_pValue, 0, signingKey->m_iByteSizeM);
    memset(bnOut.m_pValue, 0, signingKey->m_iByteSizeM);
    revmemcpy((byte*)bnMsg.m_pValue, rgPadded, signingKey->m_iByteSizeM);

    if(!mpRSAENC(bnMsg, *(signingKey->m_pbnD), *(signingKey->m_pbnM), bnOut)) {
        fprintf(g_logFile, "constructCert: decrypt failed\n");
        fRet= false;
        goto cleanup;
    }

#ifdef  TEST
    fprintf(g_logFile, "base64 encode\n");
#endif
    if(!toBase64(signingKey->m_iByteSizeM, (byte*)bnOut.m_pValue, &base64Size, szbase64)) {
        fprintf(g_logFile, "constructCert: cant transform sigto base64\n");
        fRet= false;
        goto cleanup;
    }

#ifdef  TEST
    fprintf(g_logFile, "encode signature\n");
#endif
    // encode Signature
    szCert= formatCert(szSignedInfo, szbase64);
    if(szCert==NULL) {
        fprintf(g_logFile, "constructCert: cant format Cert\n");
        fRet= false;
        goto cleanup;
    }

cleanup:
    if(szAlg!=NULL) {
        szAlg= NULL;
    }
    if(szNonce!=NULL) {
        szNonce= NULL;
    }
    if(fRet)
        return szCert;
    return NULL;
}


bool serversendCredentialtoclient(RSAKey* signingKey, safeChannel& fc, Request& oReq, sessionKeys& oKeys, 
                            int encType, byte* key, timer& accessTimer, timer& decTimer)
{
    bool        fError= false;
    //int         filesize= 0;
    // int         datasize= 0;
    byte        szBuf[MAXREQUESTSIZEWITHPAD];
    int         iLeft= MAXREQUESTSIZE;
    char*       p= (char*)szBuf;
    const char* szError= NULL;
    int         type= CHANNEL_RESPONSE;
    byte        multi= 0;
    byte        final= 0;
    char*       szCredential= NULL;

#ifdef  TEST
    fprintf(g_logFile, "serversendCredentialtoclient\n");
#endif
    // validate request (including access check) and get file location
    accessTimer.Start();
    // fError= !oReq.validateRequest(oKeys);
    accessTimer.Stop();

    if(!fError) {
        szCredential= constructCert(oReq, signingKey);
        if(szCredential==NULL) {
            fprintf(g_logFile, "serversendCredentialtoclient: can't construct proto cert\n");
            return false;
        }
    }

    // construct response
    if(!constructResponse(fError, &p, &iLeft, oReq.m_szCredentialType, szCredential, szError)) {
        fprintf(g_logFile, "serversendCredentialtoclient: constructResponse error\n");
        return false;
    }

    // send response
    fc.safesendPacket(szBuf, (int)strlen(reinterpret_cast<char*>(szBuf))+1, type, multi, final);

    // if we sent an error to the client, then return false
    if (fError) 
        return false;

#ifdef  TEST
    fprintf(g_logFile, "serversendCredentialtoclient returns true\n");
#endif
    return true;
}


// ---------------------------------------------------------------------------------


