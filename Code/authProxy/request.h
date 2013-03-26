//
//  request.h
//      John Manferdelli
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


// -----------------------------------------------------------------------------


#ifndef _REQUEST__H
#define _REQUEST__H

#include "jlmTypes.h"
#include "jlmUtility.h"
#include "keys.h"
#include "session.h"
#include "secPrincipal.h"
#include "objectManager.h"
#include "channel.h"
#include "safeChannel.h"
#include "credential.h"
#include "timer.h"
#include "policyglobals.h"


#define GETTOKEN         1

#define ACCEPT         100
#define REJECT         200


/*
 *  <Request>
 *      <Action> 
 *          getToken
 *      </Action>
 *      <CredentialType> </CredentialType>
 *      <EvidenceCollection count='2'>
 *          <EvidenceList count='1'>
 *          </EvidenceList>
 *      </EvidenceCollection>
 *      <PublicKey> </PublicKey>
 *  </Request>
 *
 *  <Response>
 *      <Action> accept, reject</Action>
 *      <ErrorCode> </ErrorCode>
 *      <CredentialType> </CredentialType>
 *      <Token> </Token>
 *  </Response>
 */


class accessGuard;


class Request {
public:
    int             m_iRequestType;
    char*           m_szAction;
    char*           m_szCredentialType;
    char*           m_szPublicKey;
    char*           m_szSubjectName;  //user
    char*           m_szEvidence;


    accessGuard*    m_poAG;

                    Request();
                    ~Request();
    bool            getDatafromDoc(const char* szRequest);
    bool            validateCredentialRequest(sessionKeys& oKeys, char* szCredType,
                            char* szSubject, char* szEvidence);
#ifdef TEST
    void        printMe();
#endif
};


class Response {
public:
    int             m_iRequestType;
    char*           m_szAction;
    char*           m_szErrorCode;
    char*           m_szCredentialType;
    char*           m_szToken;
    char*           m_szEvidence;

                    Response();
                    ~Response();
    bool            getDatafromDoc(char* szResponse);
#ifdef TEST
    void            printMe();
#endif
};


class accessGuard {
public:
    bool  permitAccess(Request& req, char*sz);
};


bool clientgetCredentialfromserver(safeChannel& fc, const char* szAction, const char* szSubjectName, 
                    const char* szCredentialType, const char* szIdentityCert, const char* szEvidence, 
                    const char* szKeyinfo, const char* szOutFile, int encType, byte* key, timer& encTimer);

bool serversendCredentialtoclient(RSAKey* signingKey, safeChannel& fc, Request& oReq, sessionKeys& oKeys, 
                                int encType, byte* key, timer& accessTimer, timer& decTimer);

bool initAccessGuard(sessionKeys& oKeys);

#ifdef TEST
void printKeys();
#endif

#endif


// -----------------------------------------------------------------------------------------


