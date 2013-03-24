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
#include "accessControl.h"
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
 *          getCredential
 *      </Action>
 *      <EvidenceCollection count='2'>
 *          <EvidenceList count='1'>
 *          </EvidenceList>
 *      </EvidenceCollection>
 *      <CredentialName> </CredentialName>
 *      <CredentialLength> </CredentialLength>
 *  </Request>
 *
 *  <Response>
 *      <Action> accept, reject</Action>
 *      <ErrorCode> </ErrorCode>
 *      <CredentialName> </CredentialName>
 *      <CredentialLength> </CredentialLength>
 *  </Response>
 */


class accessGuard;


class Request {
public:
    int             m_iRequestType;
    char*           m_szAction;
    char*           m_szCredentialName;
    int             m_iCredentialLength;
    int             m_iCredentialType;
    char*           m_szEvidence;
    char*           m_szSubjectName;

    accessGuard*    m_poAG;

                Request();
                ~Request();
    bool        getDatafromDoc(const char* szRequest);
    bool        validateCredentialRequest(sessionKeys& oKeys, char** pszFile, 
                        credential** ppCredential);
    bool        validateRequest(sessionKeys& oKeys, char** pszFile, 
                        credential** ppCredential);
#ifdef TEST
    void        printMe();
#endif
};


class Response {
public:
    int             m_iRequestType;
    char*           m_szAction;
    char*           m_szErrorCode;
    char*           m_szCredentialName;
    char*           m_szEvidence;
    int             m_iCredentialLength;

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



bool clientgetCredentialfromserver(safeChannel& fc, const char* szCredentialName, const char* szEvidence, 
                                 const char* szFile, int encType, byte* key, timer& encTimer);

bool serversendCredentialtoclient(safeChannel& fc, Request& oReq, sessionKeys& oKeys, 
                                int encType, byte* key, timer& accessTimer, timer& decTimer);

bool initAccessGuard(sessionKeys& oKeys);

#ifdef TEST
void printPrincipals();
void printCredentials();
void printKeys();
#endif
#endif


// -----------------------------------------------------------------------------------------


