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
// #include "accessControl.h"
#include "resource.h"
#include "channel.h"
#include "safeChannel.h"
#include "timer.h"


#define CREATERESOURCE   1
#define DELETERESOURCE   2
#define SENDRESOURCE     3 
#define GETRESOURCE      4
#define ADDOWNER         5
#define REMOVEOWNER      6
#define GETOWNER         7
#define ADDPRINCIPAL     8
#define REMOVEPRINCIPAL  9

#define ACCEPT         100
#define REJECT         200


/*
 *  <Request>
 *      <Action> 
 *      createResource, getResource, sendResource, deleteResource, 
 *      addOwner, removeOwner, addPrincipal, removePrincpal
 *      </Action>
 *      <EvidenceCollection count='2'>
 *          <EvidenceList count='1'>
 *          </EvidenceList>
 *      </EvidenceCollection>
 *      <ResourceName> </ResourceName>
 *      <ResourceLength> </ResourceLength>
 *  </Request>
 *
 *  <Response>
 *      <Action> accept, reject</Action>
 *      <ErrorCode> </ErrorCode>
 *      <ResoureName> </ResoureName>
 *      <ResoureLength> </ResoureLength>
 *  </Response>
 */


class Request {
public:
    int             m_iRequestType;
    char*           m_szAction;
    char*           m_szResourceName;
    int             m_iResourceLength;
    int             m_iResourceType;
    char*           m_szEvidence;
    char*           m_szSubjectName;

                Request();
                ~Request();
    bool        getDatafromDoc(const char* szRequest);
#ifdef TEST
    void        printMe();
#endif
};


class Response {
public:
    int             m_iRequestType;
    char*           m_szAction;
    char*           m_szErrorCode;
    char*           m_szResourceName;
    char*           m_szEvidence;
    int             m_iResourceLength;

                    Response();
                    ~Response();
    bool            getDatafromDoc(char* szResponse);
#ifdef TEST
    void            printMe();
#endif
};

#endif


// -----------------------------------------------------------------------------------------


