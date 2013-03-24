//
//  File: authNegoServer.h
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


//----------------------------------------------------------------------


#ifndef _AUTHNEGOSERVER__H
#define _AUTHNEGOSERVER__H

#include "objectManager.h"


class asIssuedEntry {
public:
    char*	m_szPolicyIdName;
    char*	m_szPolicyId;
    char*	m_szAuthorizedProgramName;
    char*	m_szAuthortizedCodeDigest;
    char*	m_szCertasIssued;
    char*	m_szAttestAnchor;
    char*	m_szDate;
    char*	m_szNotBefore;
    char*	m_szNotAfter;
    char*	m_szRevocation;

		asIssuedEntry();
		~asIssuedEntry();

    int         auxSize();
    int         Serialize(byte* szObj);
    bool        Deserialize(const byte* szObj, int* pi);
};


class policyEntry {
public:
    char*	m_szPolicyIdName;
    char*	m_szPolicyId;
    char*	m_szAuthorizedProgramName;
    char*	m_szAuthortizedCodeDigest;
    char*	m_szCert;
    char*	m_szAttestAnchor;
    char*	m_szDate;
    char*	m_szNotBefore;
    char*	m_szNotAfter;
    char*	m_szRevocation;

		policyEntry();
		~policyEntry();

    int         auxSize();
    int         Serialize(byte* szObj);
    bool        Deserialize(byte* szObj, int* pi);
};


#endif


//-----------------------------------------------------------------------


