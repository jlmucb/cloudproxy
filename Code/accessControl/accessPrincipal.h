//
//  accessPrincipal.h
//      John Manferdelli
//
//  Description: Access Principal classes
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


#include "jlmTypes.h"
#include "keys.h"
#include "tinyxml.h"
#include <time.h>


// ---------------------------------------------------------------------


#ifndef _ACCESSPRINCIPAL__H
#define _ACCESSPRINCIPAL__H


#define  NOPRINCIPAL        0
#define  COMPOUNDPRINCIPAL  1
#define  CODEPRINCIPAL      2
#define  USERPRINCIPAL      3
#define  MACHINEPRINCIPAL   4
#define  CHANNELPRINCIPAL   5
#define  POLICYPRINCIPAL    6


class accessPrincipal {
public:
    char*               m_szPrincipalName;
    u32                 m_uPrincipalType; 
    bool                m_fValidated;
    PrincipalCert*      m_pCert;

    accessPrincipal();
    ~accessPrincipal();
    void                printMe();
    char*               getName();
    int                 auxSize();
    bool                Deserialize(const byte* szObj, int* pi);
    int                 Serialize(byte* sz);
};


accessPrincipal* principalFromCert(PrincipalCert* pCert, bool fValidated);


#endif


// ----------------------------------------------------------------------------


