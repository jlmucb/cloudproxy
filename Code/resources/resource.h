//
//  resource.h
//      John Manferdelli
//
//  Description: resource classes
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


// ------------------------------------------------------------------------------


#ifndef _RESOURCE__H
#define _RESOURCE__H


#include "jlmTypes.h"
#include "jlmUtility.h"
#include "keys.h"
#include "secPrincipal.h"
#include "objectManager.h"


// uTypes
#define RESOURCENONE        0
#define RESOURCEFILE        1
#define RESOURCEDIRECTORY   2


class resource {
public:
    char*                   m_szResourceName;
    char*                   m_szLocation;
    u16                     m_uType;
    bool                    m_fIsPresent;
    bool                    m_fIsDeleted;
    int                     m_iSize;
    aList<accessPrincipal>  m_myOwners;
    byte                    m_rguKey1[SMALLSYMKEYSIZE];

    resource();
    ~resource();

#ifdef TEST
    void                    printMe();
#endif
    bool                    addOwner(accessPrincipal* pPrincipal);
    bool                    removeOwner(accessPrincipal* pPrincipal);
    aNode<accessPrincipal>* getFirstOwnerNode();
    aNode<accessPrincipal>* getNextOwnerNode(aNode<accessPrincipal>* pNode);
    bool                    getDatafromDoc();
    int                     getSize();
    char*                   getName();
    int                     auxSize();
    int                     Serialize(byte* szObj);
    bool                    Deserialize(byte* szObj, int* pi);

    bool                    MakeOwnerList(int* pnOwners, accessPrincipal*** ppaccessPrincipals,
                                          objectManager<accessPrincipal>* pPp);
};


#endif


// -------------------------------------------------------------------------


