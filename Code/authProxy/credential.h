//
//  File: credential.h
//      John Manferdelli
//
//  Description: Symbol and class definitions for authClient
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


//------------------------------------------------------------------------------------


#ifndef _CREDENTIAL__H
#define _CREDENTIAL__H


#include "channel.h"
#include "safeChannel.h"
#include "session.h"
#include "objectManager.h"
#include "secPrincipal.h"
#include "tao.h"
#include "timer.h"

#include <string>
using std::string;

class credential {
public:
    int                 m_clientState;
    int                 m_iSize;
    char*               m_szLocation;

    credential();
    ~credential();

    void    printMe();
    void    printTimers(FILE* log);
    void    resetTimers();
};


#endif


//-------------------------------------------------------------------------------


