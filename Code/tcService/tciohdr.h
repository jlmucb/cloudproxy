//
//  File: tciohdr.h
//  Description: tciohdr defines
//
//  Copyright (c) 2012, John Manferdelli.  All rights reserved.
//     Some contributions Copyright (c) 2012, Intel Corporation. 
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


#ifndef __TCIOHDR_H__
#define __TCIOHDR_H__

#include "jlmTypes.h"


struct tcBuffer {
    int                 m_procid;
    u32                 m_reqID;
    u32                 m_reqSize;
    u32                 m_ustatus;
    int                 m_origprocid;
};
typedef struct tcBuffer tcBuffer;


//  tcService - status values
#define TCIOSUCCESS             0
#define TCIOFAILED              1
#define TCIONOSERVICE           2
#define TCIONOMEM               3
#define TCIONOSERVICERESOURCE   4
#define TCIONOTPM               5


#endif


// ------------------------------------------------------------------------------


