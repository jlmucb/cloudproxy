//  File: kvmHostsupport.h
//      John Manferdelli
//  Description:  Support for kvm host
//
//  Copyright (c) 2012, John Manferdelli
//  Some contributions copyright (c) 2012, Intel Corporation
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
#include "tcIO.h"
#include "buffercoding.h"
#include <string.h>
#include <time.h>
#include "tcService.h"



#ifndef _KVMHOSTSUPPORT__H
#define _KVMHOSTSUPPORT__H


int startKvmVM(const char* szvmimage, const char* systemname,
                const char* xmldomainstring, const char* szdomainName,
                tcServiceInterface* ptc);
#endif


// -------------------------------------------------------------------------


