//
//  policyGlobals.h
//      John Manferdelli
//
//  Description: global values for policy 
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


// ------------------------------------------------------------------------


#ifndef _POLICYGLOBALS__H
#define _POLICYGLOBALS__H

#include "jlmTypes.h"
#include "keys.h"
#include "secPrincipal.h"


extern bool             g_globalpolicyValid;
// extern metaData	        g_theVault;
extern PrincipalCert*   g_policyPrincipalCert;
extern RSAKey*	    	g_policyKey;
extern accessPrincipal* g_policyAccessPrincipal;

#endif


// -----------------------------------------------------------------------


