//  File: newTPMHostsupport.h
//      John Manferdelli
//  Description:  TPM interface for trusted services
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


// -------------------------------------------------------------------------


#ifndef _TPMHOSTSUPPORT__H
#define _TPMHOSTSUPPORT__H

#include "jlmTypes.h"
#include "vTCIDirect.h"

class  tpmSupport {
    bool        m_fInitialized;
    tpmStatus   m_oTpm;
public:

                tpmSupport();
                ~tpmSupport();

    bool        initTPM(const char* deviceName, const char* aikblobfile, 
                        const char* szTPMPassword);
    bool        deinitTPM();
    bool        getAttestCertificateTPM(int size, byte* pKey);
    bool        getEntropyTPM(int size, byte* pKey);
    bool        getMeasurementTPM(int* pSize, byte* pHash);
    bool        sealwithTPM(int inSize, byte* inData, int* poutSize, byte* outData);
    bool        unsealwithTPM(int inSize, byte* inData, int* poutSize, byte* outData);
    bool        quotewithTPM(int inSize, byte* inData, int* poutSize, byte* outData);
};

#endif


// -------------------------------------------------------------------------


