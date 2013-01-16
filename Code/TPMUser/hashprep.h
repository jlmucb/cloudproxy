//
//  File: hashprep.h - hash prep for TPM
//
//
//  Copyright (c) 2012 John Manferdelli.  All rights reserved.
//    Some contributions (c) 2012, Intel Corporation
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



// --------------------------------------------------------------------------

#ifndef _HASHPREP_H__
#define _HASHPREP_H__

#include "jlmTypes.h"


//
//  The following structure mirror TPM structures
//
//  Quote signs the SHA-1 hash of a composite structure, called TPM12QUOTEINFO.
//  It is constructed as follows:
//      1. The data to be quoted is first hashed with SHA-1, this is
//         called hashofQuotedData, below.
//      2. Next, a "composite hash" containing the values of the PCR's
//         to be quoted along with other information is hashed.  The
//         resulting hash is called pcrcompositeDigest.  The input
//         to the SHA-1 invocation, producing pcrcompositeDigest, is:
//          (a) A 2 byte value representing the number of bytes in the 
//                PCR map.  Since TPM 1.2 has 24 PCRs this is always 3
//                in bigEndian format (0x0300).
//          (b) The size of the buffer containing the PCR's included.  For
//              example, if only PCR17 is included, this is 20.
//          (c) The pcrMap.  Each bit position represents a PCR.  If only
//              PCR 17 is included, the map is byte[3]={0x00, 0x00, 0x02}.
//              If PCR 17 and 18 are included, the map is 
//              byte[3]={0x00, 0x00, 0x06}.
//          (d) The 20 byte values of the PCR's included, in ascending order.
//      3. TPM12QUOTEINFO consists of a four byte version, which is 1.1.0.0,
//         a fixed four byte string consisting of "QUOT", the (20 byte)
//         pcrcompositeDigest, and the 20 byte hashofQuotedData
//
//  Quote2 works almost the same way with slightly modified structures (see below).


struct TPM12COMPOSITEPCR {
    u16     m_sizeMap;
    byte    m_rgpcrMap[3];
    u32     m_sizeDigests;
    byte    m_rgPCRs[20*24];
};


struct TPM12QUOTEINFO {
    u32                 m_version;                  // 1.1.0.0
    byte                m_rgFixed[4];               // 'Q', 'U', 'O', 'T'
    byte                m_pcrcompositeDigest[20];
    byte                m_hashofQuotedData[20];
};


struct TPM12INFO2COMPOSITE {
    u16     m_sizeSelect;
    u32     m_sizeValue;
    byte    m_releaseLocality;
    byte    m_rgreleaseDigest[20];
    
};


struct TPM12QUOTE2INFO {
    u16                 m_tagValue;
    byte                m_rgFixed[4];               // 'Q', 'U', 'T', '2'
    byte                m_hashofQuotedData[20];
    TPM12INFO2COMPOSITE m_pcrComposite;
};


#define TPM12QUOTE2INFOTAG  0x0036


//  TPM1.2 Quote
bool computeTPM12compositepcrDigest(byte pcrMask[3], byte* pcrs, byte* pcrDigest);
bool tpm12quoteHash(int sizenonce, byte* nonce, 
                    int sizetobeSignedHash, byte* tobesignedHash,
                    int sizepcrDigest, byte* pcrDigest, byte* outputHash);


//  TPM1.2 Quote2
bool computeTPM12quote2compositepcrDigest(byte pcrMask[3], byte* pcrs, 
                                      byte locality, byte* pcrComposite);
bool tpm12quote2Hash(int sizenonce, byte* nonce, byte pcrMask[3], 
                     byte locality, int sizetobeSignedHash, byte* tobesignedHash,
                     int sizepcrComposite, byte* pcrComposite, bool addVer,
                     u32 sizeversion, byte* versionInfo, byte* outputHash);

// JLM quote
bool sha256quoteHash(int sizenonce, byte* nonce,
                     int sizetobeSignedHash, byte* tobesignedHash,
                     int sizedigest, byte* digest, byte* outputHash);


extern byte g_pcr17Mask[3];
extern byte g_pcr1718Mask[3];
#endif


// --------------------------------------------------------------------------


