//
//      File: vTCIDirect.h - virtual Trusted Computing Interface
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

#ifndef _VTCIDIRECT_H__
#define _VTCIDIRECT_H__

#include "jlmTypes.h"

#define VTCISUCCESS             0
#define VTCIERRORBUFFTOOSMALL   1
#define VTCIUNAUTHORIZED        2
#define VTCIFUNCTIONFAILED      3


#define TPM_TAG_RQU_COMMAND             0x00C1
#define TPM_TAG_RQU_AUTH1_COMMAND       0x00C2
#define TPM_TAG_RQU_AUTH2_COMMAND       0x00C3
#define TPM_ORD_PCR_EXTEND          0x00000014
#define TPM_ORD_PCR_READ            0x00000015
#define TPM_ORD_PCR_RESET           0x000000C8
#define TPM_ORD_NV_READ_VALUE       0x000000CF
#define TPM_ORD_NV_WRITE_VALUE      0x000000CD
#define TPM_ORD_GET_CAPABILITY      0x00000065
#define TPM_ORD_SEAL                0x00000017
#define TPM_ORD_UNSEAL              0x00000018
#define TPM_ORD_OSAP                0x0000000B
#define TPM_ORD_OIAP                0x0000000A
#define TPM_ORD_SAVE_STATE          0x00000098
#define TPM_ORD_QUOTE2              0x0000003E
#define TPM_ORD_GET_RANDOM          0x00000046
#define TPM_ORD_LOADKEY2            0x00000041
#define TPM_ORD_TERMINATEHANDLE     0x00000096
#define TPM_ORD_GETPUBKEY           0x00000021

#define TPM_ET_KEYHANDLE                0x0001
#define TPM_ET_SRK                      0x0004
#define TPM_ET_KEY                      0x0005
#define TPM_KH_SRK                  0x40000000

#define KEYTYPE_SRK                          1
#define KEYTYPE_AIK                          2

#define MAXPCRS       24
#define TPMMAXBUF   4096


class tpmStatus {
public:
    bool            m_fTPMInitialized;
    int             m_tpmfd;

    bool            m_fSealKeyValid;
    u32             m_hSealKey;
    bool            m_fQuoteKeyValid;
    u32             m_hQuoteKey;

    bool            m_fpcrSelectionValid;
    int             m_npcrs;
    byte            m_rgpcrMask[3];
    bool            m_rgpcrSValid;
    byte            m_rgpcrS[20*MAXPCRS];


    bool            m_fSRKAuthSet;
    char*           m_szSRKSecret;
    byte            m_rgSRKAuth[20];

    bool            m_fTPMAuthSet;
    char*           m_szTPMSecret;
    byte            m_rgTPMAuth[20];

    byte            m_locality;

    bool            m_fEKKeyValid;
    int             m_iEkmodulusLen; 
    byte            m_rgekmodulus[256];

    bool            m_faikKeyValid;
    int             m_iaikmodulusLen; 
    byte            m_rgaikmodulus[256];

    char*           m_rgEKCert;
    char*           m_rgAIKCert;

    tpmStatus();
    ~tpmStatus();

    bool initTPM();

    bool setSRKauth(char* srkSecret);
    bool setTPMauth(char* ownerSecret);

    int  getRandom(int size, byte* puData);

    bool getPCRValue(int pcr, int* pSize, byte* buf);
    bool setPCRValue(int pcr, int size, byte* buf);

    bool selectPCRCompositeIndex(byte* pM);
    bool getCompositePCR(u32 loc, byte* pM, unsigned* pSize, byte* buf);
    bool loadKey(u32 keytype, byte* buf, int size, u32* ph);


    bool getLocality(unsigned* pOut);
    bool setLocality(u32 in);

    bool sealData(unsigned toSealSize, byte* toSealData, 
                  unsigned* pSealedSize, byte* pSealed);
    bool unsealData(unsigned unsealedSize, byte* unsealedData, 
                    unsigned* punSealedSize, byte* punSealed);
    bool quoteData(unsigned sizequoteData, byte* toquoteData,
                   unsigned* psigSize, byte* signature);

    bool makeAIK(int numCerts, byte** rgpCerts, char* pcaFile, 
                 char* reqFile, char* aikFile, char* aikPKFile);

    bool getAIKKey(char* aikBlobFile, char* aikCertFile);
    bool getEKInfo(char* fileName, bool fgetKey);

    bool verifyQuote(int dataSize, byte* signedData, byte pcsMask[3],
                     byte* ppcrs, byte locality, 
                     int externalSize, byte* pbExternal,
                     bool addVer, u32 sizeversion, byte* versionInfo);

    bool closeTPM();
};


#define TPM_SUCCESS              0
#define TPM_AUTHFAIL             1
#define TPM_BADINDEX             2
#define TPM_BAD_PARAMETER        3
#define TPM_AUDITFAILURE         4
#define TPM_CLEAR_DISABLED       5
#define TPM_DEACTIVATED          6
#define TPM_DISABLED             7
#define TPM_DISABLED_CMD         8
#define TPM_FAIL                 9
#define TPM_BAD_ORDINAL         10
#define TPM_INSTALL_DISABLED    11
#define TPM_INVALID_KEYHANDLE   12
#define TPM_KEYNOTFOUND         13
#define TPM_INAPPROPRIATE_ENC   14
#define TPM_MIGRATEFAIL         15
#define TPM_INVALID_PCR_INFO    16
#define TPM_NOSPACE             17
#define TPM_NOSRK               18
#define TPM_NOTSEALED_BLOB      19
#define TPM_OWNER_SET           20
#define TPM_RESOURCES           21
#define TPM_SHORTRANDOM         22
#define TPM_SIZE                23
#define TPM_WRONGPCRVAL         24
#define TPM_BAD_PARAM_SIZE      25
#define TPM_SHA_THREAD          26
#define TPM_SHA_ERROR           27
#define TPM_FAILEDSELFTEST      28
#define TPM_AUTH2FAIL           29
#define TPM_BADTAG              30
#define TPM_IOERROR             31
#define TPM_ENCRYPT_ERROR       32
#define TPM_DECRYPT_ERROR       33
#define TPM_INVALID_AUTHHANDLE  34
#define TPM_NO_ENDORSEMENT      35
#define TPM_INVALID_KEYUSAGE    36
#define TPM_WRONG_ENTITYTYPE    37
#define TPM_INVALID_POSTINIT    38
#define TPM_INAPPROPRIATE_SIG   39

#define TPM_TAG_PCR_INFO_LONG 0x06


typedef struct __attribute__ ((__packed__)) {
    u16     m_size;
    byte    m_mask[3];
} tpm_pcr_selection;


typedef struct __attribute__ ((__packed__)) {
    u16                 m_tag;
    byte                m_locatcreation;
    byte                m_locatrelease;
    tpm_pcr_selection   m_pcratcreation;
    tpm_pcr_selection   m_pcratrelease;
    byte                m_digestatcreation[20];
    byte                m_digestatrelease[20];
} tpm_pcrinfo_long;


typedef struct __attribute__ ((__packed__)) {
    tpm_pcr_selection   m_pcratrelease;
    byte                m_locatrelease;
    byte                m_digestatrelease[20];
} tpm_pcrinfo_short;


typedef struct __attribute__ ((__packed__)) {
    u32                 m_algid;
    u16                 m_encscheme;
    u16                 m_sigscheme;
    u32                 m_paramsize;
    byte                m_params[32];
} tpm_pubkeyparameters;


typedef struct __attribute__ ((__packed__)) {
    u32                 m_keylen;
    byte                m_key[256];
} tpm_pubkeystore;


typedef struct __attribute__ ((__packed__)) {
    tpm_pubkeyparameters        m_keyparams;
    tpm_pubkeystore             m_key;
} tpm_pubkey;


#endif 

// --------------------------------------------------------------------------


