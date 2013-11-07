//
//  File: tao.h
//      John Manferdelli
//  Description:  Tao of Trusted computing major classes
//
//  Copyright (c) 2012, John Manferdelli.  All rights reserved.
//      Some contributions (c) 2012, Intel Corporation
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
#include "sha256.h"
#include <time.h>

#include "linuxHostsupport.h"
#ifdef TPMSUPPORT
#include "TPMHostsupport.h"
#endif


// --------------------------------------------------------------------------


#ifndef _TAO__H
#define _TAO__H


#define PLATFORMTYPENONE                       0
#define PLATFORMTYPEHW                         1
#define PLATFORMTYPEHYPERVISOR                 2
#define PLATFORMTYPEKVMHYPERVISOR              3
#define PLATFORMTYPELINUX                      4
#define PLATFORMTYPEKVMHOSTEDLINUXGUESTOS      5
#define PLATFORMTYPEGUESTLINUX                 6
#define PLATFORMTYPELINUXAPP                   7
 
#define STORAGETYPENONE                        0
#define STORAGETYPETPM                         1
#define STORAGETYPEWRAPPEDTPM                  2
#define STORAGETYPESEALEDFILE                  3
#define STORAGETYPECLEARFILE                   4
#define STORAGETYPEENCRYPTEDFILE               5

#define EVIDENCENONE                           0
#define EVIDENCETPMATTEST                      1
#define EVIDENCECERT                           2
#define EVIDENCEFAKE                           3
#define EVIDENCEOSCERT                         4
#define EVIDENCECERTLIST                       5

#define KEYTYPENONE                            0
#define KEYTYPEAIKBLOB                         1
#define KEYTYPEHWPOLICY                        2
#define KEYTYPEAES128                          3
#define KEYTYPEAES128PAIREDENCRYPTINTEGRITY    4
#define KEYTYPEAES256                          5
#define KEYTYPEAES256PAIREDENCRYPTINTEGRITY    6
#define KEYTYPERSA1024INTERNALSTRUCT           7
#define KEYTYPERSA1024MODULUSONLY              8
#define KEYTYPERSA2048INTERNALSTRUCT           9
#define KEYTYPERSA2048MODULUSONLY             10
#define KEYTYPERSA2048TPMBLOB                 11
#define KEYTYPERSAINXMLCERT                   12
#define KEYTYPERSA1024SERIALIZED              13
#define KEYTYPERSA2048SERIALIZED              14

#define AES128BYTEBLOCKSIZE                   16
#define AES128BYTEKEYSIZE                     16

#define HASHTYPENONE                           0
#define HASHTYPETPM                            1
#define HASHTYPEJLMPROGRAM                     2
#define HASHTYPEHARDWARE              0xffffffff

#define QUOTETYPENONE                          0 
#define QUOTETYPETPM12RSA2048                  1
#define QUOTETYPETPM12RSA1024                  2 
#define QUOTETYPESHA256FILEHASHRSA1024         3
#define QUOTETYPESHA256FILEHASHRSA2048         4

#define STORAGEPROVIDERTYPENONE                0
#define STORAGEPROVIDERTYPEFILE                1
#define STORAGEPROVIDERTYPETPM                 2

#define MAXPROGRAMNAMESIZE                   128

#define MAXTPMSEALSIZE                       128
#define TPMSEALEDSIZE                        313

#define MAXHOSTNAMESIZE                      512
#define MAXSEALSIZE                         4096


//
//   Standard files
//
class taoFiles {
public:
    u32         m_storageType;
    char*       m_szdirectory;
    char*       m_szsymFile;
    char*       m_szprivateFile;
    char*       m_szcertFile;
    char*       m_szAncestorEvidence;

                taoFiles();
                ~taoFiles();

    bool        initNames(const char* directory, const char* subdirectory);
#ifdef TEST
    void        printAll();
#endif
    bool        getBlobData(const char* file, bool* pValid, int* pSize, byte** ppData);
    bool        putBlobData(const char* file, bool fValid, int size, byte* pData);

};


//
//  This is the object compiled in a hosted program implementing the CloudProxy
//      primitives.  This reorg from version 1 was suggested by the paper.
//
class taoHostServices {
private:
    u32         m_hostType;
    bool        m_hostValid;
    int         m_hostHandle;
    taoFiles    m_fileNames;

    bool        m_hostCertificateValid;
    u32         m_hostCertificateType;
    int         m_hostCertificateSize;
    byte*       m_hostCertificate;

    bool        m_hostEvidenceValid;
    u32         m_hostEvidenceType;
    int         m_hostEvidenceSize;
    byte*       m_hostEvidence;

    KeyInfo*    m_attestingPublicKey;
#ifdef TPMSUPPORT
    tpmSupport  m_oTpm;
#endif
    linuxDeviceChannel  m_linuxmyHostChannel;

public:
    // make this private later
    bool        Attest(int sizetoAttest, byte* toAttest, int* psizeAttested, 
                       byte* attested);

                taoHostServices();
                ~taoHostServices();

    bool        HostInit(u32 hostType, const char* hostProvider,
                         const char* directory, const char* subdirectory,
                         int nParameters, const char** rgszParameter);
    bool        HostClose();
    u32         hostType() {return m_hostType;};
    bool        isValid() {return m_hostValid;};
    bool        StartHostedProgram(int an, char** av, int* phandle);
    bool        GetHostedMeasurement(int* psize, u32* ptype, byte* buf);
    bool        GetEvidence(int* psize, byte** buf);
    bool        GetAttestCertificate(int* psize, u32* pType, byte** buf);
    bool        GetHostPolicyKey(int* psize, u32* pType, byte* buf);

    const char* GetCertificateString();
    const char* GetEvidenceString();

    bool        GetEntropy(int size, byte* buf);
    bool        Seal(int sizetoSeal, byte* toSeal, int* psizeSealed, byte* sealed);
    bool        Unseal(int sizeSealed, byte* sealed, int *psizetoSeal, byte* toSeal);
    const char* makeAttestation(int sizetoAttest, byte* toAttest, const char* hint);

#ifdef TEST
    void        printData();
#endif
};


//
//  This object implements the Tao Environment
//       This reorg from version 1 was suggested by the paper.
//
class taoEnvironment {

private:
    u32                 m_envType;
    bool                m_envValid;

    taoHostServices*    m_myHost;

    char*               m_program;
    char*               m_domain;
    char*               m_machine;

    bool                m_sealedsymKeyValid;
    int                 m_sealedsymKeySize;
    byte*               m_sealedsymKey;

    bool                m_sealedprivateKeyValid;
    int                 m_sealedprivateKeySize;
    byte*               m_sealedprivateKey;

    bool                m_symKeyValid;
    u32                 m_symKeyType;
    int                 m_symKeySize;
    byte*               m_symKey;

    int                 m_serializedpublicKeySize;
    char*               m_serializedpublicKey;
    int                 m_publicKeyBlockSize;

    u32                 m_serializedprivateKeyType;
    int                 m_serializedprivateKeySize;
    char*               m_serializedprivateKey;

    char*               m_szPrivateKeyName;
    char*               m_szPrivateSubjectName;
    char*               m_szPrivateSubjectId;

public:                 // make these private eventually
    bool                m_myMeasurementValid;
    u32                 m_myMeasurementType;
    int                 m_myMeasurementSize;
    byte*               m_myMeasurement;

    bool                m_policyCertValid;
    u32                 m_policyCertType;
    int                 m_sizepolicyCert;
    char*               m_szpolicyCert;

    bool                m_privateKeyValid;
    u32                 m_privateKeyType;
    int                 m_privateKeySize;
    byte*               m_privateKey;

    bool                m_publicKeyValid;
    int                 m_publicKeySize;
    RSAKey*             m_publicKey;

    bool                m_myCertificateValid;
    u32                 m_myCertificateType;
    int                 m_myCertificateSize;
    char*               m_myCertificate;

    bool                m_evidenceValid;
    int                 m_evidenceSize;
    char*               m_szevidence;

public:
    linuxDeviceChannel  m_linuxEnvChannel;
    taoFiles            m_fileNames;

public:
                        taoEnvironment();
                        ~taoEnvironment();

    bool                firstRun();

    bool                EnvInit(u32 type, const char* program, const char* domain,
                             const char* directory, const char* subdirectory,
                             taoHostServices* host, const char* serviceProvider, 
                             int nArgs, char** rgszParameter);
    bool                EnvClose();
    u32                 envType() {return m_envType;};
    bool                isValid() {return m_envValid;};

    bool                InitMyMeasurement();
    bool                GetMyMeasurement(int* psize, u32* ptype, byte* buf);
    bool                GetHostedMeasurement(int handle, int* psize, u32* ptype, 
                                             byte* buf);
    bool                StartHostedProgram(const char* name, int nArgs, char** av, 
                                           int* phandle);

    const char*         GetCertificateString();
    const char*         GetEvidenceString();


    bool                GetPolicyKey();
    bool                GetEntropy(int size, byte* buf);
    bool                Seal(int hostedMeasurementSize, byte* hostedMeasurement,
                            int sizetoSeal, byte* toSeal, int* psizeSealed, byte* sealed);
    bool                Unseal(int hostedMeasurementSize, byte* hostedMeasurement,
                            int sizeSealed, byte* sealed, int *psizetoSeal, byte* toSeal);
    bool                Attest(int hostedMeasurementSize, byte* hostedMeasurement,
                            int sizetoSeal, byte* toSeal, int* psizeSealed, byte* sealed);

    bool                initKeyNames();
    bool                initTao(u32 symType, u32 pubkeyType);
    bool                restoreTao();
    bool                saveTao();

private:
    bool                clearKey(u32* ptype, int* psize, byte** ppkey);

    bool                hostsealKey(u32 type, int size, byte* key, 
                                    int* psealedSize, byte** ppsealed);
    bool                hostunsealKey(int sealedSize, byte* psealed,
                                    u32* ptype, int* psize, byte** ppkey);
    bool                localsealKey(u32 type, int size, byte* key, 
                                    int* psealedSize, byte** ppsealed);
    bool                localunsealKey(int sealedSize, byte* psealed,
                                    u32* ptype, int* psize, byte** ppkey);
public:
#ifdef TEST
    void                printData();
#endif
};


//
//  This is the object initializes keys and interacts with keyNegoServer
//       This reorg from version 1 was suggested by the paper.
//
class taoInit {
public:
    taoHostServices*    m_myHost;

    bool                m_symKeyValid;
    u32                 m_symKeyType;
    int                 m_symKeySize;
    byte*               m_symKey;

    bool                m_privateKeyValid;
    u32                 m_privateKeyType;
    int                 m_privateKeySize;
    byte*               m_privateKey;

    int                 m_sizeserializedPrivateKey;
    char*               m_szserializedPrivateKey;

    bool                m_publicKeyValid;
    int                 m_publicKeySize;
    RSAKey*             m_publicKey;

    int                 m_serializedpublicKeySize;
    char*               m_serializedpublicKey;
    int                 m_publicKeyBlockSize;

    bool                m_myMeasurementValid;
    u32                 m_myMeasurementType;
    int                 m_myMeasurementSize;
    byte                m_myMeasurement[32];

    bool                m_myCertificateValid;
    u32                 m_myCertificateType;
    int                 m_myCertificateSize;
    char*               m_myCertificate;

    bool                m_evidenceValid;
    int                 m_evidenceSize;
    char*               m_szevidence;

                        taoInit(taoHostServices* host);
                        ~taoInit();

    bool                gensymKey(u32 symType);
    bool                genprivateKeyPair(u32 type, const char* szKeyName);
    bool                generateandcertifyKey(u32 keyType, const char* szKeyName, 
                                const char* szSubjectName, const char* szSubjectId);
    bool                initKeys(u32 symType, u32 pubkeyType, const char* szKeyName, 
                                const char* szSubjectName, const char* szSubjectId);
};


#include "attest.h"
#include "cert.h"
#include "validateEvidence.h"

#define NOATTESTATION     0
#define CPXMLATTESTATION  1


//
//  This is the object does Attest/Quote verification
//
class taoAttest {
private:
    u32             m_attestType;
    PrincipalCert*  m_pattestingCert;
    RSAKey*         m_pattestingKey;
    RSAKey*         m_policyKey;
    evidenceList    m_oEvidence;
    char*           m_sznonce;
    char*           m_szAttestAlg;
    Attestation     m_oAttestation;
    char*           m_szdigest;

public:
                    taoAttest();
                    ~taoAttest();

    bool            bytecodeDigest(byte* out, int* psizeout);
    char*           codeDigest();
    u32             attestType();
    char*           attestAlg();

    int             attestCodeDigestSize(){return 128;};
    int             sizeAttestedValue();

    bool            init(const char *attestation, const char* attestEvidence, 
                         KeyInfo* policyKey);
    bool            verifyAttestation(int* psizeattestValue, byte* attestValue,
                                      const char** pdigestalg, int* sizeCodeDigest, 
                                      byte* codeDigest, const char** phint);
};


#endif


// --------------------------------------------------------------------------


