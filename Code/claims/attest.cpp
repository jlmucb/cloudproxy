//
//  File: attest.cpp
//      John Manferdelli
//
//  Description:  Attestation 
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
#include "logging.h"
#include "jlmUtility.h"
#include "cryptoHelper.h"
#include "modesandpadding.h"
#include "sha1.h"
#include "sha256.h"
#include "algs.h"
#include "attest.h"
#include "cert.h"
#include "tao.h"
#include "bignum.h"
#include "mpFunctions.h"
#include "hashprep.h"
#include "tinyxml.h"

#include <time.h>
#include <string.h>


// ------------------------------------------------------------------------


const char* g_AttestTemplate=
"<Attest format=\"xml\" type=\"%s\">\n"\
"  <ds:CanonicalizationMethod Algorithm=\"http://www.manferdelli.com/2011/Xml/canonicalization/tinyxmlcanonical#\"/>\n"\
"%s"\
"  <AttestedValue>%s</AttestedValue>\n"\
"  <Attestation Algorithm=\"%s\">%s</Attestation>\n"\
"      %s\n"\
"  <InterpretationHint>\n"\
"%s\n"\
"  </InterpretationHint>\n"\
"</Attest>\n";


const char* g_sha256codeDigestTemplate=
"<CodeDigest Algorithm=\"%s\">%s</CodeDigest>\n";

const char* g_TpmcodeDigestTemplate=
"<CodeDigest Algorithm=\"%s\" locality=\"%d\" pcrMask= \"%d\">%s</CodeDigest>\n";


const char* g_AttestInfoTemplate=
"<attestInfo>\n"\
"%s"\
"</attestInfo>\n";
 

// ------------------------------------------------------------------


/*
 * 
 *  Attest
 * 
 *  <Attest format="xml" type="CP1">
 *    <ds:CanonicalizationMethod Algorithm="http://www.manferdelli.com/2011/Xml/canonicalization/tinyxmlcanonical#" />
 *    <ds:AttestMethod Algorithm="Attest-Sha256FileHash-RSA1024" />
 *    <CodeDigest alg="SHA256">al5/jR40s+ytNsx3SRTLE67oZV5bSl+EXNRrqI2gxKY=</CodeDigest>
 *    <AttestedValue>xxxx</AttestedValue>
 *    <Attestation Algorithm="Attest-Sha256FileHash-RSA1024">yyyyy</Attestation>
 *    <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#" KeyName="//www.manferdelli.com/jlmlinuxhp/Keys/TrustedOSAttest">
 *      <KeyType>RSAKeyType</KeyType>
 *        <ds:KeyValue>
 *          <ds:RSAKeyValue size="1024">
 *            <ds:M>rBdxn3Cd7a+X736tzMrIp6yCzfsF9gN+7NdoHYmRBtvy2zWRWtAbeyrxpzzbDyC7zwtZRxVCPem0NbszpP066v7Rw/SeSZvr0dWaBpzkatIhKpJHqRigcAl43RgSH0tSB6+/mEj11a/tTMUidTobi4ZEV1qPX+qauUr8dwM9kEs=</ds:M>
 *            <ds:E>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAE=</ds:E>
 *        </ds:RSAKeyValue>
 *      </ds:KeyValue>
 *    </ds:KeyInfo>
 *  
 *   <InterpretationHint>
 *  </InterpretationHint>
 *
 *</Attest>
 * 
 * 
 */

/*
 *  attestInfo for public key
 *
 *    <attestedInfo>
 *      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#" KeyName="//www.manferdelli.com/jlmlinuxhp/Keys/fileClientProgram">
 *        <KeyType>RSAKeyType</KeyType>
 *          <ds:KeyValue>
 *          <ds:RSAKeyValue size="1024">
 *            <ds:M>hGwM+FLbzGTrOhbz6iiKrIdgx+NptyUWHJAqNLUUtppsQcWcbX01pBam74muwqd9Cjc1MXgHLnmthqXtqJ3VLW75mcTAKqtJXlMO3Mb6BeewfFAHBKuVB9yf5qJyGIqLOQy2jGkoo66SSb40xuypcbsSc0acWdhTDL15wPETiT8=</ds:M>
 *            <ds:E>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAE=</ds:E>
 *          </ds:RSAKeyValue>
 *        </ds:KeyValue>
 *      </ds:KeyInfo>
 *    </attestedInfo>
 */


// ------------------------------------------------------------------


Attestation::Attestation()
{
    m_fValid= false;
    m_szAttestType= NULL;
    m_szAttestalg= NULL;
    m_szcodeDigest= NULL;
    m_szattestedValue= NULL;
    m_szattestation= NULL;
    m_szNonce= NULL;
    m_typeDigest= NULL;
    m_szCanonicalizationalg= NULL;
    m_szHint= NULL;
    m_sizecodeDigest= 0;
    m_codeDigest= NULL;
    m_sizeattestedTo= 0;
    m_attestedTo= NULL;
    m_sizeattestation= 0;
    m_attestation= NULL;
    m_szKeyInfo= NULL;

    m_pNodeAttest= NULL;
    m_pNodeNonce= NULL;
    m_pNodeCodeDigest= NULL;
    m_pNodeInterpretationHint= NULL;
    m_pNodeAttestedValue= NULL;
    m_pNodeAttestation= NULL;
    m_pNodeattestingKeyInfo= NULL;
    m_pNodeInterpretationHint= NULL;
    m_locality= 0x1f;
#ifdef PCR18
    m_pcrMask= 0x060000;
#else
    m_pcrMask= 0x020000;
#endif

}


Attestation::~Attestation()
{
    if(m_szAttestType!=NULL) {
        free(m_szAttestType);
        m_szAttestType= NULL;
    }
    if(m_szAttestalg!=NULL) {
        free(m_szAttestalg);
        m_szAttestalg= NULL;
    }
    if(m_szCanonicalizationalg!=NULL) {
        free(m_szCanonicalizationalg);
        m_szCanonicalizationalg= NULL;
    }
    if(m_szcodeDigest!=NULL) {
        free(m_szcodeDigest);
        m_szcodeDigest= NULL;
    }
    if(m_szattestedValue!=NULL) {
        free(m_szattestedValue);
        m_szattestedValue= NULL;
    }
    if(m_szattestation!=NULL) {
        free(m_szattestation);
        m_szattestation= NULL;
    }
    if(m_szNonce!=NULL) {
        free(m_szNonce);
        m_szNonce= NULL;
    }
    if(m_typeDigest!=NULL) {
        free(m_typeDigest);
        m_typeDigest= NULL;
    }
    if(m_szHint!=NULL) {
        free(m_szHint);
        m_szHint= NULL;
    }
    m_sizecodeDigest= 0;
    if(m_codeDigest!=NULL) {
        free(m_codeDigest);
        m_codeDigest= NULL;
    }
    m_sizeattestedTo= 0;
    if(m_attestedTo!=NULL) {
        free(m_attestedTo);
        m_attestedTo= NULL;
    }
    m_sizeattestation= 0;
    if(m_attestation!=NULL) {
        free(m_attestation);
        m_attestation= NULL;
    }
    if(m_szKeyInfo!=NULL) {
        free(m_szKeyInfo);
        m_szKeyInfo= NULL;
    }
}


bool Attestation::setTypeDigest(char const* szDigest)
{
    m_typeDigest= strdup(szDigest);
    return true;
}


bool Attestation::setLocality(int loc)
{
    m_locality= loc;
    return true; 
}


int  Attestation::getLocality()
{
    return m_locality;
}


bool Attestation::setpcrMask(u32 loc)
{
    m_pcrMask= loc;
    return true; 
}


u32  Attestation::getpcrMask()
{
    return m_pcrMask;
}


bool  Attestation::init(const char* attestation)
{
    TiXmlElement*   pRootElement= NULL;
    TiXmlNode*      pNode= NULL;
    TiXmlNode*      pNode1= NULL;
    const char*     szA= NULL;
    
#ifdef TEST
    fprintf(g_logFile, "Attestation::init()\n");
    fflush(g_logFile);
#endif
    if(attestation==NULL) {
        fprintf(g_logFile, "Attestation::init: attestation is null\n");
        return false;
    }
    
    if(!m_doc.Parse(attestation)) {
        fprintf(g_logFile, "Attestation::init: Can't parse attestation\n");
        return false;
    }   
    pRootElement= m_doc.RootElement();
    if(pRootElement==NULL) {
        fprintf(g_logFile, "Attestation::init: Can't get root of attest\n");
        return false;
    }

    m_pNodeAttest= Search((TiXmlNode*) pRootElement, "Attest");
    if(m_pNodeAttest==NULL) {
        fprintf(g_logFile, "Attestation::init: No Attest node\n");
        return false;
    }
    szA= ((TiXmlElement*)m_pNodeAttest)->Attribute ("type");
    if(szA==NULL) {
        fprintf(g_logFile, "Attestation::init: No type\n");
        return false;
    }
    m_szAttestType= strdup(szA);
    szA= NULL;

    pNode=  Search(m_pNodeAttest, "ds:CanonicalizationMethod");
    if(pNode==NULL) {
        fprintf(g_logFile, "Attestation::init: no CanonicalizationMethod node\n");
        return false;
    }
    szA= ((TiXmlElement*) pNode)->Attribute ("Algorithm");
    if(szA==NULL) {
        fprintf(g_logFile, "Attestation::init: No CanonicalizationMethod Algorithm\n");
        return false;
    }
    m_szCanonicalizationalg= strdup(szA);
    szA= NULL;

    pNode=  Search(m_pNodeAttest, "CodeDigest");
    if(pNode==NULL) {
        fprintf(g_logFile, "Attestation::init: No CodeDigest\n");
        return false;
    }
    szA= ((TiXmlElement*) pNode)->Attribute ("Algorithm");
    if(szA==NULL) {
        fprintf(g_logFile, "Attestation::init: No CodeDigest Algorithm\n");
        return false;
    }
    m_typeDigest= strdup(szA);
    if(strcmp(szA, "TPM12Digest")==0) {
        szA= ((TiXmlElement*) pNode)->Attribute ("locality");
        if(szA!=NULL) {
            m_locality= atoi(szA);
        }
        szA= ((TiXmlElement*) pNode)->Attribute ("pcrMask");
        if(szA!=NULL) {
            m_pcrMask= atoi(szA);
        }
    }
    pNode1= ((TiXmlElement*)pNode)->FirstChild();
    if(pNode1==NULL) {
        fprintf(g_logFile, "Attestation::init: No CodeDigest value\n");
        return false;
    }
    m_szcodeDigest= strdup(((TiXmlElement*)pNode1)->Value());
    szA= NULL;

    pNode=  Search(m_pNodeAttest, "AttestedValue");
    if(pNode==NULL) {
        fprintf(g_logFile, "Attestation::init: No AttestedValue\n");
        return false;
    }
    pNode1= ((TiXmlElement*)pNode)->FirstChild();
    if(pNode1==NULL) {
        fprintf(g_logFile, "Attestation::init: No Attestaton value\n");
        return false;
    }
    m_szattestedValue= strdup(((TiXmlElement*)pNode1)->Value());

    pNode=  Search(m_pNodeAttest, "Attestation");
    if(pNode==NULL) {
        fprintf(g_logFile, "Attestation::init: No Attestation\n");
        return false;
    }
    szA= ((TiXmlElement*) pNode)->Attribute ("Algorithm");
    if(szA==NULL) {
        fprintf(g_logFile, "Attestation::init: No Attestaton Algorithm\n");
        return false;
    }
    m_szAttestalg= strdup(szA);
    pNode1= ((TiXmlElement*)pNode)->FirstChild();
    if(pNode1==NULL) {
        fprintf(g_logFile, "Attestation::init: No Attestaton value\n");
        return false;
    }
    m_szattestation= strdup(((TiXmlElement*)pNode1)->Value());

    m_pNodeInterpretationHint= Search(m_pNodeAttest, "InterpretationHint");
    if(m_pNodeInterpretationHint!=NULL)
        m_szHint= canonicalize(m_pNodeInterpretationHint);

    m_fValid= true;
    return true;
}


bool Attestation::converttoBinary()
{
    int         size= 0;

    // char attestedTo
    if(m_attestedTo==NULL && m_szattestedValue!=NULL) {
        size= strlen(m_szattestedValue);
        m_attestedTo= (byte*) malloc(((size+8)*6)/8);
        if(m_attestedTo==NULL) {
            fprintf(g_logFile, "Attestation::converttoBinary: cant malloc in attestedto\n");
            return false;
        }
        if(!fromBase64(strlen(m_szattestedValue), m_szattestedValue, &size, m_attestedTo)) {
            fprintf(g_logFile, "Attestation::converttoBinary: cant convert attestedto to base64\n");
            return false;
        }
        m_sizeattestedTo= size;
    }

    // char codeDigest
    if(m_codeDigest==NULL && m_szcodeDigest!=NULL) {
        size= strlen(m_szcodeDigest);
        m_codeDigest= (byte*) malloc(((size+8)*6)/8);
        if(m_codeDigest==NULL) {
            fprintf(g_logFile, "Attestation::converttoBinary: cant malloc in code digest\n");
            return false;
        }
        if(!fromBase64(strlen(m_szcodeDigest), m_szcodeDigest, &size, m_codeDigest)) {
            fprintf(g_logFile, "Attestation::converttoBinary: cant convert code digest to base64\n");
            return false;
        }
        m_sizecodeDigest= size;
    }

    // char attestation
    if(m_attestation==NULL && m_szattestation!=NULL) {
        size= strlen(m_szattestation);
        m_attestation= (byte*) malloc(((size+8)*6)/8);
        if(m_attestation==NULL) {
            fprintf(g_logFile, "Attestation::converttoBinary: cant malloc in attestation\n");
            return false;
        }
        if(!fromBase64(strlen(m_szattestation), m_szattestation, &size, m_attestation)) {
            fprintf(g_logFile, "Attestation::converttoBinary: cant convert attestation to base64\n");
            return false;
        }
        m_sizeattestation= size;
    }
    return true;
}


const char* Attestation::getbase64codeDigest()
{
    if(m_szcodeDigest==NULL)
        return NULL;
    return strdup(m_szcodeDigest);
}


#define MAXATTESTDATACHAR 1024


bool Attestation::convertfromBinary()
{
    char        szBuf[MAXATTESTDATACHAR];
    int         size= 0;

    // char attestedTo
    if(m_sizeattestedTo>0 && m_attestedTo!=NULL && m_szattestedValue==NULL) {
        size= MAXATTESTDATACHAR;
        if(!toBase64(m_sizeattestedTo, m_attestedTo, &size, szBuf)) {
            fprintf(g_logFile, "Attestation::convertfromBinary: cant convert attestedto to base64\n");
            return false;
        }
        m_szattestedValue= strdup(szBuf);
    }

    // char codeDigest
    if(m_sizecodeDigest>0 && m_codeDigest!=NULL && m_szcodeDigest==NULL) {
        size= MAXATTESTDATACHAR;
        if(!toBase64(m_sizecodeDigest, m_codeDigest, &size, szBuf)) {
            fprintf(g_logFile, "Attestation::convertfromBinary:: cant convert code digest to base64\n");
            return false;
        }
        m_szcodeDigest= strdup(szBuf);
    }

    // char attestation
    if(m_sizeattestation>0 && m_attestation!=NULL && m_szattestation==NULL) {
        size= MAXATTESTDATACHAR;
        if(!toBase64(m_sizeattestation, m_attestation, &size, szBuf)) {
            fprintf(g_logFile, "Attestation::convertfromBinary:: cant convert attestation to base64\n");
            return false;
        }
        m_szattestation= strdup(szBuf);
    }
    return true;
}


const char* Attestation::getAttestAlg()
{
    if(m_szAttestalg==NULL)
        return NULL;
    return strdup(m_szAttestalg);
}


bool Attestation::setAttestAlg(const char* alg)
{
    if(alg==NULL)
        return false;
    m_szAttestalg= strdup(alg); 
    return true;
}


bool Attestation::setKeyInfo(const char* szKeyInfo)
{
    if(szKeyInfo==NULL)
        return false;
    m_szKeyInfo= strdup(szKeyInfo); 
    return true;
}


const char* Attestation::getAttestation()
{
    if(m_szattestation==NULL)
        return NULL;
    return strdup(m_szattestation);
}


const char* Attestation::getAttestedTo()
{
    if(m_szattestedValue==NULL)
        return NULL;
    return strdup(m_szattestedValue);
}


const char* Attestation::getNonce()
{
    if(m_szNonce==NULL)
        return NULL;
    return strdup(m_szNonce);
}


const char* Attestation::getattestingkeyInfo()
{
    if(m_pNodeattestingKeyInfo==NULL)
        return NULL;
    return canonicalize(m_pNodeattestingKeyInfo);
}


bool Attestation::setAttestedTo(int size, byte* attestedTo)
{
    if(size<=0 || attestedTo==NULL)
        return false;
    if(m_attestedTo!=NULL) {
        // free(m_attestedTo);
    }
    m_attestedTo= (byte*) malloc(size);
    if(m_attestedTo==NULL)
        return false;
    memcpy(m_attestedTo, attestedTo, size);
    m_sizeattestedTo= size; 
    return true;
}


bool Attestation::getAttestedTo(int* psize, byte* attestedTo)
{
    if(m_sizeattestedTo<=0 || m_attestedTo==NULL)
        return false;
    memcpy(attestedTo, m_attestedTo, m_sizeattestedTo);
    *psize= m_sizeattestedTo;
    return true;
}


bool Attestation::setAttestation(int size, byte* attestation)
{
    if(size<=0 || attestation==NULL)
        return false;
    if(m_attestation!=NULL) {
        // free(m_attestation);
    }
    m_attestation= (byte*) malloc(size);
    if(m_attestation==NULL)
        return false;
    memcpy(m_attestation, attestation, size);
    m_sizeattestation= size; 
    return true;
}


bool Attestation::getAttestation(int* psize, byte* attestation)
{
    if(m_sizeattestation<=0 || m_attestation==NULL)
        return false;
    memcpy(attestation, m_attestation, m_sizeattestation);
    *psize= m_sizeattestation;
    return true;
}


bool Attestation::setcodeDigest(int size, byte* codeDigest)
{
    if(size<=0 || codeDigest==NULL)
        return false;
    if(m_codeDigest!=NULL) {
        // free(m_codeDigest);
    }
    m_codeDigest= (byte*) malloc(size);
    if(m_codeDigest==NULL)
        return false;
    memcpy(m_codeDigest, codeDigest, size);
    m_sizecodeDigest= size; 
    return true;
}


bool Attestation::getcodeDigest(int* psize, byte* codeDigest)
{
    if(m_sizecodeDigest<=0 || m_codeDigest==NULL)
        return false;
    memcpy(codeDigest, m_codeDigest, m_sizecodeDigest);
    *psize= m_sizecodeDigest;
    return true;
}


bool Attestation::setHint(const char* hint)
{
    if(hint!=NULL)
        m_szHint= strdup(hint);
    else
        m_szHint= NULL;

    return true;
}


const char* Attestation::getHint()
{
    if(m_szHint==NULL)
        return NULL;
    return strdup(m_szHint);
}


#define MAXATTESTSIZE 8192
#define MAXDIGESTELEMENTSIZE 256


const char* Attestation::encodeAttest()
{
    char        szAttestation[MAXATTESTSIZE];
    char        szDigestElement[MAXDIGESTELEMENTSIZE];
    const char* szhint= "";
    int         size= 0;
    int         sizeD= 0;

    if(!convertfromBinary()) {
        fprintf(g_logFile, "Attestation::encodeAttest: no attestedTo\n");
        return false;
    }

    if(m_szHint!=NULL)
        szhint= m_szHint;

    // buffer big enough?
    if(m_szcodeDigest==NULL || m_szattestedValue==NULL || 
       m_szAttestalg==NULL || m_szattestation==NULL ) {
        fprintf(g_logFile, "Attestation::encodeAttest: missing value\n");
        return false;
    }
    if(m_typeDigest==NULL) {
        fprintf(g_logFile, "Attestation::encodeAttest: missing digest type\n");
        return false;
    }

    if(strcmp(m_typeDigest, "Sha256FileHash")==0) {
        sizeD= strlen(g_sha256codeDigestTemplate)+strlen(m_szcodeDigest)+16;
        if(sizeD>=MAXDIGESTELEMENTSIZE) {
            fprintf(g_logFile, "Attestation::encodeAttest: digest size too large\n");
            return false;
        }
        sprintf(szDigestElement, g_sha256codeDigestTemplate, 
                    "Sha256FileHash", m_szcodeDigest);
    }
    else if(strcmp(m_typeDigest, "TPM12Digest")==0) {
        sizeD= strlen(g_TpmcodeDigestTemplate)+strlen(m_szcodeDigest)+24;
        if(sizeD>=MAXDIGESTELEMENTSIZE) {
            fprintf(g_logFile, "Attestation::encodeAttest: digest size too large\n");
            return false;
        }
        sprintf(szDigestElement, g_TpmcodeDigestTemplate,
                    "TPM12Digest", m_locality, m_pcrMask, m_szcodeDigest);
    }
    else {
        fprintf(g_logFile, "Attestation::encodeAttest: unknown digest type\n");
        return false;
    }

    size= strlen(g_AttestTemplate)+strlen("CP1")+strlen(szDigestElement)+
          strlen(m_szattestedValue)+strlen(m_szAttestalg)+
          strlen(m_szattestation)+strlen(szhint);
    if((size+32)>MAXATTESTSIZE) {
        fprintf(g_logFile, "Attestation::encodeAttest: attestation too large\n");
        return false;
    }

    if(szhint==NULL)
        szhint= " ";

    sprintf(szAttestation, g_AttestTemplate, "CP1", szDigestElement,
            m_szattestedValue, m_szAttestalg, m_szattestation, m_szKeyInfo, szhint);
    return canonicalizeXML(szAttestation);
}


bool Attestation::checkAttest(KeyInfo* pKeyInfo)
{
    byte    hashFinal[SHA256DIGESTBYTESIZE];
    int     hashType= 0;
    int     sizefinalHash= 0;

    if(!isValid()) {
        fprintf(g_logFile, "checkAttest: Attestation not valid\n");
        return false;
    }
    if(m_szAttestalg==NULL) {
        fprintf(g_logFile, "checkAttest: empty alg\n");
        return false;
    }
    if(!converttoBinary()) {
        fprintf(g_logFile, "checkAttest: cant convert to binary values\n");
        return false;
    }

#ifdef TEST1
    fprintf(g_logFile, "checkAttest alg: %s\n", m_szAttestalg);
    PrintBytes("Code digest: ", m_codeDigest, m_sizecodeDigest);
    PrintBytes("Attested to: ", m_attestedTo, m_sizeattestedTo);
    PrintBytes("Attestation value: ", m_attestation, m_sizeattestation);
    ((RSAKey*)pKeyInfo)->printMe();
#endif

    if(strcmp(ATTESTMETHODTPM12RSA1024, m_szAttestalg)==0 
        || strcmp(ATTESTMETHODTPM12RSA2048, m_szAttestalg)==0) {
        hashType= SHA1HASH;
    }
    else if(strcmp(ATTESTMETHODSHA256FILEHASHRSA1024, m_szAttestalg)==0 
        || strcmp(ATTESTMETHODSHA256FILEHASHRSA2048, m_szAttestalg)==0) {
        hashType= SHA256HASH;
    }
    else {
        fprintf(g_logFile, "checkAttest: Unsupported attest algorithm %s\n", m_szAttestalg);
        return false;
    }

    // get nonce

    // generate final quote hash
    if(strcmp(ATTESTMETHODTPM12RSA2048, m_szAttestalg)==0 || 
        strcmp(ATTESTMETHODTPM12RSA1024, m_szAttestalg)==0) {
#ifdef NOQUOTE2
        if(!tpm12quoteHash(0, NULL, m_sizeattestedTo, m_attestedTo,
                           m_sizecodeDigest, m_codeDigest, hashFinal)) {
            fprintf(g_logFile, "checkAttest: Cant compute TPM12 hash\n");
            return false;
        }
#else
        byte    locality= 0; 
        u32     sizeversion= 0;
        byte*   versionInfo= NULL;

#ifdef PCR18
        byte pcrMask[3]= {0,0,0x6};  // pcr 17, 18
#else
        byte pcrMask[3]= {0,0,0x2};  // pcr 17
#endif

        // reconstruct PCR composite and composite hash
        if(!tpm12quote2Hash(0, NULL, pcrMask, locality,
                            m_sizeattestedTo, m_attestedTo,
                            m_sizecodeDigest, m_codeDigest,
                            false, sizeversion, versionInfo, 
                            hashFinal)) {
            fprintf(g_logFile, "checkAttest: Cant compute TPM12 hash\n");
            return false;
        }
#endif
        sizefinalHash= SHA1DIGESTBYTESIZE;
    }
    else if(strcmp(ATTESTMETHODSHA256FILEHASHRSA2048, m_szAttestalg)==0 || 
             strcmp(ATTESTMETHODSHA256FILEHASHRSA1024, m_szAttestalg)==0) {
        if(!sha256quoteHash(0, NULL, m_sizeattestedTo, m_attestedTo,
                           m_sizecodeDigest, m_codeDigest, hashFinal)) {
            fprintf(g_logFile, "checkAttest: Cant compute sha256 hash\n");
            return false;
        }
        sizefinalHash= SHA256DIGESTBYTESIZE;
    }
    else {
        fprintf(g_logFile, "checkAttest: Unsupported attest algorithm %s\n", m_szAttestalg);
        return false;
    }

    bool fRet= RSAVerify(*(RSAKey*)pKeyInfo, hashType, hashFinal,
                               m_attestation);

#ifdef TEST
    PrintBytes((char*)"final hash: ", hashFinal, sizefinalHash);
    if(fRet)
        fprintf(g_logFile, "checkAttest returns true\n");
    else
        fprintf(g_logFile, "checkAttest returns false\n");
    fflush(g_logFile);
#endif
    return fRet;
}




// ------------------------------------------------------------------


AttestInfo::AttestInfo()
{
    m_fValid= false;
    m_pNodeAttestInfo= NULL;
    m_sizeHash= 0;
    m_pKeyInfo= NULL;
    m_szHash= NULL;
}


AttestInfo::~AttestInfo()
{
    if(m_szHash!=NULL) {
        // free((void*)m_szHash);
        m_szHash= NULL;
    }
}


#define MAXATTESINFO 4096


const char* AttestInfo::makeKeyAttestInfo(const char* szSerializedKey)
{
    char   szAttestInfo[MAXATTESINFO];

    if(szSerializedKey==NULL) {
        fprintf(g_logFile, "AttestInfo::makeKeyAttestInfo: serialized ke is empty\n");
        return NULL;
    }
    if((strlen(szSerializedKey)+strlen(g_AttestInfoTemplate)+32)>MAXATTESINFO) {
        fprintf(g_logFile, "AttestInfo::makeKeyAttestInfo: attestInfo too large\n");
        return NULL;
    }
    sprintf(szAttestInfo, g_AttestInfoTemplate, szSerializedKey);
    return strdup(szAttestInfo);
}


bool  AttestInfo::init(const char* attestInfo)
{
    TiXmlElement*   pRootElement= NULL;

#ifdef TEST
    fprintf(g_logFile, "AttestInfo::init()\n");
#endif
    if(attestInfo==NULL)
        return false;

    if(!m_doc.Parse(attestInfo)) {
        fprintf(g_logFile, "AttestInfo::init: Can't parse attestInfo\n");
        return false;
    }
    pRootElement= m_doc.RootElement();
    if(pRootElement==NULL) {
        fprintf(g_logFile, "AttestInfo::init: Can't get root of attestInfo\n");
        return false;
    }

    m_pNodeAttestInfo= Search((TiXmlNode*) pRootElement, "attestInfo");
    if(m_pNodeAttestInfo==NULL) {
        fprintf(g_logFile, "AttestInfo::init: No attestInfo node\n");
        return false;
    }
    m_pKeyInfo= Search(m_pNodeAttestInfo, "ds:KeyInfo");
    if(m_pKeyInfo==NULL) {
        fprintf(g_logFile, "AttestInfo::init: No KeyInfo node\n");
        return false;
    }

    m_fValid= true;
    return true;
}


const char* AttestInfo::getSerializedKey()
{
    if(m_pKeyInfo==NULL)
        return NULL;
    return canonicalize(m_pKeyInfo);
}


const char* AttestInfo::getKeyName()
{
    const char*   szName= NULL;

    if(m_pKeyInfo==NULL) {
        return NULL;
    }
    szName= ((TiXmlElement*)m_pKeyInfo)->Attribute ("KeyName");
    if(szName==NULL) {
        fprintf(g_logFile, "AttestKeyInfo::getKeyName: no key name\n");
        return NULL;
    }
    return strdup(szName);
}


bool  AttestInfo::getAttestInfoHash(u32 type, int* psize, byte* hash)
{
    if(m_sizeHash>0) {
        if(*psize<m_sizeHash)
            return false;
        memcpy(hash, m_hash, m_sizeHash);
        *psize= m_sizeHash;
        return true; 
    }

    Sha1    oHashsha1;
    Sha256  oHashsha256;
    char    szBuf[2*GLOBALMAXDIGESTSIZE];
    int     size= 2*GLOBALMAXDIGESTSIZE;

    if(type!=SHA256HASH && type!=SHA1HASH) {
        fprintf(g_logFile, "AttestInfo::getAttestInfoHash: unsupported hash\n");
        return false;
    }
    m_hashType= type;
    const char* szCanonical= NULL;
    if(!m_fValid) {
        fprintf(g_logFile, "AttestInfo::getAttestInfoHash: not valid\n");
        return false;
    }
    if(m_pNodeAttestInfo==NULL) {
        fprintf(g_logFile, "AttestInfo::getAttestInfoHash: no attest info\n");
        return false;
    }
    szCanonical= canonicalize(m_pNodeAttestInfo);
    if(szCanonical==NULL) {
        fprintf(g_logFile, "AttestInfo::getAttestInfoHash: can't canonicalize\n");
        return false;
    }
    if(type==SHA256HASH) {
        if(*psize<oHashsha256.DIGESTSIZE) {
            fprintf(g_logFile, "AttestInfo::getAttestInfoHash: digest size too small\n");
            return false;
        }
        oHashsha256.Init();
        oHashsha256.Update((const byte*) szCanonical, strlen(szCanonical));
        oHashsha256.Final();
        oHashsha256.GetDigest(m_hash);
        m_sizeHash= oHashsha256.DIGESTSIZE;
        memcpy(hash, m_hash, m_sizeHash);
        *psize= m_sizeHash;
    }
    else if(type==SHA1HASH) {
        if(*psize<oHashsha1.DIGESTSIZE) {
            fprintf(g_logFile, "AttestInfo::getAttestInfoHash: digest size too small\n");
            return false;
        }
        oHashsha1.Init();
        oHashsha1.Update((const byte*) szCanonical, strlen(szCanonical));
        oHashsha1.Final();
        oHashsha1.getDigest(m_hash);
        m_sizeHash= oHashsha1.DIGESTSIZE;
        memcpy(hash, m_hash, m_sizeHash);
        *psize= m_sizeHash;
    }
    else {
        free((void*)szCanonical);
        szCanonical= NULL;
        return false;
    }
    free((void*)szCanonical);
    szCanonical= NULL;

    if(m_szHash==NULL) {
        if(!toBase64(m_sizeHash, m_hash, &size, szBuf)) {
            fprintf(g_logFile, "Attestation::getAttestInfoHash: cant convert attestedto to base64\n");
        }
        m_szHash= strdup(szBuf);
    }
    return true;
}


// ------------------------------------------------------------------


