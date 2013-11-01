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
"  <CodeDigest Algorithm=\"%s\">%s</CodeDigest>\n"\
"  <AttestedValue>%s</AttestedValue>\n"\
"  <Attestation Algorithm=\"%s\">%s</Attestation>\n"\
"      %s\n"\
"  <InterpretationHint>\n"\
"%s\n"\
"  </InterpretationHint>\n"\
"</Attest>\n";


const char* g_AttestInfoTemplate=
"<attestedInfo>\n"\
"%s\n"\
"</attestedInfo>\n";
 

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


Attest::Attest()
{
    m_fValid= false;
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
    m_pNodeAttest= NULL;
    m_pNodeNonce= NULL;
    m_pNodeCodeDigest= NULL;
    m_pNodeInterpretationHint= NULL;
    m_pNodeAttestedValue= NULL;
    m_pNodeAttestation= NULL;
    m_pNodeattestingKeyInfo= NULL;
    m_pNodeInterpretationHint= NULL;
}


Attest::~Attest()
{
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
}


bool  Attest::init(const char* attestation)
{
    TiXmlElement*   pRootElement= NULL;
    TiXmlNode*      pNode= NULL;
    TiXmlNode*      pNode1= NULL;
    const char*     szA= NULL;
    
#ifdef TEST
    fprintf(g_logFile, "Attest::init()\n");
#endif
    if(attestation==NULL)
        return false;
    
    if(!m_doc.Parse(attestation)) {
        fprintf(g_logFile, "Attest::init: Can't parse attestation\n");
        return false;
    }   
    pRootElement= m_doc.RootElement();
    if(pRootElement==NULL) {
        fprintf(g_logFile, "Attest::init: Can't get root of attest\n");
        return false;
    }

    m_pNodeAttest= Search((TiXmlNode*) pRootElement, "Attest");
    if(m_pNodeAttest==NULL) {
        fprintf(g_logFile, "Attest::init: No Attest node\n");
        return false;
    }
    szA= ((TiXmlElement*) pNode)->Attribute ("type");
    if(szA==NULL) {
        fprintf(g_logFile, "Attest::init: No type\n");
        return false;
    }
    m_typeDigest= strdup(szA);

    pNode=  Search(m_pNodeAttest, "ds:CanonicalizationMethod Algorithm");
    if(pNode==NULL) {
        fprintf(g_logFile, "Attest::init: CanonicalizationMethod node\n");
        return false;
    }
    szA= ((TiXmlElement*) pNode)->Attribute ("Algorithm");
    if(szA==NULL) {
        fprintf(g_logFile, "Attest::init: No CanonicalizationMethod Algorithm\n");
        return false;
    }
    m_szCanonicalizationalg= strdup(szA);

    pNode=  Search(m_pNodeAttest, "CodeDigest");
    if(pNode==NULL) {
        fprintf(g_logFile, "Attest::init: No CodeDigest\n");
        return false;
    }
    szA= ((TiXmlElement*) pNode)->Attribute ("Algorithm");
    if(szA==NULL) {
        fprintf(g_logFile, "Attest::init: No CodeDigest Algorithm\n");
        return false;
    }
    m_typeDigest= strdup(szA);
    pNode1= ((TiXmlElement*)pNode)->FirstChild();
    if(pNode1==NULL) {
        fprintf(g_logFile, "Attest::init: No CodeDigest value\n");
        return false;
    }
    m_szcodeDigest= strdup(((TiXmlElement*)pNode1)->Value());

    pNode=  Search(m_pNodeAttest, "AttestedValue");
    if(pNode==NULL) {
        fprintf(g_logFile, "Attest::init: No AttestedValue\n");
        return false;
    }
    pNode1= ((TiXmlElement*)pNode)->FirstChild();
    if(pNode1==NULL) {
        fprintf(g_logFile, "Attest::init: No Attestaton value\n");
        return false;
    }
    m_szattestedValue= strdup(((TiXmlElement*)pNode1)->Value());

    pNode=  Search(m_pNodeAttest, "Attestation");
    if(pNode==NULL) {
        fprintf(g_logFile, "Attest::init: No Attestation\n");
        return false;
    }
    szA= ((TiXmlElement*) pNode)->Attribute ("Algorithm");
    if(szA==NULL) {
        fprintf(g_logFile, "Attest::init: No Attestaton Algorithm\n");
        return false;
    }
    m_szAttestalg= strdup(szA);
    pNode1= ((TiXmlElement*)pNode)->FirstChild();
    if(pNode1==NULL) {
        fprintf(g_logFile, "Attest::init: No Attestaton value\n");
        return false;
    }
    m_szattestation= strdup(((TiXmlElement*)pNode1)->Value());

    m_pNodeInterpretationHint= Search(m_pNodeAttest, "InterpretationHint");
    if(m_pNodeInterpretationHint!=NULL)
        m_szHint= canonicalize(m_pNodeInterpretationHint);

    m_fValid= true;
    return true;
}


const char* Attest::getAttestAlg()
{
    if(m_szAttestalg==NULL)
        return NULL;
    return strdup(m_szAttestalg);
}


const char* Attest::getAttestation()
{
    if(m_szattestation==NULL)
        return NULL;
    return strdup(m_szattestation);
}


const char* Attest::getAttestedTo()
{
    if(m_szattestedValue==NULL)
        return NULL;
    return strdup(m_szattestedValue);
}


const char* Attest::getNonce()
{
    if(m_szNonce==NULL)
        return NULL;
    return strdup(m_szNonce);
}


const char* Attest::getattestingkeyInfo()
{
    if(m_pNodeattestingKeyInfo==NULL)
        return NULL;
    return canonicalize(m_pNodeattestingKeyInfo);
}


bool Attest::setAttestedTo(int size, byte* attestedTo)
{
    if(size<=0 || attestedTo==NULL)
        return false;
    if(m_attestedTo!=NULL)
        free(m_attestedTo);
    m_attestedTo= (byte*) malloc(size);
    if(m_attestedTo==NULL)
        return false;
    memcpy(m_attestedTo, attestedTo, size);
    m_sizeattestedTo= size; 
    return true;
}


bool Attest::getAttestedTo(int* psize, byte* attestedTo)
{
    if(m_sizeattestedTo<=0 || m_attestedTo==NULL)
        return false;
    memcpy(attestedTo, m_attestedTo, m_sizeattestedTo);;
    *psize= m_sizeattestedTo;
    return true;
}


bool Attest::setAttestation(int size, byte* attestation)
{
    if(size<=0 || attestation==NULL)
        return false;
    if(m_attestation!=NULL)
        free(m_attestation);
    m_attestation= (byte*) malloc(size);
    if(m_attestation==NULL)
        return false;
    memcpy(m_attestation, attestation, size);
    m_sizeattestation= size; 
    return true;
}


bool Attest::getAttestation(int* psize, byte* attestation)
{
    if(m_sizeattestation<=0 || m_attestation==NULL)
        return false;
    memcpy(attestation, m_attestation, m_sizeattestation);
    *psize= m_sizeattestation;
    return true;
}


bool Attest::setcodeDigest(int size, byte* codeDigest)
{
    if(size<=0 || codeDigest==NULL)
        return false;
    if(m_codeDigest!=NULL)
        free(m_codeDigest);
    m_codeDigest= (byte*) malloc(size);
    if(m_codeDigest==NULL)
        return false;
    memcpy(m_codeDigest, codeDigest, size);
    m_sizecodeDigest= size; 
    return true;
}


bool Attest::getcodeDigest(int* psize, byte* codeDigest)
{
    if(m_sizecodeDigest<=0 || m_codeDigest==NULL)
        return false;
    memcpy(codeDigest, m_codeDigest, m_sizecodeDigest);
    *psize= m_sizecodeDigest;
    return true;
}


bool Attest::setHint(const char* hint)
{
    if(hint!=NULL)
        m_szHint= strdup(hint);
    else
        m_szHint= NULL;

    return true;
}


const char* Attest::getHint()
{
    if(m_szHint==NULL)
        return NULL;
    return strdup(m_szHint);
}


#define MAXATTESTSIZE 8192


const char* Attest::encodeAttest()
{
    char        szAttestation[MAXATTESTSIZE];
    const char* szhint= "";
    int         size= 0;

    // char attestedTo
    if(m_sizeattestedTo<=0 || m_attestedTo==NULL) {
        fprintf(g_logFile, "Attest::encodeAttest: no attestedTo\n");
        return false;
    }
    if(m_szattestedValue==NULL) {
        size= 8192;
        if(!toBase64(m_sizeattestedTo, m_attestedTo, &size, szAttestation)) {
            fprintf(g_logFile, "Attest::encodeAttest: cant convert attestedto to base64\n");
            return false;
        }
        m_szattestedValue= strdup(szAttestation);
    }

    // char codeDigest
    if(m_sizecodeDigest<=0 || m_codeDigest==NULL) {
        fprintf(g_logFile, "Attest::encodeAttest: no code digest\n");
        return false;
    }
    if(m_szcodeDigest==NULL) {
        size= 8192;
        if(!toBase64(m_sizecodeDigest, m_codeDigest, &size, szAttestation)) {
            fprintf(g_logFile, "Attest::encodeAttest: cant convert code digest to base64\n");
            return false;
        }
        m_szcodeDigest= strdup(szAttestation);
    }

    // char attestation
    if(m_sizeattestation<=0 || m_attestation==NULL) {
        fprintf(g_logFile, "Attest::encodeAttest: no attestation\n");
        return false;
    }
    if(m_szattestation==NULL) {
        size= 8192;
        if(!toBase64(m_sizeattestation, m_attestation, &size, szAttestation)) {
            fprintf(g_logFile, "Attest::encodeAttest: cant convert attestedto to base64\n");
            return false;
        }
        m_szattestation= strdup(szAttestation);
    }

    if(m_szHint!=NULL)
        szhint= m_szHint;

    // buffer big enough?
    size= strlen(g_AttestTemplate)+strlen("CP1")+strlen("SHA256")+
          strlen(m_szcodeDigest)+strlen(m_szattestedValue)+strlen(m_szAttestalg)+
          strlen(m_szattestation)+strlen(szhint);
    if((size+32)>MAXATTESTSIZE) {
        fprintf(g_logFile, "Attest::encodeAttest: attestation too large\n");
        return false;
    }

    sprintf(szAttestation, g_AttestTemplate, "CP1", "SHA256", m_szcodeDigest, 
            m_szattestedValue, m_szAttestalg, m_szattestation, szhint);
    return canonicalizeXML(szAttestation);
}


// ------------------------------------------------------------------


AttestInfo::AttestInfo()
{
    m_fValid= false;
    m_pNodeAttestInfo= NULL;
    m_pKeyInfo= NULL;
}


AttestInfo::~AttestInfo()
{
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

    m_pNodeAttestInfo= Search((TiXmlNode*) pRootElement, "attestedInfo");
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


bool  AttestInfo::getAttestInfoHash(u32 type, int* psize, byte* hash)
{
    Sha256  oHash;

    const char* szCanonical= NULL;
    if(!m_fValid || m_pNodeAttestInfo!=NULL)
        return false;
    if(type!=SHA256DIGESTBYTESIZE)
        return false;
    if(*psize<oHash.DIGESTSIZE)
        return false;
    szCanonical= canonicalize(m_pNodeAttestInfo);
    oHash.Init();
    oHash.Update((const byte*) szCanonical, strlen(szCanonical));
    oHash.Final();
    oHash.GetDigest(hash);
    *psize= oHash.DIGESTSIZE;
    free((void*)szCanonical);
    return true;
}


// ------------------------------------------------------------------


