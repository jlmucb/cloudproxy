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


#define MAXREQUESTSIZE 16384
#ifndef SMALLNONCESIZE
#define SMALLNONCESIZE 32
#endif


// ------------------------------------------------------------------------



// ------------------------------------------------------------------


/*
 * 
 *  Attest
 * 
 *  <Attest format="xml" type="CP1">
 *    <ds:CanonicalizationMethod Algorithm="http://www.manferdelli.com/2011/Xml/canonicalization/tinyxmlcanonical#" />
 *     <ds:AttestMethod Algorithm="Attest-Sha256FileHash-RSA1024" />
 *     <CodeDigest alg="SHA256">al5/jR40s+ytNsx3SRTLE67oZV5bSl+EXNRrqI2gxKY=</CodeDigest>
 *     <AttestdValue> xxxxxx  </AttestdValue>
 *     <AttestValue>a0NDX3hYz3OzGvGQlOp87X0oJV00zGQ5YOaeVfW/3NqCdml4EzAWcjZNaFf26kry84hZ9ULOpB7+RiBplhKg9kSinMEPfljkvvJJ+vuVdbmEzu45oi3FAh4PMGyp5hoWTxpnhr+MSBhvs08BUcWe+xxMlerdI17T1Tv6wO9iJMo=</AttestValue>
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


#define MAXATTESTSIZE 16384


// ------------------------------------------------------------------


Attest::Attest()
{
}


Attest::~Attest()
{
}


bool  Attest::init(const char* attestation)
{
#if 0
    TiXmlElement*   pRootElement= NULL;
    TiXmlNode*      pNode= NULL;
    const char*     szA= NULL;
    
#ifdef QUOTETEST1
    fprintf(g_logFile, "init()\n");
#endif
    if(attestation==NULL)
        return false;
    
    if(!m_doc.Parse(attestation)) {
        fprintf(g_logFile, "Attest::init: Can't parse attest\n");
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
    // <ds:AttestMethod Algorithm=
    pNode=  Search(m_pNodeAttest, "ds:AttestMethod");
    if(pNode==NULL) {
        fprintf(g_logFile, "Attest::init: No ds:AttestMethod node\n");
        return false;
    }
    szA= ((TiXmlElement*) pNode)->Attribute ("Algorithm");
    if(szA==NULL) {
        fprintf(g_logFile, "Attest::init: No ds:AttestMethod Algorithm\n");
        return false;
    }
    m_szAttestalg= strdup(szA);
    m_pNodeNonce= Search(m_pNodeAttest, "Nonce");
    m_pNodeCodeDigest= Search(m_pNodeAttest, "CodeDigest");
    if(m_pNodeCodeDigest==NULL) {
        fprintf(g_logFile, "Attest::init: No CodeDigest node\n");
        return false;
    }
    m_pNodeAttestedInfo= Search(m_pNodeAttest, "AttestdInfo");
    if(m_pNodeAttestdInfo==NULL) {
        fprintf(g_logFile, "Attest::init: No AttestdInfo node\n");
        return false;
    }
    m_pNodeAttestValue= Search(m_pNodeAttestdInfo, "AttestValue");
    if(m_pNodeAttestValue==NULL) {
        fprintf(g_logFile, "Attest::init: No AttestValue node\n");
        return false;
    }
    m_pNodeattestdKeyInfo= Search(m_pNodeAttestdInfo, "ds:KeyInfo");
    pNode= m_pNodeAttestValue->NextSibling();
    m_pNodeattestKeyInfo= Search(pNode, "ds:KeyInfo");

    return true;
#else
    return false;
#endif
}


const char*  Attest::getAttestValue()
{
    return NULL;
}


const char* Attest::getnonceValue()
{
    return NULL;
}


const char* Attest::getattestingkeyInfo()
{
    return NULL;
}


const char* Attest::getAttestAlg()
{
    if(m_szAttestalg==NULL)
        return NULL;
    return strdup(m_szAttestalg);
}



const char* Attest::getInterpretationHint()
{
    return NULL;
}

const char* Attest::encodeAttest()
{
    return NULL;
}


bool Attest::decodeAttest()
{
    return false;
}


bool Attest::checkAttest()
{
    return false;
}



// ------------------------------------------------------------------


AttestInfo::AttestInfo()
{
}


AttestInfo::~AttestInfo()
{
}


bool  AttestInfo::init(const char* attestInfo)
{
}


const char* AttestInfo::getSerializedKey()
{
    return NULL;
}


bool  AttestInfo::getAttestInfoHash()
{
}


// ------------------------------------------------------------------


