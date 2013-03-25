//
//  File: encapsulate.cpp
//      John Manferdelli
//
//  Description: Seal key with PK, encrypt file
//
//  Copyright (c) 2011, Intel Corporation. All rights reserved.
//  Incorporates contributions  (c) John Manferdelli.  All rights reserved.
//
//  Redistribution and use in source and binary forms, with or without 
//  modification, are permitted provided that the following conditions 
//  are met:
//    Redistributions of source code must retain the above copyright notice,
//      this list of conditions and the disclaimer below.
//    Redistributions in binary form must reproduce the above copyright
//      notice, this list of conditions and the disclaimer below in the 
//      documentation and/or other materials provided with the distribution.
//
//  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
//  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
//  TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
//  PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
//  HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
//  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
//  TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
//  PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
//  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
//  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
//  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


// ---------------------------------------------------------------------------------


#include "jlmTypes.h"
#include "logging.h"
#include "jlmcrypto.h"
#include "jlmUtility.h"
#include "algs.h"
#include "keys.h"
#include "tinyxml.h"
#include "sha256.h"
#ifdef NOAESNI
#include "aes.h"
#else
#include "aesni.h"
#endif
#include "bignum.h"
#include "mpFunctions.h"
#include "modesandpadding.h"


//
//  Metadata format
//
//  <EncapsulatedMessage>
//      <SealAlg> </SealAlg>
//      <SignAlg> </SignAlg>
//      <EncryptAlgAlg> </SealAlg>
//      <SealedKey></SealedKey>
//      <Cert></Cert>
//  </EncapsulatedMessage>


// -------------------------------------------------------------------------------------


encapsulatedMessage::encapsulatedMessage()
{
    m_szSignAlg= strdup(RSA1024SIGNALG);
    m_szSealAlg= strdup(RSA1024SEALALG);
    m_szEncryptAlg= strdup(AESCBCENCRYPTALG);
    m_szSignerKeyInfo= NULL;
    m_szSubjectKeyInfo= NULL;
    m_szCert= NULL;
    m_szXMLmetadata= NULL;
    m_szSealedKey= NULL;
    m_sizeEncKey= 0;
    m_encKey= NULL;
    m_sizeIntKey= 0;
    m_intKey= NULL;
    m_sizePlain= 0;
    m_rgPlain= NULL;
    m_sizeEncrypted= 0;
    m_rgEncrypted= NULL;
    m_sizePackageSignature= 0;
    m_rgPackageSignature= NULL;
}


encapsulatedMessage::~encapsulatedMessage()
{
    if(m_szSignAlg!=NULL) {
        free(m_szSignAlg);
        m_szSignAlg= NULL;
    }
    if(m_szSealAlg!=NULL) {
        free(m_szSealAlg);
        m_szSealAlg= NULL;
    }
    if(m_szEncryptAlg!=NULL) {
        free(m_szEncryptAlg);
        m_szEncryptAlg= NULL;
    }
    if(m_szXMLmetadata!=NULL) {
        free(m_szXMLmetadata);
        m_szXMLmetadata= NULL;
    }
    if(m_szCert!=NULL) {
        free(m_szCert);
        m_szCert= NULL;
    }
    if(m_szSealedKey!=NULL) {
        free(m_szSealedKey);
        m_szSealedKey= NULL;
    }
    if(m_encKey!=NULL) {
        free(m_encKey);
        m_encKey= NULL;
    }
    if(m_intKey!=NULL) {
        free(m_intKey);
        m_intKey= NULL;
    }
    if(m_rgPlain!=NULL) {
        free(m_rgPlain);
        m_rgPlain= NULL;
    }
    if(m_rgEncrypted=!=NULL) {
        free(m_rgEncrypted=);
        m_rgEncrypted== NULL;
    }
    if(m_rgPackageSignature!=NULL) {
        free(m_rgPackageSignature);
        m_rgPackageSignature= NULL;
    }
    if(m_szSignerKeyInfo!=NULL) {
        free(m_szSignerKeyInfo);
        m_szSignerKeyInfo= NULL;
    }
    if(m_szSubjectKeyInfo!=NULL) {
        free(m_szSubjectKeyInfo);
        m_szSubjectKeyInfo= NULL;
    }

    m_sizeEncKey= 0;
    m_sizePlain= 0;
    m_sizeEncrypted= 0;
    m_sizePackageSignature= 0;
    m_sizeIntKey= 0;
}


// -------------------------------------------------------------------------------------


char*  encapsulatedMessage::serializeMetaData()
{
    char    buf[16382];
    char*   p= buf;
    int     left= 16382;

    if(m_szXMLmetadata!=NULL) 
        return strdup(m_szXMLmetadata);
#if 0
    if(!safeTransfer(&p, &left, szEvidence)) {
        fprintf(g_logFile, "encapsulatedMessage::serializeMetaData: \n");
        return false;
    }
        
    // Canonicalize
    szToHash= canonicalize(pNode);
#endif
    return NULL;
}


bool   encapsulatedMessage::parseMetaData()
{
    TiXmlDocument   doc;
    TiXmlElement*   pRootElement= NULL;
    TiXmlNode*      pNode;
    TiXmlNode*      pNode1;
    TiXmlNode*      pNode2;

    if(m_szXMLmetadata==NULL) {
        fprintf(g_logFile, "encapsulatedMessage::parseMetaData: XML metadata empty\n");
        return false;
    }

    if(!doc.Parse(m_szXMLmetadata)) {
        fprintf(g_logFile, "encapsulatedMessage::parseMetaData: Cant parse XML metadata\n");
        return false;
    }

    pRootElement= doc.RootElement();
    
    pNode= pRootElement->FirstChild();
    if(pNode->Type()!=TiXmlNode::TINYXML_ELEMENT ||
                  strcmp(((TiXmlElement*)pNode)->Value(),"EncapsulatedMessage")!=0) {
        fprintf(g_logFile, "encapsulatedMessage::parseMetaData: No EncapsulatedMessage\n");
        return false;
        }

    pNode= Search(pRootElement,"SealAlgorithm");
    if(pNode==NULL) {
        fprintf(g_logFile, "encapsulatedMessage::parseMetaData: Can't find SealAlgorithm\n");
        return false;
    }
    pNode1= pNode->FirstChild();
    if(pNode1==NULL) {
        fprintf(g_logFile, "encapsulatedMessage::parseMetaData: no value for SealAlgorithm\n");
        return false;
    }
    m_szSealAlg= strdup( ((TiXmlElement*)pNode1)->Value());

    pNode= Search(pRootElement,"SignAlgorithm");
    if(pNode==NULL) {
        fprintf(g_logFile, "encapsulatedMessage::parseMetaData: Can't find SignAlgorithm\n");
        return false;
    }
    pNode1= pNode->FirstChild();
    if(pNode1==NULL) {
        fprintf(g_logFile, "encapsulatedMessage::parseMetaData: no value for SignAlgorithm\n");
        return false;
    }
    m_szSignAlg= strdup( ((TiXmlElement*)pNode1)->Value());

    pNode= Search(pRootElement,"EncryptAlgorithm");
    if(pNode==NULL) {
        fprintf(g_logFile, "encapsulatedMessage::parseMetaData: Can't find EncryptAlgorithm\n");
        return false;
    }
    pNode1= pNode->FirstChild();
    if(pNode1==NULL) {
        fprintf(g_logFile, "encapsulatedMessage::parseMetaData: no value for EncryptAlgorithm\n");
        return false;
    }
    m_szEncryptAlg= strdup( ((TiXmlElement*)pNode1)->Value());

    pNode= Search(pRootElement,"SealedKey");
    if(pNode==NULL) {
        fprintf(g_logFile, "encapsulatedMessage::parseMetaData: Can't find SealedKey\n");
        return false;
    }
    pNode1= pNode->FirstChild();
    if(pNode1==NULL) {
        fprintf(g_logFile, "encapsulatedMessage::parseMetaData: no value for SealedKey\n");
        return false;
    }
    m_szSealedKey= strdup( ((TiXmlElement*)pNode1)->Value());

    pNode= Search(pRootElement,"Cert");
    if(pNode!=NULL) {
        pNode1= pNode->FirstChild();
        if(pNode1!=NULL) {
            m_szCert= strdup( ((TiXmlElement*)pNode1)->Value());
        }
    }

    return true;
}


bool   encapsulatedMessage::sealKey(RSAKey* pSealKey)
{
#if 0
    if(!toBase64(size/16, (u8*)bnP.m_pValue, &iOutLen, szBase64KeyP)) {
        fprintf(g_logFile, "Cant base64 encode P\n");
        return false;
    }
            if(!emsapkcspad(SHA256HASH, rgHashValue, pRSAKey->m_iByteSizeM, rgToSign)) 
                throw "Padding failure in Signing\n";
#endif
    return true;
}


bool   encapsulatedMessage::unSealKey(RSAKey* pSealKey)
{
#if 0
        if(!fromBase64(strlen(szBase64Sign), szBase64Sign, &iOutLen, rguDecoded))
            throw "Cant base64 decode signature block\n";
            fRet= emsapkcsverify(SHA256HASH, rgHashValue, pRSAKey->m_iByteSizeM, rguOut);
#endif
    return true;
}


bool   encapsulatedMessage::encryptMessage()
{
#if 0
bool AES128CBCHMACSHA256SYMPADDecryptBlob(int insize, byte* in, 
                                          int* poutsize, byte* out,
                                          byte* enckey, byte* intkey);
#endif
    return true;
}


bool   encapsulatedMessage::decryptMessage()
{
#if 0
bool AES128CBCHMACSHA256SYMPADEncryptBlob(int insize, byte* in, 
                                          int* poutsize, byte* out,
                                          byte* enckey, byte* intkey);
#endif
    return true;
}


bool   encapsulatedMessage::getencryptedMessage(byte* out)
{
    if(out==NULL)
        return false;

    memcpy(out, m_rgEncrypted, m_sizeEncrypted);
    return true;
}


bool   encapsulatedMessage::setencryptedMessage(int size, byte* in)
{
    if(in==NULL)
        return false;
    if(m_rgEncrypted==NULL) {
        free(m_rgEncrypted);
        m_rgEncrypted= NULL;
        m_sizeEncrypted= 0;
    }
    m_rgEncrypted= (byte*)malloc(size);
    if(m_rgEncrypted==NULL)
        return false;

    m_sizeEncrypted= size;
    return true;
}


bool   encapsulatedMessage::getplainMessage(byte* out)
{
    if(out==NULL)
        return false;

    memcpy(out, m_rgPlain, m_sizePlain);
    return true;
}


bool   encapsulatedMessage::setplainMessage(int size, byte* in)
{
    if(in==NULL)
        return false;
    if(m_rgPlain==NULL) {
        free(m_rgPlain);
        m_rgPlain= NULL;
        m_sizePlain= 0;
    }
    m_rgPlain= (byte*)malloc(size);
    if(m_rgPlain==NULL)
        return false;

    m_sizePlain= size;
    return true;
}


int    encapsulatedMessage::encryptedMessageSize()
{
    return m_sizeEncrypted;
}


int    encapsulatedMessage::plainMessageSize()
{
    return m_sizePlain;
}


bool   encapsulatedMessage::signPackage(RSAKey* pSignKey)
{
    return true;
}


bool   encapsulatedMessage::verifyPackage(RSAKey* pSignKey)
{
    return true;
}


char*  encapsulatedMessage::getSignerKeyInfo()
{
    return true;
}


char*  encapsulatedMessage::getSubjectKeyInfo()
{
    return true;
}


#ifdef TEST
void   encapsulatedMessage::printMe()
{
    return;
}


#endif


// -------------------------------------------------------------------------------------


