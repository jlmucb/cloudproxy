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
#include "encapsulate.h"


//
//  Metadata format
//
//  <EncapsulatedMessage>
//      <SealAlgorithm> </SealAlgorithm>
//      <SignAlgorithm> </SignAlgorithm>
//      <EncryptAlgorithm> </EncryptAlgorithm>
//      <SealedKey></SealedKey>
//      <Cert></Cert>
//  </EncapsulatedMessage>
//

static char* s_szEncapsulateBeginTemplate= (char*)
"<EncapsulatedMessage>\n    <SealAlgorithm>%s</SealAlgorithm>\n";
static char* s_szEncapsulateMidTemplate= (char*)
"    <EncryptAlgorithm>%s</EncryptAlgorithm>\n"\
"    <SealedKey>%s</SealedKey>\n";
static char* s_szEncapsulateSignTemplate= (char*)
"    <SignAlgorithm>%s</SignAlgorithm>\n";
static char* s_szEncapsulateCertTemplate= (char*)
"    <Cert>%s</Cert>\n";
static char* s_szEncapsulateEndTemplate= (char*)
"</EncapsulatedMessage>\n";



// -------------------------------------------------------------------------------------


//
//   Todo:  This uses the wrong padding algorithm
//          Replace emsapkcspad and emsapkcssanity with the right ones later
bool emsapkcssanity(int sigsize, byte* padded, int sizeout, byte* out)
{
    if(padded[0]!=0x00 || padded[1]!=0x01)
        return false;
    for(int i=3; i<20; i++)
        if(padded[i]!=0xff)
            return false;
    memcpy(out, padded+sigsize-sizeout, sizeout);
    return true;
}



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
    if(m_rgEncrypted!=NULL) {
        free(m_rgEncrypted);
        m_rgEncrypted= NULL;
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
    char    buf[16382]; // FIX
    int     start= 0;

    if(m_szXMLmetadata!=NULL) 
        return strdup(m_szXMLmetadata);

    if(m_szSealAlg==NULL || m_szEncryptAlg==NULL || m_szSealedKey==NULL) {
        fprintf(g_logFile, "encapsulatedMessage::serializeMetaData: Mandatory metadata missing\n");
        return false;
    }
    if((strlen(m_szSealAlg)+strlen(m_szEncryptAlg)+strlen(m_szSealedKey))> 16000) {
        fprintf(g_logFile, "encapsulatedMessage::serializeMetaData: parameters too large\n");
        return false;
    }

    sprintf(&buf[start], s_szEncapsulateBeginTemplate, m_szSignAlg);
    start= strlen(buf);
    sprintf(&buf[start], s_szEncapsulateMidTemplate, m_szEncryptAlg, m_szSealedKey);
    if(m_szSignAlg!=NULL) {
        start= strlen(buf);
        sprintf(&buf[start], s_szEncapsulateSignTemplate, m_szSignAlg);
    }
    if(m_szCert!=NULL) {
        start= strlen(buf);
        sprintf(&buf[start], s_szEncapsulateCertTemplate, m_szCert);
    }
    start= strlen(buf);
    sprintf(&buf[start], s_szEncapsulateEndTemplate);

    return strdup(buf);
}


bool   encapsulatedMessage::parseMetaData()
{
    TiXmlDocument   doc;
    TiXmlElement*   pRootElement= NULL;
    TiXmlNode*      pNode= NULL;
    TiXmlNode*      pNode1= NULL;

    if(m_szXMLmetadata==NULL) {
        fprintf(g_logFile, "encapsulatedMessage::parseMetaData: XML metadata empty\n");
        return false;
    }

    if(!doc.Parse(m_szXMLmetadata)) {
        fprintf(g_logFile, "encapsulatedMessage::parseMetaData: Cant parse XML metadata\n");
        return false;
    }

    pRootElement= doc.RootElement();
    pNode= (TiXmlNode*) pRootElement;
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
            m_szCert= strdup(((TiXmlElement*)pNode1)->Value());
        }
    }

    return true;
}


bool   encapsulatedMessage::sealKey(RSAKey* sealingKey)     // FIX
{
    char    buf[2*GLOBALMAXPUBKEYSIZE];
    int     outsize= 2*GLOBALMAXPUBKEYSIZE;
    byte    in[2*GLOBALMAXSYMKEYSIZE];
    int     insize= 0;
    byte    padded[GLOBALMAXPUBKEYSIZE];
    int     blocksize;
    bnum    bnMsg(2*(GLOBALMAXPUBKEYSIZE/sizeof(u64));
    bnum    bnOut(2*(GLOBALMAXPUBKEYSIZE/sizeof(u64));
    byte    sealed[GLOBALMAXPUBKEYSIZE];

    if(sealingKey==NULL) {
        fprintf(g_logFile, "encapsulatedMessage::sealKey no sealing key\n");
        return false;
    }

    blocksize= sealingKey->m_iByteSizeM;

    if((m_sizeEncKey+m_sizeIntKey)>128) {
        fprintf(g_logFile, "encapsulatedMessage::sealKey sealKey: keys too big\n");
        return false;
    }

    if(strcmp(m_szSealAlg, RSA1024SEALALG)!=0) {
        fprintf(g_logFile, "encapsulatedMessage::sealKey unsupported sealing algorithm\n");
        return false;
    }
    if(strcmp(m_szEncryptAlg, AESCBCENCRYPTALG)!=0) {
        fprintf(g_logFile, "encapsulatedMessage::sealKey unsupported encryption algorithm\n");
        return false;
    }

    m_sizeEncKey= AES128BYTEBLOCKSIZE;
    m_sizeIntKey= AES128BYTEBLOCKSIZE;

    if(m_encKey==NULL) {
        m_encKey= (byte*) malloc(m_sizeEncKey);
        if(!getCryptoRandom(m_sizeEncKey*NBITSINBYTE, m_encKey)) {
            fprintf(g_logFile, "encapsulatedMessage::sealKey can't generate encryption key\n");
            return false;
        }
    }
    if(m_intKey==NULL) {
        m_intKey= (byte*) malloc(m_sizeIntKey);
        if(!getCryptoRandom(m_sizeIntKey*NBITSINBYTE, m_intKey)) {
            fprintf(g_logFile, "encapsulatedMessage::sealKey can't generate integrity key\n");
            return false;
        }
    }

    memcpy(&in[insize],m_encKey,m_sizeEncKey);
    insize+= m_sizeEncKey;
    memcpy(&in[insize],m_intKey,m_sizeIntKey);
    insize+= m_sizeIntKey;

    // pad
    if(!emsapkcspad(SHA256HASH, in, blocksize, padded)) {
        fprintf(g_logFile, "encapsulatedMessage::sealKey can't pad %d\n", blocksize);
        return false;
    }
    // seal
    revmemcpy((byte*)bnMsg.m_pValue, padded, blocksize);
    if(!mpRSAENC(bnMsg, *(sealingKey->m_pbnE), *(sealingKey->m_pbnM), bnOut)) {
        fprintf(g_logFile, "encapsulatedMessage::sealKey can't seal\n");
        return false;
    }
    revmemcpy(sealed, (byte*)bnOut.m_pValue, blocksize);

    if(!toBase64(blocksize, sealed, &outsize, buf)) {
        fprintf(g_logFile, "Cant base64 encode sealed key\n");
        return false;
    }

   m_szSealedKey= strdup(buf); 
   return true;
}


bool   encapsulatedMessage::unSealKey(RSAKey* sealingKey)
{
    byte    in[2*GLOBALMAXSYMKEYSIZE];
    byte    padded[GLOBALMAXPUBKEYSIZE];
    int     blocksize;
    bnum    bnMsg(64);
    bnum    bnOut(64);
    int     sizeSealed= GLOBALMAXPUBKEYSIZE;
    byte    sealed[GLOBALMAXPUBKEYSIZE];

    if(sealingKey==NULL) {
        fprintf(g_logFile, "encapsulatedMessage::unSealKey no sealing key\n");
        return false;
    }

    blocksize= sealingKey->m_iByteSizeM;

    if(m_szSealedKey==NULL) {
        fprintf(g_logFile, "encapsulatedMessage::unSealKey no base64 encoded sealed key\n");
        return false;
    }

    if(strcmp(m_szSealAlg, RSA1024SEALALG)!=0) {
        fprintf(g_logFile, "encapsulatedMessage::unSealKey unsupported sealing algorithm\n");
        return false;
    }
    if(strcmp(m_szEncryptAlg, AESCBCENCRYPTALG)!=0) {
        fprintf(g_logFile, "encapsulatedMessage::unSealKey unsupported encryption algorithm\n");
        return false;
    }

    if(!fromBase64(strlen(m_szSealedKey), m_szSealedKey, &sizeSealed, sealed)) {
        fprintf(g_logFile, "encapsulatedMessage::unSealKey no base64 encoded sealed key\n");
        return false;
    }

    m_sizeEncKey= AES128BYTEBLOCKSIZE;
    m_sizeIntKey= AES128BYTEBLOCKSIZE;

    if(m_encKey==NULL) {
        m_encKey= (byte*) malloc(m_sizeEncKey);
    }
    if(m_intKey==NULL) {
        m_intKey= (byte*) malloc(m_sizeIntKey);
    }

#ifdef TEST
    PrintBytes((char*)"\nEncapsulatedMessage::unSealKey, sealed key\n", sealed, sizeSealed);
    fprintf(g_logFile, "PrivateKey:\n");
    sealingKey->printMe();
    fprintf(g_logFile, "\n");
#endif
    // unseal
    revmemcpy((byte*)bnMsg.m_pValue, sealed, blocksize);
    if(!mpRSAENC(bnMsg, *(sealingKey->m_pbnD), *(sealingKey->m_pbnM), bnOut)) {
        fprintf(g_logFile, "encapsulatedMessage::unSealKey can't unseal\n");
        return false;
    }
    revmemcpy(padded, (byte*)bnOut.m_pValue, blocksize);
#ifdef TEST
    PrintBytes((char*)"EncapsulatedMessage::unSealKey, padded\n", padded, blocksize);
#endif

    if(!emsapkcssanity(blocksize, padded, 32, in)) {
        fprintf(g_logFile, "encapsulatedMessage::unSealKey failed padding verification\n");
        return false;
    }

    memcpy(m_encKey, &in[0], m_sizeEncKey);
    memcpy(m_intKey, &in[m_sizeEncKey], m_sizeIntKey);

    return true;
}


bool   encapsulatedMessage::encryptMessage()
{
    int outsize; 

    if(strcmp(m_szEncryptAlg, AESCBCENCRYPTALG)!=0) {
        fprintf(g_logFile, "encapsulatedMessage::encryptMessage unsupported encryption algorithm\n");
        return false;
    }

    if(m_encKey==NULL) {
        fprintf(g_logFile, "encapsulatedMessage::encryptMessage no encryption key\n");
        return false;
    }
    if(m_intKey==NULL) {
        fprintf(g_logFile, "encapsulatedMessage::encryptMessage no integrity key\n");
        return false;
    }

    if(m_rgPlain==NULL) {
        fprintf(g_logFile, "encapsulatedMessage::encryptMessage: no plaintext\n");
        return false;
    }

    m_sizeEncrypted= m_sizePlain+64+SHA256DIGESTBYTESIZE;
    if(m_rgEncrypted==NULL) {
         m_rgEncrypted= (byte*) malloc(m_sizeEncrypted);
    }
    outsize= m_sizeEncrypted;
    if(!AES128CBCHMACSHA256SYMPADEncryptBlob(m_sizePlain, m_rgPlain, &outsize, m_rgEncrypted,
                                              m_encKey, m_intKey)) {
        fprintf(g_logFile, "encapsulatedMessage::encryptMessage: cant encrypt blob\n");
        return false;
    }
    m_sizeEncrypted= outsize;

    return true;
}


bool   encapsulatedMessage::decryptMessage()
{
    int outsize; 

    if(strcmp(m_szEncryptAlg, AESCBCENCRYPTALG)!=0) {
        fprintf(g_logFile, "encapsulatedMessage::decryptMessage unsupported encryption algorithm\n");
        return false;
    }

    if(m_encKey==NULL) {
        fprintf(g_logFile, "encapsulatedMessage::decryptMessage no encryption key\n");
        return false;
    }
    if(m_intKey==NULL) {
        fprintf(g_logFile, "encapsulatedMessage::decryptMessage no integrity key\n");
        return false;
    }

    if(m_rgEncrypted==NULL) {
        fprintf(g_logFile, "encapsulatedMessage::decryptMessage: no plaintext\n");
        return false;
    }
    m_sizePlain= m_sizeEncrypted;
    if(m_rgPlain==NULL) {
         m_rgPlain= (byte*) malloc(m_sizePlain);
    }
    outsize= m_sizeEncrypted;
    if(!AES128CBCHMACSHA256SYMPADDecryptBlob(m_sizeEncrypted, m_rgEncrypted, &outsize, m_rgPlain,
                                          m_encKey, m_intKey)) {
        fprintf(g_logFile, "encapsulatedMessage::decryptMessage: cant decrypt blob\n");
        return false;
    }
    m_sizePlain= outsize;

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
    memcpy(m_rgEncrypted, in, size);
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
    if(m_rgPlain!=NULL) {
        free(m_rgPlain);
        m_rgPlain= NULL;
        m_sizePlain= 0;
    }
    m_rgPlain= (byte*)malloc(size);
    if(m_rgPlain==NULL)
        return false;
    memcpy(m_rgPlain, in, size);
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
    return NULL;
}


char*  encapsulatedMessage::getSubjectKeyInfo()
{
    TiXmlDocument   doc;
    TiXmlElement*   pRootElement= NULL;
    TiXmlNode*      pNode;
    TiXmlNode*      pNode1;

    if(m_szCert==NULL) {
        fprintf(g_logFile, "encapsulatedMessage::getSubjectKeyInfo: XML empty\n");
        return false;
    }

    if(!doc.Parse(m_szCert)) {
        fprintf(g_logFile, "encapsulatedMessage::getSubjectKeyInfo: Cant parse cert\n");
        return false;
    }

    pRootElement= doc.RootElement();
    pNode= (TiXmlNode*)pRootElement;
    if(pNode->Type()!=TiXmlNode::TINYXML_ELEMENT ||
                  strcmp(((TiXmlElement*)pNode)->Value(),"ds:Signature")!=0) {
        fprintf(g_logFile, "encapsulatedMessage::getSubjectKeyInfo: No signature\n");
        return false;
        }

    pNode= Search(pRootElement,"SubjectKey");
    if(pNode==NULL) {
        fprintf(g_logFile, "encapsulatedMessage::getSubjectKeyInfo: No subject key\n");
        return false;
    }
    pNode1= pNode->FirstChild();
    if(pNode1==NULL) {
        fprintf(g_logFile, "encapsulatedMessage::getSubjectKeyInfo: no child of subject key\n");
        return false;
    }
    return canonicalize(pNode1);
}


#ifdef TEST
void   encapsulatedMessage::printMe()
{
    fprintf(g_logFile, "encapsulatedMessage data\n");
    if(m_szSignerKeyInfo!=NULL)
        fprintf(g_logFile, "\tm_szSignerKeyInfo: %s\n", m_szSignerKeyInfo);
    if(m_szSignerKeyInfo!=NULL)
        fprintf(g_logFile, "\tm_szSignerKeyInfo: %s\n", m_szSignerKeyInfo);
    if(m_szSubjectKeyInfo!=NULL)
        fprintf(g_logFile, "\tm_szSubjectKeyInfo: %s\n", m_szSubjectKeyInfo);
    if(m_szSignAlg!=NULL)
        fprintf(g_logFile, "\tm_szSignAlg: %s\n", m_szSignAlg);
    if(m_szSignAlg!=NULL)
        fprintf(g_logFile, "\tm_szSignAlg: %s\n", m_szSignAlg);
    if(m_szSealAlg!=NULL)
        fprintf(g_logFile, "\tm_szSealAlg: %s\n", m_szSealAlg);
    if(m_szEncryptAlg!=NULL)
        fprintf(g_logFile, "\tm_szEncryptAlg: %s\n", m_szEncryptAlg);
    if(m_szSealedKey!=NULL)
        fprintf(g_logFile, "\tm_szSealedKey: %s\n", m_szSealedKey);
    if(m_szXMLmetadata!=NULL)
        fprintf(g_logFile, "\tm_szXMLmetadata: %s\n", m_szXMLmetadata);
    if(m_szCert!=NULL)
        fprintf(g_logFile, "\tm_szCert: %s\n", m_szCert);

    if(m_encKey!=NULL) {
        PrintBytes((char*)"Encrypt Key: ", m_encKey, m_sizeEncKey);
    }
    if(m_intKey!=NULL) {
        PrintBytes((char*)"Integrity Key: ", m_intKey, m_sizeIntKey);
    }
    if(m_rgPlain!=NULL) {
        PrintBytes((char*)"Plaintext: ", m_rgPlain, m_sizePlain);
    }
    if(m_rgEncrypted!=NULL) {
        PrintBytes((char*)"Ciphertext: ", m_rgEncrypted, m_sizeEncrypted);
    }
    if(m_rgPackageSignature!=NULL) {
        PrintBytes((char*)"Ciphertext: ", m_rgPackageSignature, m_sizePackageSignature);
    }

    return;
}


#endif


// -------------------------------------------------------------------------------------


