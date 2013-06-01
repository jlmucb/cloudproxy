//
//  File: cryptUtility.cpp
//
//  Description: cryptoUtility
//
//  Copyright (c) 2011, Intel Corporation. All rights reserved.
//  Incorporates contributions  (c) John Manferdelli.  All rights reserved.
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
#include "jlmcrypto.h"
#include "jlmUtility.h"
#include "cryptUtility.h"
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
#include "fileHash.h"
#include "mpFunctions.h"
#include "modesandpadding.h"
#include "cert.h"
#include "quote.h"
#include "cryptoHelper.h"
#include "hashprep.h"
#include "encapsulate.h"
#include "validateEvidence.h"
#include "accessControl.h"

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <time.h>


#define NOACTION                   0
#define GENKEY                     1
#define SIGN                       2
#define CANONICAL                  3
#define VERIFY                     4
#define MAKEPOLICYFILE             6
#define ENCRYPTFILE                7
#define DECRYPTFILE                8
#define TIMEREPORT                 9
#define GCMTEST                   10
#define HEXQUOTETEST              11
#define SIGNHEXMODULUS            12
#define HASHFILE                  13
#define MAKEPOLICYKEYFILE         14
#define MAKESERVICEHASHFILE       15
#define VERIFYQUOTE               16
#define QUOTE                     17
#define ENCAPSULATE               18
#define DECAPSULATE               19
#define VALIDATECHAIN             20
#define VALIDATEASSERTION         21
#define GENCERT                   22
#define SEAL                      23
#define UNSEAL                    24


#define MAXREQUESTSIZE          2048
#define MAXADDEDSIZE              64
#define MAXREQUESTSIZEWITHPAD   (MAXREQUESTSIZE+MAXADDEDSIZE)


static const char* s_szCertTemplate= 
"<Certificate Id=\"%s\" version=\"1\">\n"\
"        <SerialNumber>%s</SerialNumber>\n"\
"        <PrincipalType>%s</PrincipalType>\n"\
"        <IssuerName>%s</IssuerName>\n"\
"        <IssuerID>%s</IssuerID>\n"\
"        <ValidityPeriod>\n"\
"            <NotBefore>%s</NotBefore>\n"\
"            <NotAfter>%s</NotAfter>\n"\
"        </ValidityPeriod>        \n"\
"        <SubjectName>%s</SubjectName>\n"\
"        <SubjectKey>\n"\
"%s\n"\
"       </SubjectKey>\n"\
"       <SubjectKeyID>%s</SubjectKeyID>\n"\
"       <RevocationPolicy>Local-check-only</RevocationPolicy>\n"\
"   </Certificate>\n";


// --------------------------------------------------------------------- 



bool GenRSAKey(int size, const char* szOutFile)
{
    RSAKey* pKey= RSAGenerateKeyPair(size);
    char*   szKeyInfo= pKey->SerializetoString();
    if(!saveBlobtoFile(szOutFile, (byte*)szKeyInfo, strlen(szKeyInfo)+1))
        return false;
    return true;
}


bool GenCertSignedInfo(int an, char** av)
{
    int             i;
    const char*     szKeyFile= NULL;
    const char*     szOutFile= NULL;
    const char*     szSerialNumber= "00001";
    const char*     szCertID= "http://www.manferdelli.com/2013/Cert/00002";
    const char*     szPrincipalType= "User";
    const char*     szIssuerName= NULL;
    const char*     szIssuerID= NULL;
    const char*     szSubjectName= NULL;
    const char*     szNotBefore= NULL;
    const char*     szNotAfter= NULL;
    const char*     szSubjectKeyID= "newKey";
    const char*     szRevocationPolicy= "Local-check-only";
    int             sizeKey= 4096;
    char            szKeyBuf[4096];
    int             sizeOut= 8192;
    char            szOutBuf[8192];

    // get notbefore and notafter if not specified
    time_t      timer;
    time(&timer);
    struct tm*  pgmtime= gmtime((const time_t*)&timer);
    szNotBefore= stringtimefromtimeInfo(pgmtime);
    pgmtime->tm_year+= 1;
    szNotAfter= stringtimefromtimeInfo(pgmtime);

    i= 0;
    szKeyFile= av[i++];
    fprintf(g_logFile, "GenCertSignedInfo\n");
    for(; i<(an-1);i++) {
        if(strcmp(av[i], "-SerialNumber")==0) {
            szSerialNumber= av[++i];
        }
        else if(strcmp(av[i], "-PrincipalType")==0) {
            szPrincipalType= "User";
        }
        else if(strcmp(av[i], "-CertID")==0) {
            szCertID= av[++i];
        }
        else if(strcmp(av[i], "-IssuerName")==0) {
            szIssuerName= av[++i];
        }
        else if(strcmp(av[i], "-IssuerID")==0) {
            szIssuerID= av[++i];
        }
        else if(strcmp(av[i], "-SubjectName")==0) {
            szSubjectName= av[++i];
        }
        else if(strcmp(av[i], "-Period")==0) {
            szNotBefore= av[++i];
            szNotAfter= av[++i];
        }
        else if(strcmp(av[i], "-RevocationPolicy")==0) {
            szRevocationPolicy= av[++i];
        }
        else if(strcmp(av[i], "-SubjectKeyID")==0) {
            szSubjectKeyID= av[++i];
        }
    }
    szOutFile= av[i];

    if(!getBlobfromFile(szKeyFile, (byte*)szKeyBuf, &sizeKey)) {
        fprintf(g_logFile, "GenCertSignedInfo: Can't read key from %s\n", szKeyFile);
        return false;
    }

    sprintf(szOutBuf,s_szCertTemplate,
            szCertID,
            szSerialNumber,
            szPrincipalType,
            szIssuerName,
            szIssuerID,
            szNotBefore,
            szNotAfter,
            szSubjectName,
            szKeyBuf,
            szSubjectKeyID,
            szRevocationPolicy);

    char* szCanonical= XMLCanonicalizedString(szOutBuf);
    if(szCanonical==NULL) {
        fprintf(g_logFile, "GenCertSignedInfo: Can't canonicalize\n");
        return false;
    }
    sizeOut= strlen(szCanonical);
    if(!saveBlobtoFile(szOutFile, (byte*)szCanonical, sizeOut)) {
        fprintf(g_logFile, "GenCertSignedInfo: Can't write output from %s\n", szOutFile);
        return false;
    }
    free(szCanonical);
    szCanonical= NULL;
    return true;
}


bool  Canonical(const char* szInFile, const char* szOutFile)
{
    TiXmlDocument   doc;

    if(!doc.LoadFile(szInFile)) {
        fprintf(g_logFile, "Cant load file %s\n", szInFile);
        return NULL;
    }
    TiXmlElement*   pRootElement= doc.RootElement();

    char* szDoc= canonicalize((TiXmlNode*) pRootElement);
    FILE* out= fopen(szOutFile,"w");
    fprintf(out, "%s", szDoc);
    fclose(out);
    return true;
}


bool GenAESKey(int size, const char* szOutFile)
{
    TiXmlDocument   doc;
    TiXmlNode*      pNode;
    TiXmlNode*      pNode1;
    u8              buf[32];
    extern char*    szAESKeyProto;
    int             iOutLen= 128;
    char            szBase64Key[256];

    /*
     *  <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#" KeyName=''>
     *  <ds:KeyValue>
     *  <ds:AESKeyValue size=''>
     */

    if(!getCryptoRandom(size, buf)) {
        fprintf(g_logFile, "Cant generate AES key\n");
        return false;
    }

    PrintBytes("AES key:", buf, size/8);

    if(!toBase64(size/8, buf, &iOutLen, szBase64Key)) {
        fprintf(g_logFile, "Cant base64 encode AES key\n");
        return false;
    }

#ifdef TEST2
    fprintf(g_logFile, "Base64 encoded: %s\n",szBase64Key);
#endif

    doc.Parse(szAESKeyProto);

    TiXmlElement* pRootElement= doc.RootElement();
    TiXmlText* pNewText;
    if(strcmp(pRootElement->Value(),"ds:KeyInfo")==0) {
        pRootElement->SetAttribute("KeyName","KEYNAME");
    }
    pNode= pRootElement->FirstChild();
    while(pNode) {
        if(pNode->Type()==TiXmlNode::TINYXML_ELEMENT) {
            if(strcmp(((TiXmlElement*)pNode)->Value(),"KeyType")==0) {
                    pNewText= new TiXmlText("AESKeyType");
                    pNode->InsertEndChild(*pNewText);
            }
            if(strcmp(((TiXmlElement*)pNode)->Value(),"ds:KeyValue")==0) {
                pNode1= pNode->FirstChild();
                while(pNode1) {
                    if(strcmp(((TiXmlElement*)pNode1)->Value(),"ds:AESKeyValue")==0) {
                        ((TiXmlElement*) pNode1)->SetAttribute ("size", size);
                        pNewText= new TiXmlText(szBase64Key);
                        pNode1->InsertEndChild(*pNewText);
                    }
                    pNode1= pNode1->NextSibling();
                }
            }
        }
        pNode= pNode->NextSibling();
    }

    TiXmlPrinter printer;
    doc.Accept(&printer);
    const char* szDoc= printer.CStr();
    FILE* out= fopen(szOutFile,"w");
    fprintf(out, "%s", szDoc);
    fclose(out);
    // fprintf(g_logFile, "%s", szDoc);
    return true;
}


bool GenKey(const char* szKeyType, const char* szOutFile)
{
    bool fRet;

    if(szKeyType==NULL)
        return false;
    if(strcmp(szKeyType, "AES128")==0) {
        return GenAESKey(128, szOutFile);
    }
    if(strcmp(szKeyType, "AES256")==0) {
        return GenAESKey(256, szOutFile);
    }
    // just for test
    if(strcmp(szKeyType, "RSA128")==0) {
        return GenRSAKey(128, szOutFile);
    }
    if(strcmp(szKeyType, "RSA256")==0) {
        return GenRSAKey(256, szOutFile);
    }
    if(strcmp(szKeyType, "RSA512")==0) {
        return GenRSAKey(512, szOutFile);
    }
    if(strcmp(szKeyType, "RSA1024")==0) {
        fprintf(g_logFile, "calling GenRSAKey\n");
        fRet= GenRSAKey(1024, szOutFile);
        fprintf(g_logFile, "returned from GenRSAKey\n");
        return fRet;
    }
    if(strcmp(szKeyType, "RSA2048")==0) {
        return GenRSAKey(2048, szOutFile);
    }
    return false;
}


// --------------------------------------------------------------------


const char*   szSigHeader= 
          "<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" Id='uniqueid'>\n";
const char*   szSigValueBegin= "    <ds:SignatureValue>    \n";
const char*   szSigValueEnd= "\n    </ds:SignatureValue>\n";
const char*   szSigTrailer= "</ds:Signature>\n";


bool Sign(const char* szKeyFile, const char* szAlgorithm, const char* szInFile, const char* szOutFile)
{
    char*   szBuf[8192];
    int     bufLen= 8192;
    RSAKey* pKey= (RSAKey*)ReadKeyfromFile(szKeyFile);

    if(pKey==NULL) {
        fprintf(g_logFile, "Sign: Can't get key from keyfile %s\n", szKeyFile);
        return false;
    }

    if(!getBlobfromFile(szInFile, (byte*)szBuf, &bufLen)) {
        fprintf(g_logFile, "Sign: Can't read signedInfo from %s\n", szInFile);
        return false;
    }
    szBuf[bufLen]= 0;
    char* szSignedInfo= XMLCanonicalizedString((const char*) szBuf);
    if(szSignedInfo==NULL) {
        fprintf(g_logFile, "Sign: Cant canonicalize signedInfo\n");
        return false;
    }

    char* szSig= constructXMLRSASha256SignaturefromSignedInfoandKey(*pKey,
                                                "newKey", szSignedInfo);
    if(szSig==NULL) {
        fprintf(g_logFile, "Sign: Cant construct signature\n");
        return false;
    }

    if(!saveBlobtoFile(szOutFile, (byte*)szSig, strlen(szSig)+1)) {
        fprintf(g_logFile, "Sign: Cant save %s\n", szOutFile);
        return false;
    }
    return true;
}


bool Verify(const char* szKeyFile, const char* szInFile)
{
    char*   szBuf[8192];
    int     bufLen= 8192;
    RSAKey* pKey= (RSAKey*)ReadKeyfromFile(szKeyFile);

    if(pKey==NULL) {
        fprintf(g_logFile, "Verify: Can't get key from keyfile %s\n", szKeyFile);
        return false;
    }

    if(!getBlobfromFile(szInFile, (byte*)szBuf, &bufLen)) {
        fprintf(g_logFile, "Verify: Can't read signature from %s\n", szInFile);
        return false;
    }

#ifdef TEST
    fprintf(g_logFile, "Verify: got blob\n"); fflush(g_logFile);
#endif

    TiXmlDocument doc;
    if(!doc.Parse((const char*)szBuf)) {
        fprintf(g_logFile, "Verify: Cant parse Signature Document\n");
        return NULL;
    }
    if(doc.RootElement()==NULL) {
        fprintf(g_logFile, "Verify: Cant get root element\n");
        return NULL;
    }
    TiXmlNode* pNode= Search((TiXmlNode*) doc.RootElement(), "ds:SignedInfo");
    if(pNode==NULL) {
        fprintf(g_logFile, "Verify: Can't get SignedInfo\n");
        return false;
    }
    char* szSignedInfo= canonicalize(pNode);

#ifdef TEST
    fprintf(g_logFile, "Verify: got signedinfo\n"); fflush(g_logFile);
#endif

    pNode= Search((TiXmlNode*) doc.RootElement(), "ds:SignatureValue");
    if(pNode==NULL) {
        fprintf(g_logFile, "Verify: Can't get SignatureValue element\n");
        return false;
    }
    TiXmlNode* pNode1= pNode->FirstChild();
    if(pNode1==NULL) {
        fprintf(g_logFile, "Verify: Can't get SignatureValue element\n");
        return false;
    }
    if(pNode1->Value()==NULL) {
        fprintf(g_logFile, "Verify: Can't get SignatureValue\n");
        return false;
    }
    char* szSigValue= strdup(pNode1->Value());
    if(szSigValue==NULL) {
        fprintf(g_logFile, "Verify: Can't get szSigValue\n");
        return false;
    }

#ifdef TEST
    fprintf(g_logFile, "Verify: about to VerifyRSASha256SignaturefromSignedInfoandKey\n"); 
    fflush(g_logFile);
#endif

    return VerifyRSASha256SignaturefromSignedInfoandKey(*pKey, szSignedInfo, szSigValue);
}


bool Seal(const char* szKeyFile, bool fPublic, const char* szDataIn, 
          const char** pszDataOut)
{
    RSAKey* pKey= (RSAKey*)ReadKeyfromFile(szKeyFile);
    if(pKey==NULL) {
        fprintf(g_logFile, "Sign: Can't get key from keyfile %s\n", szKeyFile);
        return false;
    }
    byte    inBuf[4096];
    byte    outBuf[4096];
    int     size= 4096;
    int     outsize= 4096;
    int     strSize= 4096;
    char    szOut[4096];

    if(!fromBase64(strlen(szDataIn), szDataIn, &size, inBuf)) {
        fprintf(g_logFile, "Seal: Cant base64 decode input data\n");
        return false;
    }
    PrintBytes((char*)"Input data: ", inBuf, size);
    u32     keyUse= USEPUBLIC;
    if(fPublic)
        keyUse= USEPUBLIC;
    else
        keyUse= USEPRIVATE;

    if(!RSASeal(*pKey, keyUse, size, inBuf, &outsize, outBuf)) {
        fprintf(g_logFile, "Seal: Cant RSAUnseal\n");
        return false;
    }
    PrintBytes((char*)"Sealed data: ", outBuf, outsize);
    if(!toBase64(outsize, outBuf, &strSize, szOut)) {
        fprintf(g_logFile, "Seal: Cant base64 encode sealed data\n");
        return false;
    }
    *pszDataOut= strdup(szOut); 
    return true;
}


bool Unseal(const char* szKeyFile, bool fPublic, const char* szDataIn, const char** pszDataOut)
{
    RSAKey* pKey= (RSAKey*)ReadKeyfromFile(szKeyFile);
    if(pKey==NULL) {
        fprintf(g_logFile, "Sign: Can't get key from keyfile %s\n", szKeyFile);
        return false;
    }
    byte    inBuf[4096];
    byte    outBuf[4096];
    int     size= 4096;
    int     outsize= 4096;
    int     strSize= 4096;
    char    szOut[4096];

    if(!fromBase64(strlen(szDataIn), szDataIn, &size, inBuf)) {
        fprintf(g_logFile, "Unseal: Cant base64 decode sealed data\n");
        return false;
    }
    PrintBytes((char*)"Sealed data: ", inBuf, size);
    u32     keyUse= USEPUBLIC;
    if(fPublic)
        keyUse= USEPUBLIC;
    else
        keyUse= USEPRIVATE;

    if(!RSAUnseal(*pKey, keyUse, size, inBuf, &outsize, outBuf)) {
        fprintf(g_logFile, "Unseal: Cant RSAUnseal\n");
        return false;
    }
    PrintBytes((char*)"Unsealed data: ", outBuf, outsize);
    if(!toBase64(outsize, outBuf, &strSize, szOut)) {
        fprintf(g_logFile, "Unseal: Cant base64 encode sealed data\n");
        return false;
    }
    *pszDataOut= strdup(szOut); 
    return true;
}


#define BUFSIZE       2048
#define BYTESPERLINE    16


bool MakePolicyFile(const char* szKeyFile, const char* szOutFile, const char* szProgramName)
{
    int         i, n;
    int         iToRead;
    char        rgszBuf[BUFSIZE];
    struct stat statBlock;

    if(szKeyFile==NULL || szOutFile==NULL) {
        fprintf(g_logFile, "Error: null file name\n");
        return false;
    }
    int iRead = open(szKeyFile, O_RDONLY);
    if(iRead<0) {
        fprintf(g_logFile, "Can't open input file %s\n", szKeyFile);
        return false;
    }
    FILE* out= fopen(szOutFile,"w");
    if(out==NULL) {
        fprintf(g_logFile, "Can't open output file %s\n", szOutFile);
        return false;
    }

    if(stat(szKeyFile, &statBlock)<0) {
        fprintf(g_logFile, "Can't stat input file\n");
        return false;
    }

    int iFileSize= statBlock.st_size;
    int iLeft= iFileSize;

    fprintf(out, "\n// Policy Cert\n\n");
    fprintf(out, "char    g_szXmlPolicyCert[%d]= {", iFileSize+1);  // we'll add a 0 byte
    while(iLeft>0) {
        if(iLeft<BUFSIZE)
            iToRead= iLeft;
        else
            iToRead= BUFSIZE;

        n= read(iRead, rgszBuf, iToRead);
        if(n<0) {
            fprintf(g_logFile, "Unexpected file end\n");
            break;
        }
        iLeft-= n;
        for(i=0; i<n; i++) {
            if((i%BYTESPERLINE)==0)
                fprintf(out, "\n    ");
            fprintf(out, "0x%02x,", rgszBuf[i]);
            
        }
    }
    fprintf(out, "0x00\n};\n\n");
    fprintf(out, "\nint    g_szpolicykeySize= %d;\n\n", iFileSize+1);
    fprintf(out, "\nint    g_szProgramNameSize= %d;\n", (int) strlen(szProgramName)+1);
    fprintf(out, "\nchar*  g_szProgramName= \"%s\";\n\n", szProgramName);
    
    fclose(out);
    close(iRead);

    return true;
}


bool AES128CBCHMACSHA256SYMPADEncryptFile (int filesize, int iRead, int iWrite, 
                        u8* enckey, u8* intkey)
{
    cbc     oCBC;
    int     fileLeft= filesize;
    u8      iv[AES128BYTEBLOCKSIZE];
    u8      rgBufIn[4*AES128BYTEBLOCKSIZE];
    u8      rgBufOut[4*AES128BYTEBLOCKSIZE];

#ifdef TEST
    fprintf(g_logFile, "CBCEncrypt\n");
#endif
    // init iv
    if(!getCryptoRandom(AES128BYTEBLOCKSIZE*NBITSINBYTE, iv)) {
        fprintf(g_logFile, "Cant generate iv\n");
        return false;
    }

    // init 
    if(!oCBC.initEnc(AES128, SYMPAD, HMACSHA256, AES128BYTEKEYSIZE, enckey, AES128BYTEKEYSIZE, 
                     intkey, filesize, AES128BYTEBLOCKSIZE, iv))
        return false;

    // get and send first cipher block
    oCBC.firstCipherBlockOut(rgBufOut);
    if(write(iWrite, rgBufOut, AES128BYTEBLOCKSIZE)<0) {
        fprintf(g_logFile, "AES128CBCHMACSHA256SYMPADEncryptFile: bad write\n");
        return false;
    }

    // read, encrypt, and copy bytes
    while(fileLeft>AES128BYTEBLOCKSIZE) {
        if(read(iRead, rgBufIn, AES128BYTEBLOCKSIZE)<0) {
            fprintf(g_logFile, "bad read\n");
            return false;
        }
        oCBC.nextPlainBlockIn(rgBufIn, rgBufOut);
        if(write(iWrite, rgBufOut, AES128BYTEBLOCKSIZE)<0) {
            fprintf(g_logFile, "bad write\n");
            return false;
        }
        fileLeft-= AES128BYTEBLOCKSIZE;
    }

    // final block
    if(read(iRead, rgBufIn, fileLeft)<0) {
        fprintf(g_logFile, "AES128CBCHMACSHA256SYMPADEncryptFile: bad read\n");
        return false;
    }
    int n= oCBC.lastPlainBlockIn(fileLeft, rgBufIn, rgBufOut);
    if(n<0)
        return false;

    // write final encrypted blocks and HMAC
    if(write(iWrite, rgBufOut, n)<0) {
        fprintf(g_logFile, "bad write\n");
        return false;
    }

    return true;
}


bool AES128CBCHMACSHA256SYMPADDecryptFile (int filesize, int iRead, int iWrite,
                         u8* enckey, u8* intkey)
{
    cbc     oCBC;
    int     fileLeft= filesize;
    u8      rgBufIn[4*AES128BYTEBLOCKSIZE];
    u8      rgBufOut[4*AES128BYTEBLOCKSIZE];

#ifdef TEST
    fprintf(g_logFile, "CBCDecrypt\n");
#endif
    // init 
    if(!oCBC.initDec(AES128, SYMPAD, HMACSHA256, AES128BYTEKEYSIZE, enckey, AES128BYTEKEYSIZE, 
                     intkey, filesize))
        return false;

    // get and send first cipher block
    if(read(iRead, rgBufIn, AES128BYTEBLOCKSIZE)<0) {
            fprintf(g_logFile, "bad read\n");
            return false;
        }
    oCBC.firstCipherBlockIn(rgBufIn);
    fileLeft-= AES128BYTEBLOCKSIZE;

    // read, decrypt, and write bytes
    while(fileLeft>3*AES128BYTEBLOCKSIZE) {
        if(read(iRead, rgBufIn, AES128BYTEBLOCKSIZE)<0) {
            fprintf(g_logFile, "bad read\n");
            return false;
        }
        oCBC.nextCipherBlockIn(rgBufIn, rgBufOut);
        if(write(iWrite, rgBufOut, AES128BYTEBLOCKSIZE)<0) {
            fprintf(g_logFile, "bad write\n");
            return false;
        }
        fileLeft-= AES128BYTEBLOCKSIZE;
    }

    // final blocks
    if(read(iRead, rgBufIn, fileLeft)<0) {
            fprintf(g_logFile, "bad read\n");
            return false;
        }
    int n= oCBC.lastCipherBlockIn(fileLeft, rgBufIn, rgBufOut);
    if(n<0)
        return false;

    // write final decrypted bytes
    if(write(iWrite, rgBufOut, n)<0) {
        fprintf(g_logFile, "bad write\n");
        return false;
    }

    return oCBC.validateMac();
}


bool Encrypt(u32 op, const char* szKeyFile, const char* szInFile, const char* szOutFile, u32 mode=CBCMODE, 
             u32 alg=AES128, u32 pad=SYMPAD, u32 mac=HMACSHA256)
{
    u8          rguEncKey[BIGSYMKEYSIZE];
    u8          rguIntKey[BIGSYMKEYSIZE];

    if(op==ENCRYPTFILE)
        fprintf(g_logFile, "Encrypt (%s, %s, %s)\n", szKeyFile, szInFile, szOutFile);
    else
        fprintf(g_logFile, "Decrypt (%s, %s, %s)\n", szKeyFile, szInFile, szOutFile);
    if(mode==CBCMODE)
        fprintf(g_logFile, "CBC Mode\n");
    else
        fprintf(g_logFile, "GCM Mode\n");

    memset(rguEncKey , 0, BIGSYMKEYSIZE);
    memset(rguIntKey , 0, BIGSYMKEYSIZE);

    // Get File size
    struct stat statBlock;
    if(stat(szInFile, &statBlock)<0) {
        fprintf(g_logFile, "Can't stat input file\n");
        return false;
    }
    int fileSize= statBlock.st_size;

    int iRead= open(szInFile, O_RDONLY);
    if(iRead<0) {
        fprintf(g_logFile, "Can't open read file\n");
        return false;
    }

    int iWrite= open(szOutFile, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if(iWrite<0) {
        fprintf(g_logFile, "Can't open write file\n");
        return false;
    }

    int iKey= open(szKeyFile, O_RDONLY);
    if(iKey<0) {
        fprintf(g_logFile, "Can't open Key file\n");
        return false;
    }
    if(read(iKey, rguEncKey, AES128BYTEKEYSIZE)<0) {
            fprintf(g_logFile, "bad read\n");
            return false;
        }
    if(mode==CBCMODE)
        if(read(iKey, rguIntKey, AES128BYTEKEYSIZE)<0) {
            fprintf(g_logFile, "bad read\n");
            return false;
        }
    close(iKey);

    bool fRet= false;

    if(op==ENCRYPTFILE && alg==AES128 && mode==CBCMODE && mac==HMACSHA256 && pad==SYMPAD)
        fRet= AES128CBCHMACSHA256SYMPADEncryptFile(fileSize, iRead, iWrite, 
                     rguEncKey, rguIntKey);
    else if(op==DECRYPTFILE && alg==AES128 && mode==CBCMODE && mac==HMACSHA256 && pad==SYMPAD)
        fRet= AES128CBCHMACSHA256SYMPADDecryptFile(fileSize, iRead, iWrite, 
                     rguEncKey, rguIntKey);
#ifdef GCMENABLED
    else if(op==ENCRYPTFILE && alg==AES128 && mode==GCMMODE)
        fRet= AES128GCMEncryptFile(fileSize, iRead, iWrite, rguEncKey);
    else if(op==DECRYPTFILE && alg==AES128 && mode==GCMMODE)
        fRet= AES128GCMDecryptFile(fileSize, iRead, iWrite, rguEncKey);
#endif
    else
        fRet= false;
    
    close(iRead);
    close(iWrite);
    memset(rguEncKey , 0, BIGSYMKEYSIZE);
    memset(rguIntKey , 0, BIGSYMKEYSIZE);

#ifdef TEST
    if(fRet)
        fprintf(g_logFile, "Encrypt/Decrypt returns true\n");
    else
        fprintf(g_logFile, "Encrypt/Decrypt returns false\n");
#endif
    return fRet;
}


void  GetTime()
{
    time_t      timer;

    time(&timer);
    // 1997-07-16T19:20:30.45+01:00
    struct tm*  pgmtime= gmtime((const time_t*)&timer);
    char* szTime= stringtimefromtimeInfo(pgmtime);
    fprintf(g_logFile,  "The current date/time is: %s\n", szTime);

    return;
}


inline byte fromHextoVal(char a, char b)
{
    byte x= 0;

    if(a>='a' && a<='f')
        x= (((byte) (a-'a')+10)&0xf)<<4;
    else if(a>='A' && a<='F')
        x= (((byte) (a-'A')+10)&0xf)<<4;
    else
        x= (((byte) (a-'0'))&0xf)<<4;

    if(b>='a' && b<='f')
        x|= ((byte) (b-'a')+10)&0xf;
    else if(b>='A' && b<='F')
        x|= ((byte) (b-'A')+10)&0xf;
    else
        x|= ((byte) (b-'0'))&0xf;

    return x;
}


int MyConvertFromHexString(const char* szIn, int iSizeOut, byte* rgbBuf)
{
    char    a, b;
    int     j= 0;

    while(*szIn!=0) {
        if(*szIn=='\n' || *szIn==' ') {
            szIn++;
            continue;
        }
        a= *(szIn++);
        b= *(szIn++);
        if(a==0 || b==0)
            break;
        rgbBuf[j++]= fromHextoVal(a, b);
    }
    return j;
}

const char* g_aikTemplate=
"<ds:SignedInfo>\n" \
"    <ds:CanonicalizationMethod Algorithm=\"http://www.manferdelli.com/2011/Xml/canonicalization/tinyxmlcanonical#\" />\n" \
"    <ds:SignatureMethod Algorithm=\"http://www.manferdelli.com/2011/Xml/algorithms/rsa1024-sha256-pkcspad#\" />\n" \
"    <Certificate Id='%s' version='1'>\n" \
"        <SerialNumber>20110930001</SerialNumber>\n" \
"        <PrincipalType>Hardware</PrincipalType>\n" \
"        <IssuerName>manferdelli.com</IssuerName>\n" \
"        <IssuerID>manferdelli.com</IssuerID>\n" \
"        <ValidityPeriod>\n" \
"            <NotBefore>2011-01-01Z00:00.00</NotBefore>\n" \
"            <NotAfter>2021-01-01Z00:00.00</NotAfter>\n" \
"        </ValidityPeriod>\n" \
"        <SubjectName>//www.manferdelli.com/Keys/attest/0001</SubjectName>\n" \
"        <SubjectKey>\n" \
"<ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" " \
"            KeyName=\"%s\">\n" \
"    <KeyType>RSAKeyType</KeyType>\n" \
"    <ds:KeyValue>\n" \
"        <ds:RSAKeyValue size='%d'>\n" \
"            <ds:M>%s</ds:M>\n" \
"            <ds:E>AAAAAAABAAE=</ds:E>\n" \
"        </ds:RSAKeyValue>\n" \
"    </ds:KeyValue>\n" \
"</ds:KeyInfo>\n" \
"        </SubjectKey>\n" \
"        <SubjectKeyID>%s</SubjectKeyID>\n" \
"        <RevocationPolicy>Local-check-only</RevocationPolicy>\n" \
"    </Certificate>\n" \
"</ds:SignedInfo>\n" ;

// Cert ID
// Key name
// M
// Subject Key id


// --------------------------------------------------------------------- 



bool SignHexModulus(const char* szKeyFile, const char* szInFile, const char* szOutFile)
{
    bool        fRet= true;
    TiXmlNode*  pNode= NULL;
    RSAKey*     pRSAKey= NULL;
    char        rgBase64[1024];
    int         size= 1024;
    char*       szToHash= NULL;
    char        szSignedInfo[4096];

    fprintf(g_logFile, "SignHexModulus(%s, %s, %s)\n", szKeyFile, szInFile, szOutFile);
    char* modString= readandstoreString(szInFile); 
    if(modString==NULL) {
        fprintf(g_logFile, "Couldn't open modulusfile %s\n", szInFile);
        return false;
    }

    byte    modHex[1024];
    int     modSize=  MyConvertFromHexString(modString, 1024, modHex);
    PrintBytes("\nmodulus\n", modHex, modSize);

    if(szKeyFile==NULL) {
        fprintf(g_logFile, "No Key file\n");
        return false;
    }
    if(szInFile==NULL) {
        fprintf(g_logFile, "No Input file\n");
        return false;
    }
    if(szOutFile==NULL) {
        fprintf(g_logFile, "No Output file\n");
        return false;
    }

    try {

        pRSAKey= (RSAKey*)ReadKeyfromFile(szKeyFile);
        if(pRSAKey==NULL)
            throw "Cant open Keyfile\n";
        if(((KeyInfo*)pRSAKey)->m_ukeyType!=RSAKEYTYPE) {
            delete (KeyInfo*) pRSAKey;
            pRSAKey= NULL;
            throw "Wrong key type for signing\n";
        }

        fprintf(g_logFile, "\n");
        pRSAKey->printMe();
        fprintf(g_logFile, "\n");

        // construct key XML from modulus
        const char*   szCertid= "www.manferdelli.com/certs/000122";
        const char*   szKeyName= "Gauss-AIK-CERT";
        byte    revmodHex[1024];

        revmemcpy(revmodHex, modHex, modSize);
        if(!toBase64(modSize, revmodHex, &size, rgBase64))
            throw "Cant base64 encode modulus value\n";

        const char*   szKeyId= "/Gauss/AIK";
        int     iNumBits= ((size*6)/1024)*1024;

        sprintf(szSignedInfo, g_aikTemplate, szCertid, 
                szKeyName, iNumBits, rgBase64, szKeyId);

        // read input file
        TiXmlDocument toSignDoc;
        if(!toSignDoc.Parse(szSignedInfo))
            throw "Can't parse signed info\n";
        
        pNode= Search(toSignDoc.RootElement(), "ds:SignedInfo");
        if(pNode==NULL) {
            fprintf(g_logFile, "Can't find SignedInfo\n");
            return false;
        }

        // Canonicalize
        szToHash= canonicalize(pNode);
        if(szToHash==NULL) 
            throw "Can't canonicalize\n";

        char* szSignature= constructXMLRSASha256SignaturefromSignedInfoandKey(*pRSAKey,
                                                szKeyId, szToHash);
        if(szSignature==NULL) {
            fprintf(g_logFile, "Can't construct signature\n");
            return false;
        }
        if(!saveBlobtoFile(szOutFile, (byte*)szSignature, strlen(szSignature)+1))
            return false;

#ifdef TEST
        fprintf(g_logFile, "Signature written\n");
#endif
    }
    catch(const char* szError) {
        fRet= false;
        fprintf(g_logFile, "Sign error: %s\n", szError);
    }

    if(szToHash!=NULL) {
        free(szToHash);
        szToHash= NULL;
    }
    if(pRSAKey!=NULL) {
        delete pRSAKey;
        pRSAKey= NULL;
    }

    return fRet;
}


// --------------------------------------------------------------------- 


bool VerifyQuote(const char* szQuoteFile, const char* szCertFile)
{
    Quote           oQuote;
    PrincipalCert   oCert;
    char* szCertString= readandstoreString(szCertFile);
    char* szQuoteString= readandstoreString(szQuoteFile);

#ifdef TEST
    fprintf(g_logFile, "VerifyQuote: quoteFile: %s, certFile: %s\n",
            szQuoteFile, szCertFile);
    fflush(g_logFile);
#endif

    // get and parse Quote
    if(szQuoteFile==NULL) {
        fprintf(g_logFile, "VerifyQuote: Can't cant read quote file %s\n", szQuoteFile);
        return false;
    }
    if(!oQuote.init(szQuoteString)) {
        fprintf(g_logFile, "VerifyQuote: Can't parse quote\n");
        return false;
    }

    // get and parse Cert
    if(szCertFile==NULL) {
        fprintf(g_logFile, "VerifyQuote: Can't cant read cert file %s\n", szCertFile);
        return false;
    }
    if(!oCert.init(szCertString)) {
        fprintf(g_logFile, "VerifyQuote: Can't parse cert\n");
        return false;
    }

    // decode request
    char* szAlg= oQuote.getQuoteAlgorithm();
    char* szQuotedInfo= oQuote.getCanonicalQuoteInfo();
    char* szQuoteValue= oQuote.getQuoteValue();
    char* sznonce= oQuote.getnonceValue();
    char* szDigest= oQuote.getcodeDigest();

    if(!oCert.parsePrincipalCertElements()) {
        fprintf(g_logFile, "VerifyQuote: Can't get principal cert elements\n");
        return false;
    }

    // check quote
    RSAKey* pAIKKey= (RSAKey*) oCert.getSubjectKeyInfo();
    if(pAIKKey==NULL) {
        fprintf(g_logFile, "VerifyQuote: Cant get quote keyfromkeyInfo\n");
        return false;
    }

    fprintf(g_logFile, "Quote key size: %d\n", pAIKKey->m_iByteSizeM);
    fprintf(g_logFile, "Quote Algorithm: %s\n", szAlg);
    fprintf(g_logFile, "Quote:\n%s\n\n", szQuoteString);
    fprintf(g_logFile, "Quoted value:\n%s\n\n", szQuotedInfo);
    fprintf(g_logFile, "AttestCert:\n%s\n\n", szCertString);
    
    return checkXMLQuote(szAlg, szQuotedInfo, sznonce,
                          szDigest, pAIKKey, szQuoteValue);
}

bool Quote(const char* szKeyFile, const char* sztoQuoteFile, const char* szMeasurementFile)
{
    int     hostedMeasurementSize;
    byte    hostedMeasurement[64];
    int     sizetoAttest;
    byte    toAttest[64];
    int     sizeAttested;
    byte    attest[4096];
    int     sizenewattest= 2048;
    char    newattest[2048];

    char*   szToQuote= readandstoreString(sztoQuoteFile);
    char*   szMeasurement= readandstoreString(szMeasurementFile);
    RSAKey* pKey= (RSAKey*) ReadKeyfromFile(szKeyFile);

#ifdef TEST
    fprintf(g_logFile, "Quote\n");
    fflush(g_logFile);
#endif

    if(szToQuote==NULL) {
        fprintf(g_logFile, "Cant read quote file %s\n", szToQuote);
        return false;
    }
    if(szMeasurement==NULL) {
        fprintf(g_logFile, "Cant read measurement file %s\n", szMeasurement);
        return false;
    }
    if(pKey==NULL) {
        fprintf(g_logFile, "Couldn't get private key from %s\n", szKeyFile);
        return false;
    }

    fprintf(g_logFile, "Quote: %s\n", szToQuote);
    fprintf(g_logFile, "Measurement: %s\n", szMeasurement);
    szMeasurement[strlen(szMeasurement)-1]= 0;
    PrintBytes((char*)"string: ", (byte*)szMeasurement, strlen(szMeasurement));

    hostedMeasurementSize= 64;
    if(!fromBase64(strlen(szMeasurement), szMeasurement, &hostedMeasurementSize, hostedMeasurement)) {
        fprintf(g_logFile, "Cant base64 decode measurement\n");
        return false;
    }
    PrintBytes((char*)"Code Digest: ", hostedMeasurement, hostedMeasurementSize);

    byte        rgQuotedHash[SHA256DIGESTBYTESIZE];
    byte        rgToSign[512];
    Sha256      oHash;

    // compute quote hash
    oHash.Init();
    oHash.Update((byte*) szToQuote, strlen(szToQuote));
    oHash.Final();
    oHash.GetDigest(toAttest);

    // Compute quote
    sizetoAttest= SHA256_DIGESTSIZE_BYTES;
    PrintBytes((char*)"To attest: ", toAttest, sizetoAttest);
    if(!sha256quoteHash(0, NULL, sizetoAttest, toAttest, hostedMeasurementSize,
                        hostedMeasurement, rgQuotedHash)) {
            fprintf(g_logFile, "Cant compute sha256 quote hash\n");
            return false;
        }
    // pad
    if(!emsapkcspad(SHA256HASH, rgQuotedHash, pKey->m_iByteSizeM, rgToSign)) {
        fprintf(g_logFile, "emsapkcspad returned false\n");
        return false;
    }
    PrintBytes((char*)"Padded: ", rgToSign, pKey->m_iByteSizeM);

    // sign
    bnum    bnMsg(pKey->m_iByteSizeM/sizeof(u64)+2);
    bnum    bnOut(pKey->m_iByteSizeM/sizeof(u64)+2);
    memset(bnMsg.m_pValue, 0, pKey->m_iByteSizeM);
    memset(bnOut.m_pValue, 0, pKey->m_iByteSizeM);
    revmemcpy((byte*)bnMsg.m_pValue, rgToSign, pKey->m_iByteSizeM);

   if(!mpRSAENC(bnMsg, *(pKey->m_pbnD), *(pKey->m_pbnM), bnOut)) {
        fprintf(g_logFile, "mpRSAENC returned false\n");
        return false;
    }

    revmemcpy(attest, (byte*)bnOut.m_pValue, pKey->m_iByteSizeM);
    sizeAttested= pKey->m_iByteSizeM;
    PrintBytes((char*)"Quote value: ", attest, sizeAttested);
    if(!toBase64(sizeAttested, attest, &sizenewattest, newattest)) {
        fprintf(g_logFile, "can't base64 encode attest\n");
        return false;
    }
    fprintf(g_logFile, "Quote string\n%s\n", newattest);

    mpZeroNum(bnMsg);
    mpZeroNum(bnOut);
    byte rgdecrypted[4096];
    revmemcpy((byte*)bnMsg.m_pValue, attest, pKey->m_iByteSizeM);

   if(!mpRSAENC(bnMsg, *(pKey->m_pbnE), *(pKey->m_pbnM), bnOut)) {
        fprintf(g_logFile, "mpRSAENC returned false\n");
        return false;
    }
    revmemcpy(rgdecrypted, (byte*)bnOut.m_pValue, pKey->m_iByteSizeM);
    PrintBytes((char*)"Decrypted\n", rgdecrypted, pKey->m_iByteSizeM);

    return true;
}

bool QuoteTest(const char* szKeyFile, const char* szInFile)
{
    char* keyString= readandstoreString(szKeyFile); 
    char* quoteString= readandstoreString(szInFile); 
    if(keyString==NULL) {
        fprintf(g_logFile, "Couldn't open key file %s\n", szKeyFile);
        return false;
    }
    if(quoteString==NULL) {
        fprintf(g_logFile, "Couldn't open quote file %s\n", szInFile);
        return false;
    }
    byte    keyHex[1024];
    int     keySize=   MyConvertFromHexString(keyString, 1024, keyHex);
    byte    quoteHex[1024];
    int     quoteSize=  MyConvertFromHexString(quoteString, 1024, quoteHex);

    fprintf(g_logFile, "keySize: %d, quoteSize: %d\n\n", keySize, quoteSize);
    PrintBytes("\nkey", keyHex, keySize);
    PrintBytes("\nquote", quoteHex, quoteSize);

    bnum  bnM(32);
    bnum  bnC(32);
    bnum  bnE(2);
    bnum  bnR(32);

    int     i;
    byte*   pB; 
    byte*   pA;

    pA= (byte*) bnM.m_pValue;
    for(i=(keySize-1); i>=0; i--) {
        pB= &keyHex[i];
        *(pA++)= *pB;
    }

    pA= (byte*) bnC.m_pValue;
    for(i=(quoteSize-1); i>=0; i--) {
        pB= &quoteHex[i];
        *(pA++)= *pB;
    }
    bnE.m_pValue[0]= 0x10001ULL;

    fprintf(g_logFile, "\nM: "); printNum(bnM); printf("\n");
    fprintf(g_logFile, "\nC: "); printNum(bnC); printf("\n");
    fprintf(g_logFile, "\nE: "); printNum(bnE); printf("\n");

    if(!mpRSAENC(bnC, bnE, bnM, bnR))
        fprintf(g_logFile, "\nENC fails\n");
    else
        fprintf(g_logFile, "\nENC succeeds\n");
    fprintf(g_logFile, "\nR: "); printNum(bnR); printf("\n");

    fprintf(g_logFile, "\n\nreturning\n");
    
    return true;
}


// --------------------------------------------------------------------- 


bool Encapsulate(const char* szCert, const char* szMetaDataFile, 
                 const char* szInFile, const char* szOutFile)
{
    encapsulatedMessage  oM;
    byte                 plain[4096];   // stat and allocate later
    int                  plainsize= 4096;
    char*                szEncapsulateKeyInfo= NULL;
    RSAKey*              sealingKey= NULL;
    bool                 fRet= true;

    if(szCert==NULL) {
        fprintf(g_logFile, "Encapsulate: no certificate\n");
        fRet= false;
        goto done;
    }
    oM.m_szCert= strdup(szCert);

    // get key from Cert
    szEncapsulateKeyInfo= oM.getSubjectKeyInfo();
    if(szEncapsulateKeyInfo==NULL) {
        fprintf(g_logFile, "Encapsulate: cant extract sealing key from %s\n", oM.m_szCert);
        fRet= false;
        goto done;
    }

    // Make RSAKey
    sealingKey= (RSAKey*)RSAKeyfromkeyInfo(szEncapsulateKeyInfo);
    if(sealingKey==NULL) {
        fprintf(g_logFile, "Encapsulate: cant parse key\n");
        fRet= false;
        goto done;
    }

    // get plaintext and encrypt
    if(!getBlobfromFile(szInFile, plain, &plainsize)) {
        fprintf(g_logFile, "Encapsulate: cant read: %s\n", szInFile);
        fRet= false;
        goto done;
    }
    if(!oM.setplainMessage(plainsize, plain)) {
        fprintf(g_logFile, "Encapsulate: cant set plaintext\n");
        fRet= false;
        goto done;
    }

    // seal key
    if(!oM.sealKey(sealingKey)) {
        fprintf(g_logFile, "Encapsulate: cant seal key\n");
        fRet= false;
        goto done;
    }

    if(!oM.encryptMessage()) {
        fprintf(g_logFile, "Encapsulate: cant encrypt message\n");
        fRet= false;
        goto done;
    }

    // serialize metadata
    oM.m_szXMLmetadata= oM.serializeMetaData();
    if(oM.m_szXMLmetadata==NULL) {
        fprintf(g_logFile, "Encapsulate: cant serialize metadata\n");
        fRet= false;
        goto done;
    }

    // write metadata
    if(!saveBlobtoFile(szMetaDataFile, (byte*)oM.m_szXMLmetadata, strlen(oM.m_szXMLmetadata)+1)) {
        fprintf(g_logFile, "Encapsulate: cant write metadata %s\n", oM.m_szXMLmetadata);
        fRet= false;
        goto done;
    }

    // write encrypted data
    if(!saveBlobtoFile(szOutFile, oM.m_rgEncrypted, oM.m_sizeEncrypted)) {
        fprintf(g_logFile, "Encapsulate: cant write encrypted data to %s\n", szOutFile);
        fRet= false;
        goto done;
    }

done:
#ifdef TEST
    oM.printMe();
#endif
    if(szEncapsulateKeyInfo!=NULL) {
        free(szEncapsulateKeyInfo);
        szEncapsulateKeyInfo= NULL;
    }
    if(sealingKey!=NULL) {
        delete sealingKey;
        sealingKey= NULL;
    }
    return fRet;
}


bool Decapsulate(const char* szKeyInfo, const char* szMetaDataFile, 
                 const char* szInFile, const char* szOutFile)
{
    encapsulatedMessage  oM;
    byte                 cipher[4096];   // stat and allocate later
    int                  ciphersize= 4096;
    RSAKey*              sealingKey= NULL;
    bool                 fRet= true;
    char                 szMetadata[4096];
    int                  sizemetadata= 4096;

    if(szKeyInfo==NULL) {
        fprintf(g_logFile, "Decapsulate: no keyinfo\n");
        fRet= false;
        goto done;
    }

    // Make RSAKey
    sealingKey= (RSAKey*)RSAKeyfromkeyInfo(szKeyInfo);
    if(sealingKey==NULL) {
        fprintf(g_logFile, "Decapsulate: cant parse key\n");
        fRet= false;
        goto done;
    }

    // get metadata
    if(!getBlobfromFile(szMetaDataFile, (byte*)szMetadata, &sizemetadata)) {
        fprintf(g_logFile, "Encapsulate: cant read metadata: %s\n", szMetaDataFile);
        fRet= false;
        goto done;
    }
    oM.m_szXMLmetadata= strdup(szMetadata);

    // get ciphertext and decrypt
    if(!getBlobfromFile(szInFile, cipher, &ciphersize)) {
        fprintf(g_logFile, "Decapsulate: cant read: %s\n", szInFile);
        fRet= false;
        goto done;
    }
    if(!oM.setencryptedMessage(ciphersize, cipher)) {
        fprintf(g_logFile, "Decapsulate: cant set ciphertext\n");
        fRet= false;
        goto done;
    }

    // parse metadata
    if(!oM.parseMetaData()) {
        fprintf(g_logFile, "Decapsulate: cant parse metadata\n");
        fRet= false;
        goto done;
    }

    // unseal key
    if(!oM.unSealKey(sealingKey)) {
        fprintf(g_logFile, "Decapsulate: cant unseal key\n");
        fRet= false;
        goto done;
    }

    if(!oM.decryptMessage()) {
        fprintf(g_logFile, "Decapsulate: cant decrypt message\n");
        fRet= false;
        goto done;
    }

    // write plain data
    if(!saveBlobtoFile(szOutFile, oM.m_rgPlain, oM.m_sizePlain)) {
        fprintf(g_logFile, "Decapsulate: cant write decrypted data to %s\n", szOutFile);
        fRet= false;
        goto done;
    }

done:
#ifdef TEST
    oM.printMe();
#endif
    if(sealingKey!=NULL) {
        delete sealingKey;
        sealingKey= NULL;
    }
    return fRet;
}


bool validateChain(const char* szKeyString, const char* szInFile)
{
    evidenceList    oEvidence;
    RSAKey*         pKey= RSAKeyfromkeyInfo(szKeyString);
    const char*     szEvidenceList= readandstoreString(szInFile);

    if(szEvidenceList==NULL) {
        fprintf(g_logFile, "validateChain: can't read evidence list\n");
        return false;
    }
    if(!oEvidence.m_doc.Parse(szEvidenceList)) {
        fprintf(g_logFile, "validateChain: can't parse evidence list \n");
        return false;
    }
    oEvidence.m_fDocValid= true;
    oEvidence.m_pRootElement= oEvidence.m_doc.RootElement();
    if(!oEvidence.validateEvidenceList(pKey)) {
        fprintf(g_logFile, "validateChain: validate evidence list fails\n");
        return false;
    }
    return true;
}


bool  parseReq(const char* szReq, accessRequest* pReq)
{
    return false;
}


bool  parsePrincpals(const char* szPrincipals, int* pnumPrincipals, PrincipalCert*** pppCerts)
{
    return false;
}


bool  parseMetaData(const char* szMeta, metaData& meta)
{
    /*
     *  addResource(resource* pResource);
     *  resource*           findResource(const char* szName);
     *  bool                addPrincipal(accessPrincipal* pPrin);
     *  PrincipalCert*      findPrincipal(const char* szName);
     */
    return false;
}


bool validateAssertion(const char* szKey, const char* szReq, const char* szCollection, 
                       const char* szPrincipals, const char* szMeta)
{
    metaData            oMeta;
    accessGuard         guard;
    RSAKey*             pKey= RSAKeyfromkeyInfo(szKey);
    accessRequest       req;
    int                 numPrincipals= 0;
    PrincipalCert**     rgCerts= NULL;
    int                 i;

    if(szCollection==NULL|| szKey==NULL || szReq==NULL) {
        fprintf(g_logFile, "validateAssertion: missing key data\n");
        return false;
    }

    oMeta.m_metaDataValid= true;
    oMeta.m_fEncryptFile= true;

    // initialize principals
    if(!parsePrincpals(szPrincipals, &numPrincipals, &rgCerts)) {
        fprintf(g_logFile, "validateAssertion: can't parse principals\n");
        return false;
    }

    for(i=0; i<numPrincipals; i++) {
        if(!oMeta.addPrincipal(rgCerts[i])) {
                fprintf(g_logFile, "validateAssertion: can't add principals\n");
                return false;
        }
    }

    // initialize metadata
    if(!parseMetaData(szMeta, oMeta)) {
        fprintf(g_logFile, "validateAssertion: can't parse metadata\n");
        return false;
    }

    // parse request
    if(!parseReq(szReq, &req)) {
        fprintf(g_logFile, "validateAssertion: can't parse reqs\n");
        return false;
    }

    // initialize guard
    if(!guard.initGuard(pKey, &oMeta)) {
        fprintf(g_logFile, "validateAssertion: can't initialize metadata\n");
        return false;
    }

    // collect chidren of root for permit access
    if(!guard.permitAccess(req, szCollection)) {
        fprintf(g_logFile, "validateAssertion: access NOT permitted\n");
        return false;
    }
    fprintf(g_logFile, "validateAssertion: access permitted\n");
    return true;
}


// --------------------------------------------------------------------- 


//  -GenKey keytype outputfile
//  -Sign keyfile algname inputfile outputfile
//  -Verify keyfile inputfile 
//  -Hash algname inputfile outputfile
//  -Canonical inputfile outputfile 
//  -PolicyCert certFile outputfile
//  -Encrypt   keyFile inputfile outputfile
//  -Decrypt   keyFile inputfile outputfile
//  -HashquoteTest keyFile inputFile


int main(int an, char** av)
{
    const char*   szInFile= NULL;
    const char*   szKeyType= NULL;
    const char*   szOutFile= NULL;
    const char*   szAlgorithm= NULL;
    const char*   szKeyFile= NULL;
    const char*   szMetaDataFile= NULL;
    const char*   szReqFile= NULL;
    const char*   szPrincipalsFile= NULL;
    const char*   szMeasurementFile= NULL;
    const char*   szDataIn= NULL;
    const char*   szDataOut= NULL;
    const char*   szProgramName=  "Program no name";
    bool          fPublic= true;
    int           numArgs= 0;
    char**        pszArgs= NULL;
    int           iAction= NOACTION;
    int           mode= CBCMODE;
    bool          fRet;
    int           i;

    for(i=0; i<an; i++) {
        if(strcmp(av[i], "-help")==0) {
            fprintf(g_logFile, "\nUsage: cryptUtility -GenKey keytype outputfile\n");
            fprintf(g_logFile, "       cryptUtility -GenCertSignedInfo keyfile ");
                fprintf(g_logFile, " -SerialNumber SN");
                fprintf(g_logFile, " -PrincipalType [User|Program|Channel]");
                fprintf(g_logFile, " -IssuerName Name");
                fprintf(g_logFile, " -IssuerID ID");
                fprintf(g_logFile, " -SubjectName SN");
                fprintf(g_logFile, " -Period 2011-01-01Z00:00.00 2011-01-01Z00:00.00");
                fprintf(g_logFile, " -RevocationPolicy file");
                fprintf(g_logFile, " -SubjectKeyID ID");
                fprintf(g_logFile, " outputfile\n");
            fprintf(g_logFile, "       cryptUtility -Sign keyfile rsa1024-sha256-pkcspad inputfile outputfile\n");
            fprintf(g_logFile, "       cryptUtility -Verify keyfile inputfile\n");
            fprintf(g_logFile, "       cryptUtility -Canonical inputfile outputfile\n");
            fprintf(g_logFile, "       cryptUtility -PolicyCert certfile outputfile programname\n");
            fprintf(g_logFile, "       cryptUtility -Encrypt keyfile inputfile outputfile\n");
            fprintf(g_logFile, "       cryptUtility -Decrypt keyfile inputfile outputfile\n");
            fprintf(g_logFile, "       cryptUtility -Time \n");
#ifdef GCMENABLED
            fprintf(g_logFile, "       cryptUtility -TestGCM \n");
#endif
            fprintf(g_logFile, "       cryptUtility -HexquoteTest\n");
            fprintf(g_logFile, "       cryptUtility -SignHexModulus keyfile input-file output-file\n");
            fprintf(g_logFile, "       cryptUtility -HashFile input-file [alg]\n");
            fprintf(g_logFile, "       cryptUtility -makePolicyKeyFile input-file outputfile\n");
            fprintf(g_logFile, "       cryptUtility -makeServiceHashFile input-file outputfile\n");
            fprintf(g_logFile, "       cryptUtility -Quote quote-priv-key quote measurement\n");
            fprintf(g_logFile, "       cryptUtility -VerifyQuote xml-quote xml-aikcert\n");
            fprintf(g_logFile, "       cryptUtility -EncapsulateMessage xml-cert metadatafile inputfile outputfile\n");
            fprintf(g_logFile, "       cryptUtility -DecapsulateMessage xml-key metadata-file inputfile outputfile\n");
            fprintf(g_logFile, "       cryptUtility -validateChain rootKeyFile evidenceFile\n");
            fprintf(g_logFile, "       cryptUtility -Seal key-file -Public|-Private base64in\n");
            fprintf(g_logFile, "       cryptUtility -Unseal key-file -Public|-Private base64in\n");
            return 0;
        }
        if(strcmp(av[i], "-Canonical")==0) {
            if(an<(i+2)) {
                fprintf(g_logFile, "Too few arguments: input-file elementName\n");
                return 1;
            }
            szInFile= av[i+1];
            szOutFile= av[i+2];
            iAction= CANONICAL;
            break;
        }
        if(strcmp(av[i], "-GenKey")==0) {
            if(an<(i+3)) {
                fprintf(g_logFile, "Too few arguments: [AES128|RSA1024] output-file\n");
                return 1;
            }
            szKeyType= av[i+1];
            szOutFile= av[i+2];
            iAction= GENKEY;
            break;
        }
        if(strcmp(av[i], "-GenCertSignedInfo")==0) {
            i++;
            numArgs= an-i;
            pszArgs= &av[i];
            iAction= GENCERT;
            break;
        }
        if(strcmp(av[i], "-Sign")==0) {
            if(an<(i+4)) {
                fprintf(g_logFile, "Too few arguments: key-file rsa2048-sha256-pkcspad input-file output-file\n");
                return 1;
            }
            szKeyFile= av[i+1];
            szAlgorithm= av[i+2];
            szInFile= av[i+3];
            szOutFile= av[i+4];
            iAction= SIGN;
            break;
        }
        if(strcmp(av[i], "-Verify")==0) {
            if(an<(i+2)) {
                fprintf(g_logFile, "Too few arguments: key-file input-file\n");
                return 1;
            }
            szKeyFile= av[i+1];
            szInFile= av[i+2];
            iAction= VERIFY;
            break;
        }
        if(strcmp(av[i], "-PolicyCert")==0) {
            if(an<(i+3)) {
                fprintf(g_logFile, "Too few arguments: cert-file\n");
                return 1;
            }
            szKeyFile= av[i+1];
            szOutFile= av[i+2];
            szProgramName= av[i+3];
            iAction= MAKEPOLICYFILE;
            break;
        }
        if(strcmp(av[i], "-makePolicyKeyFile")==0) {
            if(an<(i+3)) {
                fprintf(g_logFile, "Too few arguments: key-file\n");
                return 1;
            }
            szKeyFile= av[i+1];
            szOutFile= av[i+2];
            szProgramName= av[i+3];
            iAction= MAKEPOLICYKEYFILE;
            break;
        }
        if(strcmp(av[i], "-Encrypt")==0) {
            if(an<(i+3)) {
                fprintf(g_logFile, "Too few arguments: key-file input-file output-file\n");
                return 1;
            }
            szKeyFile= av[i+1];
            szInFile= av[i+2];
            szOutFile= av[i+3];
            iAction= ENCRYPTFILE;
            if(an>(i+4) && strcmp(av[i+4],"gcm")==0)
                mode= CBCMODE;
            break;
        }
        if(strcmp(av[i], "-Decrypt")==0) {
            if(an<(i+3)) {
                fprintf(g_logFile, "Too few arguments: key-file input-file output-file\n");
                return 1;
            }
            szKeyFile= av[i+1];
            szInFile= av[i+2];
            szOutFile= av[i+3];
            iAction= DECRYPTFILE;
            if(an>(i+4) && strcmp(av[i+4],"gcm")==0)
                mode= CBCMODE;
            break;
        }
        if(strcmp(av[i], "-Time")==0) {
            iAction= TIMEREPORT;
            break;
        }

        if(strcmp(av[i], "-HashFile")==0) {
            iAction= HASHFILE;
            szInFile= av[i+1];
            szAlgorithm= "SHA256";
            break;
        }
        if(strcmp(av[i], "-makeServiceHashFile")==0) {
            iAction= MAKESERVICEHASHFILE;
            szInFile= av[i+1];
            szOutFile= av[i+2];
            szAlgorithm= "SHA256";
            break;
        }
        if(strcmp(av[i], "-Quote")==0) {
            if(an<(i+3)) {
                fprintf(g_logFile, "Too few arguments: key-file input-file measurement-file\n");
                return 1;
            }
            iAction= QUOTE;
            szKeyFile= av[i+1];
            szInFile= av[i+2];
            szMeasurementFile= av[i+3];
            break;
        }
        if(strcmp(av[i], "-VerifyQuote")==0) {
            iAction= VERIFYQUOTE;
            szInFile= av[i+1];
            szKeyFile= av[i+2];
            break;
        }
        if(strcmp(av[i], "-HexquoteTest")==0) {
            if(an<(i+2)) {
                fprintf(g_logFile, "Too few arguments: key-file input-file output-file\n");
                return 1;
            }
            szKeyFile= av[i+1];
            szInFile= av[i+2];
            iAction= HEXQUOTETEST;
            break;
        }
        if(strcmp(av[i], "-SignHexModulus")==0) {
            if(an<(i+3)) {
                fprintf(g_logFile, "Too few arguments: key-file input-file output-file\n");
                return 1;
            }
            szKeyFile= av[i+1];
            szInFile= av[i+2];
            szOutFile= av[i+3];
            iAction= SIGNHEXMODULUS;
            break;
        }
        if(strcmp(av[i], "-EncapsulateMessage")==0) {
            if(an<(i+5)) {
                fprintf(g_logFile, "Too few arguments: key-file metadata-file input-file output-file\n");
                return 1;
            }
            szKeyFile= av[i+1];
            szMetaDataFile= av[i+2];
            szInFile= av[i+3];
            szOutFile= av[i+4];
            iAction= ENCAPSULATE;
            break;
        }
        if(strcmp(av[i], "-DecapsulateMessage")==0) {
            if(an<(i+5)) {
                fprintf(g_logFile, "Too few arguments: key-file metadata-file input-file output-file\n");
                return 1;
            }
            szKeyFile= av[i+1];
            szMetaDataFile= av[i+2];
            szInFile= av[i+3];
            szOutFile= av[i+4];
            iAction= DECAPSULATE;
            break;
        }
        if(strcmp(av[i], "-validateChain")==0) {
            if(an<(i+3)) {
                fprintf(g_logFile, "Too few arguments: key-file input-file\n");
                return 1;
            }
            szKeyFile= av[i+1];
            szInFile= av[i+2];
            iAction= VALIDATECHAIN;
            break;
        }
        if(strcmp(av[i], "-validateAssertion")==0) {
            if(an<(i+6)) {
                fprintf(g_logFile, "Too few arguments: key-file input-file\n");
                return 1;
            }
            szKeyFile= av[i+1];
            szReqFile= av[i+2];
            szInFile= av[i+3];
            szPrincipalsFile= av[i+4];
            szMetaDataFile= av[i+5];
            iAction= VALIDATEASSERTION;
            break;
        }
        if(strcmp(av[i], "-Seal")==0) {
            if(an<(i+4)) {
                fprintf(g_logFile, "Too few arguments: key-file -Public|-Private base64in\n");
                return 1;
            }
            szKeyFile= av[i+1];
            if(strcmp(av[i+2], "-Public")==0) {
                fPublic= true;
            }
            if(strcmp(av[i+2], "-Private")==0) {
                fPublic= false;
            }
            szDataIn= av[i+3];
            iAction= SEAL;
            break;
        }
        if(strcmp(av[i], "-Unseal")==0) {
            if(an<(i+4)) {
                fprintf(g_logFile, "Too few arguments: key-file -Public|-Private base64in\n");
                return 1;
            }
            szKeyFile= av[i+1];
            if(strcmp(av[i+2], "-Public")==0) {
                fPublic= true;
            }
            if(strcmp(av[i+2], "-Private")==0) {
                fPublic= false;
            }
            szDataIn= av[i+3];
            iAction= UNSEAL;
            break;
        }
    }

    if(iAction==NOACTION) {
        fprintf(g_logFile, "Cant find option\n");
        return 1;
    }

    if(iAction==GENKEY) {
        initCryptoRand();
        initBigNum();
        fRet= GenKey(szKeyType, szOutFile);
        if(fRet)
            fprintf(g_logFile, "GenKey returning successfully\n");
        else
            fprintf(g_logFile, "GenKey returning unsuccessfully\n");
        closeCryptoRand();
    }

    if(iAction==VERIFY) {
        initCryptoRand();
        initBigNum();
        fRet= Verify(szKeyFile, szInFile);
        if(fRet)
            fprintf(g_logFile, "Signature verifies\n");
        else
            fprintf(g_logFile, "Signature fails\n");
        closeCryptoRand();
    }

    if(iAction==GENCERT) {
        fRet= GenCertSignedInfo(numArgs, pszArgs);
    }

    if(iAction==SIGN) {
        initCryptoRand();
        initBigNum();
        fRet= Sign(szKeyFile, szAlgorithm, szInFile, szOutFile);
        closeCryptoRand();
        if(fRet)
            fprintf(g_logFile, "Sign succeeded\n");
        else
            fprintf(g_logFile, "Sign failed\n");
    }

    if(iAction==SEAL) {
        initCryptoRand();
        initBigNum();
        fRet= Seal(szKeyFile, fPublic, szDataIn, &szDataOut);
        closeCryptoRand();
        if(fRet)
            fprintf(g_logFile, "Seal succeeded %s\n", szDataOut);
        else
            fprintf(g_logFile, "Seal failed\n");
    }

    if(iAction==UNSEAL) {
        initCryptoRand();
        initBigNum();
        fRet= Unseal(szKeyFile, fPublic, szDataIn, &szDataOut);
        closeCryptoRand();
        if(fRet)
            fprintf(g_logFile, "Unseal succeeded %s\n", szDataOut);
        else
            fprintf(g_logFile, "Unseal failed\n");
    }

    if(iAction==MAKEPOLICYFILE) {
        MakePolicyFile(szKeyFile, szOutFile, szProgramName);
        fprintf(g_logFile, "MakePolicyFile complete\n");
    }

    if(iAction==CANONICAL) {
        Canonical(szInFile, szOutFile);
        fprintf(g_logFile, "Canonical complete\n");
    }

    if(iAction==ENCRYPTFILE) {
        initCryptoRand();
        initBigNum();
        fRet= Encrypt(ENCRYPTFILE, szKeyFile, szInFile, szOutFile, mode);
        closeCryptoRand();
    }

    if(iAction==DECRYPTFILE) {
        initCryptoRand();
        initBigNum();
        fRet= Encrypt(DECRYPTFILE, szKeyFile, szInFile, szOutFile, mode);
        closeCryptoRand();
    }

    if(iAction==TIMEREPORT) {
        GetTime();
    }

    if(iAction==HEXQUOTETEST) {
        initCryptoRand();
        initBigNum();
        fRet= QuoteTest(szKeyFile, szInFile);
        closeCryptoRand();
    }

    if(iAction==SIGNHEXMODULUS) {
        initCryptoRand();
        initBigNum();
        fRet= SignHexModulus(szKeyFile, szInFile, szOutFile);
        closeCryptoRand();
    }

    if(iAction==HASHFILE) {
        u32  uType= 0;
        int  size= SHA256DIGESTBYTESIZE;
        byte rgHash[SHA256DIGESTBYTESIZE];
        if(getfileHash(szInFile, &uType, &size, rgHash)) {
            fprintf(g_logFile, "cryptUtility: cant hash file\n");
            return 1;
        }
        fprintf(g_logFile, "Hash of file %s is: ", szInFile);
        PrintBytes("", rgHash, size);
    }
   
    if(iAction==MAKEPOLICYKEYFILE) {
        RSAKey* pKey= (RSAKey*)ReadKeyfromFile(szKeyFile);
        byte*   rgB= pKey->m_rgbM;

        if(pKey==NULL) {
            fprintf(g_logFile, "can't read key %s\n", szKeyFile);
            return 1;
        }

        // write output file
        FILE* out= fopen(szOutFile,"w");
        fprintf(out, "u32 tciodd_policykeyType= RSA1024;\n");
        fprintf(out, "int tciodd_sizepolicykey= 128;\n");
        fprintf(out, "byte tciodd_policykey[256] = {\n");
        for(i=0; i<128; i+=8) {
            fprintf(out, "    0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x, \n",
                    rgB[i], rgB[i+1], rgB[i+2], rgB[i+3],
                    rgB[i+4], rgB[i+5], rgB[i+6], rgB[i+7]);
        }
        fprintf(out, "};\n");
        fclose(out);
        fprintf(g_logFile, "MakePolicyKeyFile complete\n");
    }

    if(iAction==MAKESERVICEHASHFILE ) {
        u32  uType= 0;
        int  size= SHA256DIGESTBYTESIZE;
        byte rgHash[SHA256DIGESTBYTESIZE];
        if(!getfileHash(szInFile, &uType, &size, rgHash)) {
            fprintf(g_logFile, "cryptUtility: cant hash file\n");
            return 1;
        }

        // write output file
        FILE* out= fopen(szOutFile,"w");
        fprintf(out, "u32 tciodd__fileHashtype= SHA256HASH;\n");
        fprintf(out, "#define SHA256HASHSIZE 32\n");
        fprintf(out, "byte tciodd_serviceHash[SHA256HASHSIZE]= {\n");
        for(i=0; i<SHA256DIGESTBYTESIZE; i+=8) {
            fprintf(out, "    0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x, \n",
                    rgHash[i], rgHash[i+1], rgHash[i+2], rgHash[i+3],
                    rgHash[i+4], rgHash[i+5], rgHash[i+6], rgHash[i+7]);
        }
        fprintf(out, "};\n");
        fclose(out);

        fprintf(g_logFile, "Hash of file %s is: ", szInFile);
        PrintBytes("", rgHash, size);
    }

    if(iAction==QUOTE) {
        initCryptoRand();
        initBigNum();
        fRet= Quote(szKeyFile, szInFile, szMeasurementFile);
        if(fRet)
            fprintf(g_logFile, "Signature generated\n");
        else
            fprintf(g_logFile, "Signature failed\n");
        closeCryptoRand();
    }

    if(iAction==VERIFYQUOTE) {
        if(VerifyQuote(szInFile, szKeyFile)) {
            fprintf(g_logFile, "Quote verifies\n");
        }
        else {
            fprintf(g_logFile, "Quote does NOT verify\n");
        }
        return 0;
    }
    if(iAction==ENCAPSULATE) {
        initCryptoRand();
        initBigNum();
        char* szCertString= readandstoreString(szKeyFile);
        if(szCertString==NULL) {
            fprintf(g_logFile, "Cant read certificate\n");
            return 1;
        }
        if(Encapsulate(szCertString, szMetaDataFile, szInFile, szOutFile)) {
            fprintf(g_logFile, "Encapsulate succeeds\n");
        }
        else {
            fprintf(g_logFile, "Encapsulate fails\n");
        }
        free(szCertString);
        return 0;
    }
    if(iAction==DECAPSULATE) {
        initCryptoRand();
        initBigNum();
        char* szKeyInfoString= readandstoreString(szKeyFile);
        if(Decapsulate(szKeyInfoString, szMetaDataFile, szInFile, szOutFile)) {
            fprintf(g_logFile, "Decapsulate succeeds\n");
        }
        else {
            fprintf(g_logFile, "Decapsulate fails\n");
        }
        free(szKeyInfoString);
        return 0;
    }
    if(iAction==VALIDATECHAIN) {
        initCryptoRand();
        initBigNum();
        char* szKeyString= readandstoreString(szKeyFile);
        char* szEvidenceList= readandstoreString(szInFile);

        if(validateChain(szKeyString, szInFile)) {
            fprintf(g_logFile, "validateChain succeeds\n");
        }
        else {
            fprintf(g_logFile, "validateChain fails\n");
        }
        if(szKeyString!=NULL)
            free(szKeyString);
        if(szEvidenceList!=NULL)
            free(szEvidenceList);
        return 0;
    }
    if(iAction==VALIDATEASSERTION) {
        char* szKeyString= readandstoreString(szKeyFile);
        char* szCollection= readandstoreString(szInFile);
        char* szPrincipals= NULL;
        char* szMeta= NULL;
        char* szReq= readandstoreString(szReqFile);

        if(szPrincipalsFile!=NULL)
            szPrincipals= readandstoreString(szPrincipalsFile);
        if(szMetaDataFile!=NULL)
            szMeta= readandstoreString(szMetaDataFile);

        initCryptoRand();
        initBigNum();
        if(validateAssertion(szKeyString, szReq, szCollection, szPrincipals, szMeta)) {
            fprintf(g_logFile, "validateAssertion succeeds\n");
        }
        else {
            fprintf(g_logFile, "validateAssertion fails\n");
        }
        if(szKeyString!=NULL)
            free(szKeyString);
        if(szCollection!=NULL)
            free(szCollection);
        if(szPrincipals!=NULL)
            free(szPrincipals);
        if(szMeta!=NULL)
            free(szMeta);
        if(szReq!=NULL)
            free(szReq);
        return 0;
    }

    closeLog();
    return 0;
}


// -------------------------------------------------------------------------



