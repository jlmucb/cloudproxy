//
//  File: keyNegoServer.cpp
//      John Manferdelli
//
//  Description: Sever for keyNegoServer
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


#define CHANNEL_REQUEST    1
// #define HASHESDEFINED


// ------------------------------------------------------------------------


#include "jlmTypes.h"
#include "logging.h"
#include "jlmcrypto.h"
#include "jlmUtility.h"
#include "tinyxml.h"
#include "sha256.h"
#include "bignum.h"
#include "mpFunctions.h"
#include "cryptoHelper.h"
#include "objectManager.h"
#include "keys.h"
#include "keyNegoServer.h"
#include "cert.h"
#include "quote.h"
#include "validateEvidence.h"
#include "hashprep.h"
#include "tao.h"

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#ifdef LINUX
#include <wait.h>
#endif


// ------------------------------------------------------------------------


inline byte val(char a)
{
    if((a>='0')&(a<='9'))
        return a-'0';
    if((a>='a')&(a<='f'))
        return a-'a'+10;
    return 16;
}


bool fromhex(const char* szH, byte* buf, int sizemax, int* psizeout)
{
    int     i;
    byte*   p= buf;
    byte    a, b, c;

    for(i=0; i<sizemax; i++) {
        if(*szH==0 || *(szH+1)==0)
            break;
        a= val(*szH);
        b= val(*(szH+1));
        szH+= 2;
        c= a*16+b;
        *(p++)= c;
    }
    *psizeout= i;
    return true;
}


inline bool whitespace(char b)
{
    return(b==' ' || b=='\t' || b=='\r' || b=='\n');
}


int getNextToken(const char* sz, const char** pszToken)
{
    int     n;

    if(sz==NULL)
        return -1;

    while(*sz!='\0') {
        if(!whitespace(*sz))
            break;
    sz++;
    }

    if(*sz=='\0')
        return -1;

    *pszToken= sz;
    n= 0;
    while(*sz!='\0' && !whitespace(*sz)) {
        sz++;
        n++;
    }
    return n;
}


int   getnextline(int file, char* buf, int sizeBuf)
{
    int     n= 0;
    int     k= 0;

    for(;;) {
        if(n>=(sizeBuf-1)) {
            return -1;
        }
        k= read(file, &buf[n], 1);
        if(k<=0)
            return k;
        if(buf[n]=='\n') {
            buf[++n]= '\0';
            return n;
        }
        n++;
    }
}


class validBase64Hashes {
public:
    char*       m_szPolicyId;
    char*       m_szProgramName;
    char*       m_szBase64Hash;
};


#define MAXLINE 256
#define MAXBASE64HASHES 2048
int                 g_numbase64Hashes= 0;
validBase64Hashes   validBase64HashesTable[MAXBASE64HASHES];


bool parseEntry(const char* p, const char** pszPolicyId, 
                const char** pszProgramName, const char** pszBase64Hash)
{
    char* q;
    char* r;
    int   k;

    *pszPolicyId= NULL;
    *pszProgramName= NULL;
    *pszBase64Hash= NULL;

    if(*p!='\"')
        return false;
    q= (char*)++p;
    while(*q!='\n' && *q!='\0') {
        if(*q=='\"')
            break;
        q++;
    }
    if(*q!='\"')
        return false;
    *q= '\0';
    r= q+1;
    while(*r!=',' && *r!='\0' && *r!='\n')
        r++; 
    if(*r!=',')
        return false;
    *(q+1)= '\0';
    *pszPolicyId= p;
    r++;

    k= getNextToken(r, &p);
    if(k<=0){
        return false;
    }
    if(*p!='\"')
        return false;
    q= (char*) ++p;
    while(*q!='\n' && *q!='\0') {
        if(*q=='\"')
            break;
        q++;
    }
    if(*q!='\"')
        return false;
    *q= '\0';
    r= q+1;
    while(*r!=',' && *r!='\0' && *r!='\n')
        r++; 
    if(*r!=',')
        return false;
    *pszProgramName= p;
    r++;

    k= getNextToken(r, &p);
    if(*p!='\"')
        return false;
    q= (char*)++p;
    while(*q!='\n' && *q!='\0') {
        if(*q=='\"')
            break;
        q++;
    }
    if(*q!='\"')
        return false;
    *q= '\0';
    *pszBase64Hash= p;

    return true;
}


bool getValidHashes(const char* szHashFile)
//
//  Format of file is 
//      numhashes
//  numhashes lines of
//      "id", "name", "hash"
//
{
    int             i, j, n;
    char            buf[MAXLINE];
    const char*     nextp = NULL;
    const char*     szPolicyId= NULL;
    const char*     szProgramName= NULL;
    const char*     szBase64Hash= NULL;
    bool            fRet= false;

#ifdef  TEST
    fprintf(g_logFile, "getValidHashes %s\n", szHashFile);
    fflush(g_logFile);
#endif
    if(szHashFile==NULL) {
        fprintf(g_logFile, "getValidHashes: empty hash file name\n");
        return false;
    }
    int iRead = open(szHashFile, O_RDONLY);

    if(iRead<0) {
        fprintf(g_logFile, "getValidHashes: can't open %s\n", szHashFile);
        return false;
    }

    // get first non comment
    for(;;) {
        n= getnextline(iRead, buf, MAXLINE);
        if(n<0) {
            fprintf(g_logFile, "getValidHashes: getnextline<0\n");
            goto done;
        }
        if(n==0)
            break;
        i= getNextToken(buf, &nextp);
        if(i<0) {
            fprintf(g_logFile, "getValidHashes: getNextToken<0\n");
            goto done;
        }
        if(*nextp!='#')
            break;
    }
    // should be a number
    sscanf(nextp, "%d", &g_numbase64Hashes);
    if(g_numbase64Hashes<1 ||g_numbase64Hashes>=MAXBASE64HASHES) {
        fprintf(g_logFile, "getValidHashes: bad hash entry number %d\n", 
                g_numbase64Hashes);
        goto done;
    }

    // get lines of hashes
    i= 0;
    while(i<g_numbase64Hashes) {
        n= getnextline(iRead, buf, MAXLINE-1);
        if(n<=0)
            break;
        j= getNextToken(buf, &nextp);
        if(j<0) {
            fprintf(g_logFile, "getValidHashes: bad token length %d\n", j);
            continue;
        }
        if(*nextp=='#')
            continue;
        // should be: "id", "name", "hash"
        if(!parseEntry(nextp, &szPolicyId, &szProgramName, &szBase64Hash))
            continue;
        validBase64HashesTable[i].m_szPolicyId= strdup(szPolicyId);
        validBase64HashesTable[i].m_szProgramName= strdup(szProgramName);
        validBase64HashesTable[i].m_szBase64Hash= strdup(szBase64Hash);
        i++;
    }
     
    if(i!=g_numbase64Hashes) {
        fprintf(g_logFile, 
               "getValidHashes: mismatch between expected entries (%d) and entries (%d)\n",
                g_numbase64Hashes, i);
    }
    if(i<=g_numbase64Hashes)
        g_numbase64Hashes= i;
    fRet= true;

done:
    if(iRead>0)
        close(iRead);
    return fRet;
}


// ------------------------------------------------------------------------


bool            g_fTerminateProxy= false;
const int       iQueueSize= 5;

const char*     g_szPrivateKeyFileName= "policy/privatePolicyKey.xml";
const char*     g_szValidHashFileName= "policy/validHash.txt";
const char*     g_szPolicy= "Policy1";
bool            g_fIsEncrypted= false;
RSAKey*         g_pSigningKey= NULL;
const char*     g_szSigningAlgorithm=
                     "http://www.manferdelli.com/2011/Xml/algorithms/rsa1024-sha256-pkcspad#";

#define MAXREQUESTSIZE          16384
#define SERVICENAME             "keyNegoServer"
#define SERVICEADDRESS          "127.0.0.1"
#define SERVICE_PORT            6001
#define REQUESTLOGFILE          "~/requestLog.log"

#include "channel.h"


// ------------------------------------------------------------------------


/*
 *      Key Nego protocol
 *
 *      C-->S: Key sign request, initProxyCert, Attested signed info for
 *              client generated private key (includes client hash),
 *              certificate chain for platform key signing
 *
 *      S-->C: success/fail, EvidenceList supporting signed client cert(included
 *              in evidenceList)
 *
 */


const char* g_szResponse=
    "<serverCertNego phase='1'>\n    <Status> %s </Status>\n"\
    "    <ErrorCode> %s </ErrorCode>\n"\
    "    <Cert> %s </Cert>\n</serverCertNego>\n";


bool serverCertNegoMessage1(int maxSize, char* buf, const char* szStatus,
                           const char* szErrorCode, const char* szCert)
{
#ifdef  TEST
    fprintf(g_logFile, "serverCertNegoMessage1(%s %s %s\n", szStatus, szErrorCode, szCert);
#endif
    int iSize= strlen(g_szResponse);

    if(szStatus!=NULL)
        iSize+= strlen(szStatus);
    if(szErrorCode!=NULL) {
        iSize+= strlen(szErrorCode);
    }
    else {
        szErrorCode="";
    }
    if(szCert!=NULL) {
        iSize+= strlen(szCert);
    }
    else {
        szCert="";
    }
    if(iSize>=maxSize) {
        fprintf(g_logFile, "Response too large\n");
        return false;
    }
    sprintf(buf, g_szResponse, szStatus, szErrorCode,  szCert);
    return true;
}


bool getDatafromClientCertMessage1(char* buf, char** pszpolicyKeyId,
                           char** pszAttested, char** pszEvidence)
{
    TiXmlDocument   doc;
    TiXmlNode*      pNode= NULL;
    TiXmlNode*      pNode1= NULL;
    TiXmlElement*   pRootElement= NULL;
    const char*     szLabel= NULL;
    const char*     szPolicyId= NULL;
    char*           szsignedRequest= NULL;
    int             phase, count;
    bool            fRet= true;

#ifdef  TEST
    fprintf(g_logFile, "getDatafromClientCertMessage1\n%s\n", buf);
#endif
    try {

        // Parse document
        if(!doc.Parse(buf)) 
            throw "Message 1 parse failure in key Nego\n";
        pRootElement= doc.RootElement();
        if(pRootElement==NULL) 
            throw "Cant find root\n";
        szLabel= pRootElement->Value();
        if(szLabel==NULL || strcmp("clientCertNego", szLabel)!=0)
            throw "Bad response format (no clientCertNego)\n";

        pRootElement->QueryIntAttribute("phase", &phase);

        // policy ID
        pNode= Search((TiXmlNode*) pRootElement, "policyKeyId");
        if(pNode==NULL)
            throw "Cant find policy key id in client message 1\n";
        pNode1= pNode->FirstChild();
        if(pNode1==NULL)
            throw  "Bad policy key id in client message";
        szPolicyId=  pNode1->Value();
        if(szPolicyId==NULL)
            throw  "Bad policy key value in client message";
        *pszpolicyKeyId= strdup(szPolicyId);

        // signedRequest
        pNode= Search((TiXmlNode*) pRootElement, "signedRequest");
        if(pNode==NULL)
            throw "Cant find signed request in client message 1\n";
        pNode1= pNode->FirstChild();
        if(pNode1==NULL)
            throw  "Bad signed request in client message";
        szsignedRequest= canonicalize(pNode1);
        if(szsignedRequest==NULL)
            *pszAttested= NULL;
        else
            *pszAttested= szsignedRequest;

        // Evidence
        pNode= Search((TiXmlNode*) pRootElement, "EvidenceList");
        if(pNode==NULL)
            throw "Cant find evidence list in client message 1\n";
        ((TiXmlElement*)pNode)->QueryIntAttribute("count", &count);
        if(count==0) {
            *pszEvidence= NULL;
        }
        else {
            *pszEvidence= canonicalize(pNode);
        }

    }
    catch(const char* szError) {
        fRet= false;
        fprintf(g_logFile, "%s", szError);
    }

#ifdef  TEST
    fprintf(g_logFile, "getDatafromClientCertMessage1 returns %d\n", (int) fRet);
#endif
    return fRet;
}


// ------------------------------------------------------------------------


bool initString(const char* str, const char* strCmp)
{
    int     n= strlen(str);
   
    while(n-->0) {
        if(*str==0 || *strCmp==0)
            return false;
        if(*str!=*strCmp)
            return false;
        str++;  strCmp++;
    } 
    return true;
}


char* insertMiddle(const char* szName, const char* pS, const char* pE, const char* newStr)
{
    char    szNewName[512];
    int     n= strlen(szName);
    const char*   p= szName;
    char*   q= szNewName;

#ifdef TEST
    fprintf(g_logFile, "insertMiddle: %s, %s, %s, %s\n",
            szName,  pS, pE, newStr);
    fflush(g_logFile);
#endif
    if(n>500)
        return strdup(szName);
    while(p!=pS)
        *(q++)= *(p++);
    while(*newStr!=0)
        *(q++)= *(newStr++);
    p= ++pE;
    while(*p!=0)
        *(q++)= *(p++);
    *q= 0;

#ifdef TEST
    fprintf(g_logFile, "insertMiddlereturns %s\n", newStr);
    fflush(g_logFile);
#endif
    return strdup(szNewName);
}


char* replaceKeywithProgram(const char* szKeyName)
{
    const char*   p= szKeyName;
    char*         newstr= NULL;
    const char*   replaced= "Keys";
    const char*   replacedBy= "Programs/";

#ifdef TEST
    fprintf(g_logFile, "replaceKeywithProgram(%s)\n", szKeyName);
    fflush(g_logFile);
#endif
    // www.manferdelli.com/Herstein/Keys/fileClientProgram"
    while(p!=NULL) {
        if(initString(replaced, p)) {
            newstr= insertMiddle(szKeyName, p, p+strlen(replaced), replacedBy);
            break;
        }
        p++;
    }
    if(newstr==NULL)
        newstr= strdup(szKeyName);
   return newstr; 
}


// Data base call to see if approved and get parameters
bool getCertParameters(const char* szPolicyKeyId, const char* szDigest, const char* szEvidenceCollection, 
            const char* szKeyName, char** pszCertid, int* pserialNo, char** pszPrincipalType, 
            char** pszIssuerName, char** pszIssuerID, char** pszNotBefore, 
            char** pszNotAfter, char** pszSubjName, char** pszSubjKeyID)
{
    *pszCertid= strdup("Certid");
    *pserialNo= 42;
    *pszPrincipalType= strdup("Program");
    *pszIssuerName= strdup("www.manferdelli.com");
    *pszIssuerID= strdup("www.manferdelli.com");
    *pszNotBefore= strdup("2011-01-01Z00:00.00");
    *pszNotAfter= strdup("2021-01-01Z00:00.00");

#ifdef TEST
    fprintf(g_logFile, 
        "getCertParameters. policy key: %s, digest: %s, keyname: %s\n",
            szPolicyKeyId, szDigest, szKeyName);
    fflush(g_logFile);
#endif
    // www.manferdelli.com/Herstein/Keys/fileClientProgram"
    if(szKeyName==NULL) {
        *pszSubjName= strdup("//www.manferdelli.com/Programs/Unknown");
        *pszSubjKeyID= strdup("UnknownKey");
    }
    else {
        *pszSubjName=  replaceKeywithProgram(szKeyName);
        *pszSubjKeyID= strdup(szKeyName);
    }
#ifdef TEST
    fprintf(g_logFile, 
        "getCertParameters, SubjName: %s, SubjKeyId: %s\n",
            *pszSubjName,  *pszSubjKeyID);
    fflush(g_logFile);
#endif
    return true;
}


// ---------------------------------------------------------------------------------


//  Typical signed response to key quote
// 
//  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id='signeruniqueid'>
//     <ds:SignedInfo>
//         <ds:CanonicalizationMethod 
//          Algorithm="http://www.manferdelli.com/2011/Xml/canonicalization/tinyxmlcanonical#" />
//         <ds:SignatureMethod 
//          Algorithm="http://www.manferdelli.com/2011/Xml/algorithms/rsa1024-sha256-pkcspad#" />
//         <Certificate Id="//www.manferdelli.com/2011/Cert/User00001" version="1">
//             <SerialNumber>20111011001</SerialNumber>
//             <PrincipalType>Program</PrincipalType>
//             <CodeDigest alg='SHA256'> </CodeDigest>
//             <IssuerName>manferdelli.com</IssuerName>
//             <IssuerID>manferdelli.com</IssuerID>
//             <ValidityPeriod>
//                 <NotBefore>2011-01-01Z00:00.00</NotBefore>
//                 <NotAfter>2021-01-01Z00:00.00</NotAfter>
//             </ValidityPeriod>
//             <SubjectName>//www.manferdelli.com/User/JohnManferdelli/0001</SubjectName>
//         <SubjectKey>
//             <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#" 
//                KeyName="//www.manferdelli.com/Keys/jlmPrincipal/0001">
//                 <KeyType>RSAKeyType</KeyType>
//                 <ds:KeyValue>
//                     <ds:RSAKeyValue size="1024">
//                         <ds:M></ds:M>
//                         <ds:E>AAAAAAABAAE=</ds:E>
//                     </ds:RSAKeyValue>
//                 </ds:KeyValue>
//             </ds:KeyInfo>
//         </SubjectKey>
//         <SubjectKeyID>//www.manferdelli.com/Keys/jlmPrincipal/0001</SubjectKeyID>
//         <RevocationPolicy>Local-check-only</RevocationPolicy>
//     </Certificate>
// </ds:SignedInfo>
//     <ds:SignatureValue>    
//     </ds:SignatureValue>    
// </ds:Signature>


RSAKey* getKeyfromID(const char* szPolicyKeyId)
{
    return g_pSigningKey;
}


char* getKeyNamefromQuotedKeyInfo(const char* szquotedKeyInfo)
{
    if(szquotedKeyInfo==NULL)
        return NULL;

    TiXmlDocument doc;
    if(!doc.Parse(szquotedKeyInfo)) {
        fprintf(g_logFile, "getKeyNamefromQuotedKeyInfo: cant parse cert\n");
        return NULL;
    }
    TiXmlElement*   pRootElement= doc.RootElement();
    if(pRootElement==NULL) {
        fprintf(g_logFile, "getKeyNamefromQuotedKeyInfo: Can't get root of quote\n");
        return NULL;
    }
    TiXmlNode* pNode= Search((TiXmlNode*) pRootElement, "ds:KeyInfo");
    if(pNode==NULL) {
        fprintf(g_logFile, "getKeyNamefromQuotedKeyInfo: No ds:KeyInfo node\n");
        return NULL;
    }
    const char* szA= ((TiXmlElement*) pNode)->Attribute ("KeyName");
    if(szA!=NULL)
        return strdup(szA);
   return NULL; 
}


bool registerCertandEvidence(const char* szPolicyKeyId, const char* szCert, 
                             const char* szEvidence)
{
#ifdef  TEST
    fprintf(g_logFile, "registerCertandEvidence\n");
#endif
    return true;
}


bool validCodeDigest(const char* szPolicyKeyId, const char* szCodeDigest)
{
#ifdef  TEST
    fprintf(g_logFile, "validCodeDigest %s %s\n", szPolicyKeyId, szCodeDigest);
#endif

#ifdef HASHESDEFINED
    int     i;

    for(i=0; i<g_numbase64Hashes; i++) {
        if(strcmp(validBase64HashesTable[i].m_szPolicyId, szPolicyKeyId)==0 &&
           strcmp(validBase64HashesTable[i].m_szBase64Hash, szCodeDigest)==0)
            return true;
    }
    return false;
#else
    return true;
#endif
}


bool validateRequestandIssue(const char* szPolicyKeyId, const char* szXMLQuote, 
                             const char* szEvidence, char**  pszCert)
{
    char*   szAlg= NULL;
    char*   szNonce= NULL;
    char*   szDigest= NULL;
    char*   szQuotedInfo= NULL;
    char*   szQuoteValue= NULL;
    char*   szSignedInfo= NULL;
    char*   szCert= NULL;

    char*   szCertid= NULL;
    int     serialNo= 0;
    char*   szPrincipalType= NULL;
    char*   szIssuerName= NULL;
    char*   szIssuerID= NULL;
    char*   szNotBefore= NULL;
    char*   szNotAfter= NULL;
    char*   szSubjName= NULL;
    char*   szKeyName= NULL;
    char*   szSubjKeyID= NULL;

    char*   szquoteKeyInfo= NULL;
    char*   szquotedKeyInfo= NULL;

    RSAKey* pKey= NULL;
    taoAttest  oAttest;
    bool    fRet= true;

#ifdef  TEST
    fprintf(g_logFile, "validateRequestandIssue\n");
    fprintf(g_logFile, "Policy key: %s\n", szPolicyKeyId);
    fprintf(g_logFile, "Quote: %s\n", szXMLQuote);
    if(szEvidence!=NULL)
        fprintf(g_logFile, "Evidence: %s\n", szEvidence);
    else
        fprintf(g_logFile, "Evidence: none\n");
#endif

    // get policy key
    pKey= getKeyfromID(szPolicyKeyId);
    if(pKey==NULL) {
        fprintf(g_logFile, "validateRequestandIssue: cant get Signing key\n");
        fRet= false;
        goto cleanup;
    }


#ifdef  TEST
    fflush(g_logFile);
    fprintf(g_logFile, "about to init attestation\n");
    fprintf(g_logFile, "Quote: %s\n", szXMLQuote);
    fprintf(g_logFile, "Cert: %s\n", szCert);
    if(szEvidence!=NULL)
        fprintf(g_logFile, "Evidence: %s\n", szEvidence);
    else
        fprintf(g_logFile, "Evidence: none\n");
#endif

    // initialize Attest object
    if(!oAttest.init(CPXMLATTESTATION, szXMLQuote, szEvidence, (KeyInfo*) pKey)) {
        fprintf(g_logFile, "validateRequestandIssue: cant init attest object\n");
        fRet= false;
        goto cleanup;
    }

    szDigest= oAttest.codeDigest();
    if(szDigest==NULL) {
        fprintf(g_logFile, "validateRequestandIssue: cant get code digest\n");
        fRet= false;
        goto cleanup;
    }

    szquotedKeyInfo= oAttest.quotedKeyInfo();
    if(szquotedKeyInfo==NULL) {
        fprintf(g_logFile, "validateRequestandIssue: cant get quoted keyInfo\n");
        fRet= false;
        goto cleanup;
    }
#ifdef  TEST
    fprintf(g_logFile, "quotedkeyInfo\n%s\n", szquotedKeyInfo);
    fflush(g_logFile);
#endif

    // Key name
    szKeyName= oAttest.quotedKeyName();

    // check policy
    if(!validCodeDigest(szPolicyKeyId, szDigest)) {
        fprintf(g_logFile, "validateRequestandIssue: out of policy\n");
        fRet= false;
        goto cleanup;
    }

#ifdef  TEST
    fprintf(g_logFile, "getting cert parameters\n");
    fflush(g_logFile);
#endif
    // get cert parameters
    if(!getCertParameters(szPolicyKeyId, szDigest, szEvidence, szKeyName,
                          &szCertid, &serialNo, &szPrincipalType, 
                          &szIssuerName, &szIssuerID, &szNotBefore, 
                          &szNotAfter, &szSubjName, &szSubjKeyID)) {
        fprintf(g_logFile, "validateRequestandIssue: cant get certificate parameters\n");
        fRet= false;
        goto cleanup;
    }

#ifdef TEST
    fprintf(g_logFile, "verifying attestation\n");
    fflush(g_logFile);
#endif
    // verify attestation 
    if(!oAttest.verifyAttestation()) {
        fprintf(g_logFile, "validateRequestandIssue: attest fails\n");
        fRet= false;
        goto cleanup;
    }

#ifdef TEST
    fprintf(g_logFile, "encoding signed body\n");
    fflush(g_logFile);
#endif
    // encode signed body
    szSignedInfo= formatSignedInfo(pKey, szCertid, serialNo, szPrincipalType, 
            szIssuerName, szIssuerID, szNotBefore, szNotAfter,
            szSubjName, szquotedKeyInfo, szDigest, szSubjKeyID);
    if(szSignedInfo==NULL) {
        fprintf(g_logFile, "validateRequestandIssue: cant generate SignedInfo\n");
        fRet= false;
        goto cleanup;
    }

#ifdef  TEST
    fprintf(g_logFile, "hashing\n");
    fflush(g_logFile);
#endif
    szCert= constructXMLRSASha256SignaturefromSignedInfoandKey(*pKey,
                                                szSubjName, szSignedInfo);
    if(szCert==NULL) {
        fprintf(g_logFile, "validateRequestandIssue: Cant construct signature\n");
        return false;
    }
    *pszCert= szCert;

#ifdef  TEST
    fprintf(g_logFile, "registering\n");
    fflush(g_logFile);
#endif
    // register it and return
    if(!registerCertandEvidence(szPolicyKeyId, szCert, szEvidence)) {
        fprintf(g_logFile, "validateRequestandIssue: Invalid program hash\n");
        fRet= false;
        goto cleanup;
    }
#ifdef  TEST
    fprintf(g_logFile, "returning cert\n");
    fprintf(g_logFile, "\n%s\n", szCert);
    fflush(g_logFile);
#endif

cleanup:
    if(szAlg!=NULL) {
        szAlg= NULL;
    }
    if(szNonce!=NULL) {
        szNonce= NULL;
    }
    if(szDigest!=NULL) {
        free(szDigest);
        szDigest= NULL;
    }
    if(szQuotedInfo!=NULL) {
        free(szQuotedInfo);
        szQuotedInfo= NULL;
    }
    if(szQuoteValue!=NULL) {
        free(szQuoteValue);
        szQuoteValue= NULL;
    }
    if(szquotedKeyInfo!=NULL) {
        free(szquotedKeyInfo);
        szquotedKeyInfo= NULL;
    }
    if(szquoteKeyInfo!=NULL) {
        free(szquoteKeyInfo);
        szquoteKeyInfo= NULL;
    }
    if(szKeyName!=NULL) {
        free(szKeyName);
        szKeyName= NULL;
    }
    return fRet;
}


// --------------------------------------------------------------------------


bool certNego(int fd)
{
    char        request[MAXREQUESTSIZE];
    int         type= 0;
    byte        multi= 0;
    byte        final= 0;
    bool        fRet= true;
    char*       szPolicyKeyId= NULL;
    char*       szQuote= NULL;
    char*       szEvidence= NULL;
    const char* szStatus= NULL;
    const char* szErrorCode= NULL;
    char*       szCert= NULL;
    int         n= 0;
    FILE*       requestLog= NULL;
    struct tm*  current;
    time_t      now;

#ifdef  TEST
    fprintf(g_logFile, "keyNegoServer(%d)\n", fd);
#endif

    requestLog= fopen(REQUESTLOGFILE, "w+");
    if(requestLog==NULL) {
        fprintf(g_logFile, "Can't open request log: %s\n", REQUESTLOGFILE);
    }

    try {
    
        // Phase 1, receive
        if((n=getPacket(fd, (byte*)request, MAXREQUESTSIZE, &type, &multi, &final))<0)
            throw  "Can't get packet 1 in keyNegoServer\n";

        if(!getDatafromClientCertMessage1(request, &szPolicyKeyId, &szQuote, &szEvidence))
            throw  "Can't decode client packet in keyNegoServer\n";

        // log request
        if(requestLog!=NULL) {
            time(&now);
            current= localtime(&now);
            fprintf(requestLog, "\nRequest time: %02d/%02d/%04d  %i:%i:%i\n", 
                current->tm_year, current->tm_mon+1, current->tm_mday,
                current->tm_hour, current->tm_min, current->tm_sec);
            fprintf(requestLog,"%s\n\n", request);
        }

        // check request, sign and register
        bool fIssue= validateRequestandIssue(szPolicyKeyId, szQuote, szEvidence, &szCert);
        if(fIssue) {
            szStatus= "accept";
            szErrorCode= NULL;
        }
        else {
            szStatus= "reject";
            szErrorCode= "invalid request";
            szCert= NULL;
        }

#ifdef  TEST
        fprintf(g_logFile, "validateRequestandIssue complete %d\n", (int) fIssue);
        fflush(g_logFile);
#endif
        // Phase 1, response
        if(!serverCertNegoMessage1(MAXREQUESTSIZE, request, szStatus, szErrorCode, szCert))
            throw  "Can't construct response in keyNegoServer\n";
#ifdef  TEST
        fprintf(g_logFile, "Server response:\n%s\n", request);
        fflush(g_logFile);
#endif
        if((n=sendPacket(fd, (byte*)request, strlen(request)+1, CHANNEL_REQUEST, 0, 1)) <0)
             throw  "Can't send packet 1 in keyNegoServer\n";

    }
    catch(const char* szError) {
        fprintf(g_logFile, "%s\n", szError);
        fRet= false;
    }

    fflush(g_logFile);
    if(requestLog!=NULL) {
        fflush(requestLog);
        fclose(requestLog);
        requestLog= NULL;
    }
    return fRet;
}

bool server()
{
    int                 fd, newfd;
    int                 childpid;
    struct sockaddr_in  server_addr, client_addr;
    int                 slen= sizeof(struct sockaddr_in);
    int                 clen= sizeof(struct sockaddr);
    int                 iError;

    // Signing key
    g_pSigningKey= (RSAKey*) ReadKeyfromFile(g_szPrivateKeyFileName);
    if(g_pSigningKey==NULL) {
        fprintf(g_logFile, "server: Can't init signing key %s\n", g_szPrivateKeyFileName);
        return false;
    }

    fd= socket(AF_INET, SOCK_STREAM, 0);
    if(fd<0) {
        fprintf(g_logFile, "Can't open socket\n");
        return false;
    }
#ifdef  TEST
    fprintf(g_logFile, "keyNegoServer: socket opened\n");
#endif

    memset((void*) &server_addr, 0, sizeof(struct sockaddr_in));
    server_addr.sin_family= AF_INET;
    server_addr.sin_addr.s_addr= htonl(INADDR_ANY);     // 127.0.0.1
    server_addr.sin_port= htons(SERVICE_PORT);

    iError= bind(fd,(const struct sockaddr *) &server_addr, slen);
    if(iError<0) {
        fprintf(g_logFile, "Can't bind socket %s", strerror(errno));
        return false;
    }
#ifdef  TEST
    fprintf(g_logFile, "keyNegoServer: bind succeeded\n");
#endif

    listen(fd, iQueueSize);

    // set the signal disposition of SIGCHLD to not create zombies
    struct sigaction sigAct;
    memset(&sigAct, 0, sizeof(sigAct));
    sigAct.sa_handler = SIG_DFL;
    sigAct.sa_flags = SA_NOCLDWAIT; // don't zombify child processes
    int sigRv = sigaction(SIGCHLD, &sigAct, NULL);
    if (sigRv < 0) {
        fprintf(g_logFile, "Failed to set signal disposition for SIGCHLD\n");
    } else {
        fprintf(g_logFile, "Set SIGCHLD to avoid zombies\n");
    }

    for(;;) {
        newfd= accept(fd, (struct sockaddr*) &client_addr, (socklen_t*)&clen);
        if(newfd<0) {
            fprintf(g_logFile, "Can't accept socket %s", strerror(errno));
            return false;
        }

        if((childpid=fork())<0) {
            close(fd);
            fprintf(g_logFile, "Can't fork in server()");
            return false;
        }

        if(childpid==0) {
            if(!certNego(newfd)) {
                close(newfd);
                break;
            }
            close(newfd);
        fflush(g_logFile);
        }

    if(g_fTerminateProxy)
        break;
    }

    close(fd);
    return true;
}


// --------------------------------------------------------------------------


int main(int an, char** av)
// certNego.exe [-store storename]
{
    initLog("keyNegoServer.log");
#ifdef  TEST
    fprintf(g_logFile, "keyNegoServer\n");
    fflush(g_logFile);
#endif

#ifdef HASHESDEFINED
    if(!getValidHashes(g_szValidHashFileName)) {
        fprintf(g_logFile, "keyNegoServer can't get valid hashes\n");
        return 1;
    }

#ifdef  TEST
    int     i;
    fprintf(g_logFile, "Hash table, %d entries\n", g_numbase64Hashes);
    for(i=0; i<g_numbase64Hashes;i++) {
        fprintf(g_logFile, "Policy: %s, Program name: %s, Hash: %s\n",
            validBase64HashesTable[i].m_szPolicyId,
            validBase64HashesTable[i].m_szProgramName,
            validBase64HashesTable[i].m_szBase64Hash);
    }
#endif
    fflush(g_logFile);
#endif

    server();
    return 0;
}


// ------------------------------------------------------------------------


