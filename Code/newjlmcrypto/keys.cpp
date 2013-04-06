//
//  File: keys.cpp
//      John Manferdelli
//
//  Description:  Key formats
//
//  Copyright (c) 2011, Intel Corporation. All rights reserved.
//  Some contributions (c) John Manferdelli.  All rights reserved.
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
#include "keys.h"
#include "tinyxml.h"
#include "jlmcrypto.h"
#include "bignum.h"
#include "mpFunctions.h"

#include <string.h>


extern bnum g_bnOne;


const char*  szAESKeyProto=
  "<ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">" \
  "<KeyType></KeyType>"
  "<ds:KeyValue> <ds:AESKeyValue size=''> </ds:AESKeyValue>" 
  "</ds:KeyValue> </ds:KeyInfo>\n";
const char*  szRSAKeyProto=
   "<ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n"\
   "<KeyType></KeyType>\n"\
   " <ds:KeyValue> <ds:RSAKeyValue size=''> "
   "<ds:M></ds:M><ds:E></ds:E><ds:D></ds:D><ds:P></ds:P><ds:Q></ds:Q>"
   "</ds:RSAKeyValue></ds:KeyValue>\n</ds:KeyInfo>\n";


// -----------------------------------------------------------------------------


KeyInfo::KeyInfo() 
{
    m_ukeyType= NOKEYTYPE;
    m_uAlgorithm= NOALG;
    m_ikeySize= 0;
    m_ikeyNameSize= 0;
    m_pDoc= NULL;
}


KeyInfo::~KeyInfo()
{
    if(m_pDoc!=NULL)
         delete m_pDoc;
    m_pDoc= NULL;
    memset(m_rgkeyName, 0, KEYNAMEBUFSIZE);
}


bool KeyInfo::ParsefromString(const char* szXML)
{
    TiXmlDocument* pDoc= new TiXmlDocument();
    if(!pDoc->Parse(szXML)) {
        fprintf(g_logFile, "Cant parse document from file string\n");
        return false;
    }
    m_pDoc= pDoc;
    return true;
}


bool KeyInfo::ParsefromFile(const char* fileName)
{
    TiXmlDocument* pDoc= new TiXmlDocument();

    if(!pDoc->LoadFile(fileName)) {
        fprintf(g_logFile, "Cant load document from file: %s\n", fileName);
        return false;
    }
    m_pDoc= pDoc;
    return pDoc;
}


int KeyInfo::getKeyTypeFromRoot(TiXmlElement*  pRootElement)
{
    TiXmlNode*  pNode;
    TiXmlNode*  pNode1;
    const char*       szKeyType= NULL;

    pNode= pRootElement->FirstChild();
    while(pNode) {
        if(pNode->Type()==TiXmlNode::TINYXML_ELEMENT) {
            if(strcmp(((TiXmlElement*)pNode)->Value(),"KeyType")==0) {
                pNode1= ((TiXmlElement*)pNode)->FirstChild();
            szKeyType= ((TiXmlElement*)pNode1)->Value();
            break;
            }
        }
        pNode= pNode->NextSibling();
    }

    if(szKeyType==NULL)
        return NOKEYTYPE;

    if(strcmp(szKeyType,"AESKeyType")==0) {
        return AESKEYTYPE;
    }
    if(strcmp(szKeyType,"RSAKeyType")==0) {
        return RSAKEYTYPE;
    }
    return NOKEYTYPE;
}


int  KeyInfo::getKeyType(TiXmlDocument*  pDoc)
{
    if(pDoc==NULL)
        return NOKEYTYPE;
    return getKeyTypeFromRoot(pDoc->RootElement());
}


symKey::symKey()
{
    m_ukeyType= NOKEYTYPE;
    m_uAlgorithm= NOALG;
    m_ikeySize= 0;
    m_ikeyNameSize= 0;
    m_pDoc= NULL;
    m_iByteSizeKey= 0;
    m_iByteSizeIV= 0;

    memset(m_rgbKey, 0, SMALLKEYSIZE);
    memset(m_rgbIV, 0, SMALLKEYSIZE);
}


symKey:: ~symKey()
{
    memset(m_rgbKey, 0, SMALLKEYSIZE);
    memset(m_rgbIV, 0, SMALLKEYSIZE);
}


bool symKey::getDataFromRoot(TiXmlElement* pRootElement)
{
    TiXmlNode*      pNode;
    TiXmlNode*      pNode1;
    TiXmlNode*      pNode2;
    const char*     szKeyName= NULL;
    int             keySize= 0;
    char*           szBase64KeyValue= NULL;
    char*           szKeyType= NULL;
    int             iOutLen= 128;

    if(pRootElement==NULL) {
        fprintf(g_logFile, "No root element\n");
        return false;
    }

    if(strcmp(pRootElement->Value(),"ds:KeyInfo")==0) {
        szKeyName= strdup((pRootElement->Attribute("KeyName")));
    }
    pNode= pRootElement->FirstChild();
    while(pNode) {
        if(pNode->Type()==TiXmlNode::TINYXML_ELEMENT) {
            if(strcmp(((TiXmlElement*)pNode)->Value(),"KeyType")==0) {
                    pNode1= pNode->FirstChild();
                    if(pNode1)
                        szKeyType= strdup(((TiXmlNode*)pNode1)->Value());
            }
            if(strcmp(((TiXmlElement*)pNode)->Value(),"ds:KeyValue")==0) {
                pNode1= pNode->FirstChild();
                while(pNode1) {
                    if(strcmp(((TiXmlElement*)pNode1)->Value(),"ds:AESKeyValue")==0) {
                        ((TiXmlElement*) pNode1)->QueryIntAttribute ("size", &keySize);
                        m_ikeyNameSize= keySize;
                        pNode2= pNode1->FirstChild();
                        if(pNode2)
                            szBase64KeyValue= strdup( ((TiXmlNode*) pNode2)->Value());
                    }
                    pNode1= pNode1->NextSibling();
                }
            }
        }
        pNode= pNode->NextSibling();
    }

    if(strcmp(szKeyType,"AESKeyType")==0) {
        m_ukeyType=AESKEYTYPE;
        m_uAlgorithm= NOALG;
        m_ikeySize= keySize;
        m_ikeyNameSize= strlen(szKeyName);
        if(m_ikeyNameSize<KEYNAMEBUFSIZE) {
            strcpy(m_rgkeyName, szKeyName);
        }
        else {
            m_ikeyNameSize= 0;
        }
        m_iByteSizeKey= keySize;
        m_iByteSizeIV= 0;
        iOutLen= SMALLKEYSIZE;
        if(!fromBase64(strlen(szBase64KeyValue), szBase64KeyValue, &iOutLen, m_rgbKey)) {
            fprintf(g_logFile, "Cant base64 decode AES key\n");
            return false;
        }
    }
    else {
        fprintf(g_logFile, "Unknown key type\n");
        return false;
    }
 
    return true;
}


bool    symKey::getDataFromDoc()
{
    if(m_pDoc==NULL) {
        fprintf(g_logFile, "No Document\n");
        return false;
    }
    return getDataFromRoot(m_pDoc->RootElement());
}


char*   symKey::SerializetoString()
{
    return NULL;
}


bool    symKey::SerializetoFile(const char* fileName)
{
    return false;
}

#ifdef TEST
void symKey::printMe()
{
    if(m_ukeyType==AESKEYTYPE) {
        fprintf(g_logFile, "AES key\n");
    }
    else
        fprintf(g_logFile, "Unknown key\n");
    if(m_ikeyNameSize>0)
        fprintf(g_logFile, "Key name: %s\n", m_rgkeyName);
    else
        fprintf(g_logFile, "No key name\n");
    fprintf(g_logFile, "Key size %d\n", m_ikeySize);
    if(m_iByteSizeKey>0)
        PrintBytes("Key", m_rgbKey, m_iByteSizeKey);
}
#endif


RSAKey::RSAKey()
{
    m_ukeyType= NOKEYTYPE;
    m_uAlgorithm= NOALG;
    m_ikeySize= 0;
    m_ikeyNameSize= 0;

    m_pDoc= NULL;

    m_pbnM= NULL;
    m_pbnP= NULL;
    m_pbnQ= NULL;
    m_pbnE= NULL;
    m_pbnD= NULL;
    m_pbnDP= NULL;
    m_pbnDQ= NULL;
    m_pbnPM1= NULL;
    m_pbnQM1= NULL;

    m_iByteSizeM= 0;
    m_iByteSizeD= 0;
    m_iByteSizeE= 0;
    m_iByteSizeP= 0;
    m_iByteSizeQ= 0;
    m_iByteSizeDP= 0;
    m_iByteSizeDQ= 0;
    m_iByteSizePM1= 0;
    m_iByteSizeQM1= 0;

    memset(m_rgbM, 0, BIGKEYSIZE);
    memset(m_rgbD, 0, BIGKEYSIZE); 
    memset(m_rgbE, 0, BIGKEYSIZE); 
    memset(m_rgbP, 0, BIGKEYSIZE);
    memset(m_rgbQ, 0, BIGKEYSIZE); 
    memset(m_rgbDP, 0, BIGKEYSIZE);
    memset(m_rgbDQ, 0, BIGKEYSIZE); 
    memset(m_rgbPM1, 0, BIGKEYSIZE);
    memset(m_rgbQM1, 0, BIGKEYSIZE); 
}


RSAKey::~RSAKey()
{
    wipeKeys();
}


void RSAKey::wipeKeys()
{

    memset(m_rgbM, 0, BIGKEYSIZE);
    memset(m_rgbD, 0, BIGKEYSIZE); 
    memset(m_rgbE, 0, BIGKEYSIZE); 
    memset(m_rgbP, 0, BIGKEYSIZE);
    memset(m_rgbQ, 0, BIGKEYSIZE); 
    memset(m_rgbDP, 0, BIGKEYSIZE);
    memset(m_rgbDQ, 0, BIGKEYSIZE); 
    memset(m_rgbPM1, 0, BIGKEYSIZE);
    memset(m_rgbQM1, 0, BIGKEYSIZE); 

    if(m_pbnM!=NULL) {
        memset(m_pbnM->m_pValue, 0, m_pbnM->mpSize()*sizeof(u64));
        delete m_pbnM;
        m_pbnM= NULL;
    }
    if(m_pbnP!=NULL) {
        memset(m_pbnP->m_pValue, 0, m_pbnP->mpSize()*sizeof(u64));
        delete m_pbnP;
        m_pbnP= NULL;
    }
    if(m_pbnQ!=NULL) {
        memset(m_pbnQ->m_pValue, 0, m_pbnQ->mpSize()*sizeof(u64));
        delete m_pbnQ;
        m_pbnQ= NULL;
    }
    if(m_pbnE!=NULL) {
        memset(m_pbnE->m_pValue, 0, m_pbnE->mpSize()*sizeof(u64));
        delete m_pbnE;
        m_pbnE= NULL;
    }
    if(m_pbnD!=NULL) {
        memset(m_pbnD->m_pValue, 0, m_pbnD->mpSize()*sizeof(u64));
        delete m_pbnD;
        m_pbnD= NULL;
    }
    if(m_pbnDP!=NULL) {
        memset(m_pbnDP->m_pValue, 0, m_pbnDP->mpSize()*sizeof(u64));
        delete m_pbnDP;
        m_pbnDP= NULL;
    }
    if(m_pbnDQ!=NULL) {
        memset(m_pbnDQ->m_pValue, 0, m_pbnDQ->mpSize()*sizeof(u64));
        delete m_pbnDQ;
        m_pbnDQ= NULL;
    }
    if(m_pbnPM1!=NULL) {
        memset(m_pbnPM1->m_pValue, 0, m_pbnPM1->mpSize()*sizeof(u64));
        delete m_pbnPM1;
        m_pbnPM1= NULL;
    }
    if(m_pbnQM1!=NULL) {
        memset(m_pbnQM1->m_pValue, 0, m_pbnQM1->mpSize()*sizeof(u64));
        delete m_pbnQM1;
        m_pbnQM1= NULL;
    }
}


bool RSAKey::getDataFromRoot(TiXmlElement*  pRootElement)
{
    TiXmlNode*      pNode;
    TiXmlNode*      pNode1;
    TiXmlNode*      pNode2;
    TiXmlNode*      pNode3;
    int             keySize= 0;
    const char*     szKeyName= NULL;
    const char*     szKeyType= NULL;
    const char*     szRsaKeyP= NULL;
    const char*     szRsaKeyQ= NULL;
    const char*     szRsaKeyM= NULL;
    const char*     szRsaKeyE= NULL;
    const char*     szRsaKeyD= NULL;
    const char*     szRsaKeyDP= NULL;
    const char*     szRsaKeyDQ= NULL;
    int             iOutLen= 512;

    if(pRootElement==NULL) {
        fprintf(g_logFile, "Cant get root element\n");
        return false;
    }

    if(strcmp(pRootElement->Value(),"ds:KeyInfo")==0) {
        szKeyName= pRootElement->Attribute("KeyName");
    }
    pNode= pRootElement->FirstChild();
    while(pNode) {
        if(pNode->Type()==TiXmlNode::TINYXML_ELEMENT) {
            if(strcmp(((TiXmlElement*)pNode)->Value(),"KeyType")==0) {
                    pNode1= pNode->FirstChild();
                    szKeyType= ((TiXmlNode*)pNode1)->Value();
            }
            if(strcmp(((TiXmlElement*)pNode)->Value(),"ds:KeyValue")==0) {
                pNode1= pNode->FirstChild();
                while(pNode1) {
                    if(strcmp(((TiXmlElement*)pNode1)->Value(),"ds:RSAKeyValue")==0) {
                        ((TiXmlElement*) pNode1)->QueryIntAttribute ("size", &keySize);
                        m_ikeySize= keySize;
                        pNode2= pNode1->FirstChild();
                        while(pNode2!=NULL) {
                            if(strcmp(((TiXmlElement*)pNode2)->Value(),"ds:P")==0) {
                                pNode3= pNode2->FirstChild();
                                if(pNode3!=NULL)
                                    szRsaKeyP= ((TiXmlNode*)pNode3)->Value();
                            }
                            if(strcmp(((TiXmlElement*)pNode2)->Value(),"ds:Q")==0) {
                                pNode3= pNode2->FirstChild();
                                if(pNode3!=NULL)
                                    szRsaKeyQ= ((TiXmlNode*)pNode3)->Value();
                            }
                            if(strcmp(((TiXmlElement*)pNode2)->Value(),"ds:M")==0) {
                                pNode3= pNode2->FirstChild();
                                if(pNode3!=NULL)
                                    szRsaKeyM= ((TiXmlNode*)pNode3)->Value();
                            }
                            if(strcmp(((TiXmlElement*)pNode2)->Value(),"ds:E")==0) {
                                pNode3= pNode2->FirstChild();
                                    szRsaKeyE= ((TiXmlNode*)pNode3)->Value();
                            }
                            if(strcmp(((TiXmlElement*)pNode2)->Value(),"ds:D")==0) {
                                pNode3= pNode2->FirstChild();
                                if(pNode3!=NULL)
                                    szRsaKeyD= ((TiXmlNode*)pNode3)->Value();
                            }
                            if(strcmp(((TiXmlElement*)pNode2)->Value(),"ds:DP")==0) {
                                pNode3= pNode2->FirstChild();
                                if(pNode3!=NULL)
                                    szRsaKeyDP= ((TiXmlNode*)pNode3)->Value();
                            }
                            if(strcmp(((TiXmlElement*)pNode2)->Value(),"ds:DQ")==0) {
                                pNode3= pNode2->FirstChild();
                                if(pNode3!=NULL)
                                    szRsaKeyDQ= ((TiXmlNode*)pNode3)->Value();
                            }
                            pNode2= pNode2->NextSibling();
                        }
                    }
                    pNode1= pNode1->NextSibling();
                }
            }
        }
        pNode= pNode->NextSibling();
    }

    if(strcmp(szKeyType,"RSAKeyType")==0) {
        m_ukeyType=RSAKEYTYPE;
        m_uAlgorithm= NOALG;
        m_ikeySize= keySize;
        m_ikeyNameSize= strlen(szKeyName);
        if(m_ikeyNameSize<KEYNAMEBUFSIZE) {
            strcpy(m_rgkeyName, szKeyName);
        }
        else {
            m_ikeyNameSize= 0;
        }

        iOutLen= BIGKEYSIZE;
        m_iByteSizeM= 0;
        if(szRsaKeyM) {
            if(!fromBase64(strlen(szRsaKeyM), szRsaKeyM, &iOutLen, m_rgbM)) {
                fprintf(g_logFile, "Cant base64 decode M in RSA key\n");
                return false;
            }
            m_iByteSizeM= iOutLen;
        }

        iOutLen= BIGKEYSIZE;
        m_iByteSizeP= 0;
        if(szRsaKeyP) {
            if(!fromBase64(strlen(szRsaKeyP), szRsaKeyP, &iOutLen, m_rgbP)) {
                fprintf(g_logFile, "Cant base64 decode P in RSA key\n");
                return false;
            }
            m_iByteSizeP= iOutLen;
        }

        m_iByteSizeQ= 0;
        iOutLen= BIGKEYSIZE;
        if(szRsaKeyQ) {
            if(!fromBase64(strlen(szRsaKeyQ), szRsaKeyQ, &iOutLen, m_rgbQ)) {
                fprintf(g_logFile, "Cant base64 decode Q in RSA key\n");
                return false;
            }
            m_iByteSizeQ= iOutLen;
        }

        iOutLen= BIGKEYSIZE;
        m_iByteSizeE= 0;
        if(szRsaKeyE) {
            if(!fromBase64(strlen(szRsaKeyE), szRsaKeyE, &iOutLen, m_rgbE)) {
                fprintf(g_logFile, "Cant base64 decode E in RSA key\n");
                return false;
            }
            m_iByteSizeE= iOutLen;
        }

        iOutLen= BIGKEYSIZE;
        m_iByteSizeD= 0;
        if(szRsaKeyD) {
            if(!fromBase64(strlen(szRsaKeyD), szRsaKeyD, &iOutLen, m_rgbD)) {
                fprintf(g_logFile, "Cant base64 decode D in RSA key\n");
                return false;
            }
            m_iByteSizeD= iOutLen;
        }

        iOutLen= BIGKEYSIZE;
        m_iByteSizeDP= 0;
        if(szRsaKeyDP) {
            if(!fromBase64(strlen(szRsaKeyDP), szRsaKeyDP, &iOutLen, m_rgbDP)) {
                fprintf(g_logFile, "Cant base64 decode DP in RSA key\n");
                return false;
            }
            m_iByteSizeDP= iOutLen;
        }

        iOutLen= BIGKEYSIZE;
        m_iByteSizeDQ= 0;
        if(szRsaKeyDQ) {
            if(!fromBase64(strlen(szRsaKeyDQ), szRsaKeyDQ, &iOutLen, m_rgbDQ)) {
                fprintf(g_logFile, "Cant base64 decode DQ in RSA key\n");
                return false;
            }
            m_iByteSizeDQ= iOutLen;
        }
    }
    else {
        fprintf(g_logFile, "Unknown key type\n");
        return false;
    }

printf("DP: %s\n", szRsaKeyDP); fflush(stdout);
printf("DQ: %s\n", szRsaKeyDQ); fflush(stdout);
printf("making bignums\n"); fflush(stdout);
    // make bignums
    if(m_iByteSizeM>0) {
        m_pbnM= new bnum((m_iByteSizeM+sizeof(u64)-1)/sizeof(u64));
        memcpy(m_pbnM->m_pValue, m_rgbM, m_iByteSizeM);
    }
    if(m_iByteSizeP>0) {
        m_pbnP= new bnum((m_iByteSizeP+sizeof(u64)-1)/sizeof(u64));
        memcpy(m_pbnP->m_pValue, m_rgbP, m_iByteSizeP);
    }
    if(m_iByteSizeQ>0) {
        m_pbnQ= new bnum((m_iByteSizeQ+sizeof(u64)-1)/sizeof(u64));
        memcpy(m_pbnQ->m_pValue, m_rgbQ, m_iByteSizeQ);
    }
    if(m_iByteSizeE>0) {
        m_pbnE= new bnum((m_iByteSizeE+sizeof(u64)-1)/sizeof(u64));
        memcpy(m_pbnE->m_pValue, m_rgbE, m_iByteSizeE);
    }
    if(m_iByteSizeD>0) {
        m_pbnD= new bnum((m_iByteSizeD+sizeof(u64)-1)/sizeof(u64));
        memcpy(m_pbnD->m_pValue, m_rgbD, m_iByteSizeD);
    }
    if(m_iByteSizeDP>0) {
        m_pbnDP= new bnum((m_iByteSizeDP+sizeof(u64)-1)/sizeof(u64));
        m_pbnPM1= new bnum((m_iByteSizeP+sizeof(u64)-1)/sizeof(u64));
        memcpy(m_pbnDP->m_pValue, m_rgbDP, m_iByteSizeDP);
    }
    if(m_iByteSizeDQ>0) {
        m_pbnDQ= new bnum((m_iByteSizeDQ+sizeof(u64)-1)/sizeof(u64));
        m_pbnQM1= new bnum((m_iByteSizeQ+sizeof(u64)-1)/sizeof(u64));
        memcpy(m_pbnDQ->m_pValue, m_rgbDQ, m_iByteSizeDQ);
    }

    if(m_iByteSizeDP>0 &&  m_iByteSizeDQ>0 && m_pbnPM1!=NULL && m_pbnQM1!=NULL) {
        mpSub(*m_pbnP, g_bnOne, *m_pbnPM1);
        mpSub(*m_pbnQ, g_bnOne, *m_pbnQM1);
    }
 
    return true;
}

bool    RSAKey::getDataFromDoc()
{
    if(m_pDoc==NULL) {
        fprintf(g_logFile, "No Document\n");
        return false;
    }
    return getDataFromRoot(m_pDoc->RootElement());
}


// ------------------------------------------------------------------------


const char* szlocalKeyInfoHeader=
  "<ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" KeyName='%s'>\n";
const char* szlocalKeyInfoBody1= "    <KeyType>RSAKeyType</KeyType>\n";
const char* szlocalKeyInfoBody2= "    <ds:KeyValue>\n";
const char* szlocalKeyInfoBody3= "        <ds:RSAKeyValue size='%d'>\n";
const char* szlocalKeyInfoParam= "            <ds:%s>%s</ds:%s>\n";
const char* szlocalKeyInfoBody4= "        </ds:RSAKeyValue>\n";
const char* szlocalKeyInfoBody5= "    </ds:KeyValue>\n";
const char* szlocalKeyInfoTrailer= "</ds:KeyInfo>\n";


#define MAXSTRLEN 8192
#define MAXBASE64 1024


char*   RSAKey::SerializetoString()
{
    char    szStr[MAXSTRLEN];
    char    szBase64[MAXBASE64];
    int     nLeft= MAXSTRLEN;
    char*   p= szStr;
    int     n;
    int     iOutLen;

    if(m_ikeyNameSize>0)
        sprintf(p, szlocalKeyInfoHeader, m_rgkeyName);
    else
        sprintf(p, szlocalKeyInfoHeader, "NO NAME");
    n= strlen(p);
    p+= n;
    nLeft-= n;

    if(!safeTransfer(&p, &nLeft, szlocalKeyInfoBody1))
        return NULL;
    if(!safeTransfer(&p, &nLeft, szlocalKeyInfoBody2))
        return NULL;

    sprintf(p, szlocalKeyInfoBody3, m_ikeySize);
    n= strlen(p);
    p+= n;
    nLeft-= n;

    if(m_iByteSizeM>0) {
        iOutLen= MAXBASE64;
        if(!toBase64(m_iByteSizeM, (byte*)m_pbnM->m_pValue, &iOutLen, szBase64)) 
            return NULL;
        szBase64[iOutLen]= 0;
        sprintf(p, szlocalKeyInfoParam, "M", szBase64, "M");
        n= strlen(p);
        p+= n;
        nLeft-= n;
    }
    if(m_iByteSizeE>0) {
        iOutLen= MAXBASE64;
        if(!toBase64(m_iByteSizeE, (byte*)m_pbnE->m_pValue, &iOutLen, szBase64)) 
            return NULL;
        szBase64[iOutLen]= 0;
        sprintf(p, szlocalKeyInfoParam, "E", szBase64, "E");
        n= strlen(p);
        p+= n;
        nLeft-= n;
    }

    if(m_iByteSizeD>0) {
        iOutLen= MAXBASE64;
        if(!toBase64(m_iByteSizeD, (byte*)m_pbnD->m_pValue, &iOutLen, szBase64)) 
            return NULL;
        szBase64[iOutLen]= 0;
        sprintf(p, szlocalKeyInfoParam, "D", szBase64, "D");
        n= strlen(p);
        p+= n;
        nLeft-= n;
    }

    if(m_iByteSizeP>0) {
        iOutLen= MAXBASE64;
        if(!toBase64(m_iByteSizeP, (byte*)m_pbnP->m_pValue, &iOutLen, szBase64)) 
            return NULL;
        szBase64[iOutLen]= 0;
        sprintf(p, szlocalKeyInfoParam, "P", szBase64, "P");
        n= strlen(p);
        p+= n;
        nLeft-= n;
    }

    if(m_iByteSizeQ>0) {
        iOutLen= MAXBASE64;
        if(!toBase64(m_iByteSizeQ, (byte*)m_pbnQ->m_pValue, &iOutLen, szBase64)) 
            return NULL;
        szBase64[iOutLen]= 0;
        sprintf(p, szlocalKeyInfoParam, "Q", szBase64, "Q");
        n= strlen(p);
        p+= n;
        nLeft-= n;
    }

    if(m_iByteSizeDP>0) {
        iOutLen= MAXBASE64;
        if(!toBase64(m_iByteSizeDP, (byte*)m_pbnDP->m_pValue, &iOutLen, szBase64)) 
            return NULL;
        szBase64[iOutLen]= 0;
        sprintf(p, szlocalKeyInfoParam, "DP", szBase64, "DP");
        n= strlen(p);
        p+= n;
        nLeft-= n;
    }

    if(m_iByteSizeDQ>0) {
        iOutLen= MAXBASE64;
        if(!toBase64(m_iByteSizeDQ, (byte*)m_pbnDQ->m_pValue, &iOutLen, szBase64)) 
            return NULL;
        szBase64[iOutLen]= 0;
        sprintf(p, szlocalKeyInfoParam, "DQ", szBase64, "DQ");
        n= strlen(p);
        p+= n;
        nLeft-= n;
    }

    if(!safeTransfer(&p, &nLeft, szlocalKeyInfoBody4))
        return NULL;

    if(!safeTransfer(&p, &nLeft, szlocalKeyInfoBody5))
        return NULL;

    if(!safeTransfer(&p, &nLeft, szlocalKeyInfoTrailer))
        return NULL;

    if(nLeft<=0)
        return NULL;
    *p= 0;

    return strdup(szStr);
}


char*   RSAKey::SerializePublictoString()
{
    char    szStr[MAXSTRLEN];
    char    szBase64[MAXSTRLEN];
    int     nLeft= MAXSTRLEN;
    char*   p= szStr;
    int     n;
    int     iOutLen;

    if(m_ikeyNameSize>0)
        sprintf(p, szlocalKeyInfoHeader, m_rgkeyName);
    else
        sprintf(p, szlocalKeyInfoHeader, "NO NAME");
    n= strlen(p);
    p+= n;
    nLeft-= n;
    if(!safeTransfer(&p, &nLeft, szlocalKeyInfoBody1))
        return NULL;
    if(!safeTransfer(&p, &nLeft, szlocalKeyInfoBody2))
        return NULL;
    sprintf(p, szlocalKeyInfoBody3, m_ikeySize);
    n= strlen(p);
    p+= n;
    nLeft-= n;

    if(m_iByteSizeM>0) {
        iOutLen= MAXBASE64;
        if(!toBase64(m_iByteSizeM, (byte*)m_rgbM, &iOutLen, szBase64)) 
            return NULL;
        szBase64[iOutLen]= 0;
        sprintf(p, szlocalKeyInfoParam, "M", szBase64, "M");
        n= strlen(p);
        p+= n;
        nLeft-= n;
    }
    if(m_iByteSizeE>0) {
        iOutLen= MAXBASE64;
        if(!toBase64(m_iByteSizeE, (byte*)m_rgbE, &iOutLen, szBase64)) 
            return NULL;
        szBase64[iOutLen]= 0;
        sprintf(p, szlocalKeyInfoParam, "E", szBase64, "E");
        n= strlen(p);
        p+= n;
        nLeft-= n;
    }
    if(!safeTransfer(&p, &nLeft, szlocalKeyInfoBody4))
        return NULL;
    if(!safeTransfer(&p, &nLeft, szlocalKeyInfoBody5))
        return NULL;
    if(!safeTransfer(&p, &nLeft, szlocalKeyInfoTrailer))
        return NULL;
    if(nLeft<=0)
        return NULL;
    *p= 0;

    return strdup(szStr);
}



bool    RSAKey::SerializetoFile(const char* fileName)
{
    return false;
}


#ifdef TEST
void RSAKey::printMe()
{
    fprintf(g_logFile, "\n");
    if(m_ukeyType==RSAKEYTYPE) {
        fprintf(g_logFile, "RSA key\n");
    }
    else
        fprintf(g_logFile, "Unknown key\n");
    fprintf(g_logFile, "Key size: %d\n", m_ikeySize);
    fprintf(g_logFile, "Key name size: %d\n", m_ikeyNameSize);
    if(m_ikeyNameSize>0)
        fprintf(g_logFile, "Key name: %s\n", m_rgkeyName);
    else
        fprintf(g_logFile, "No key name\n");

    if(m_pbnM) {
        fprintf(g_logFile, "M: "); printNum(*m_pbnM); fprintf(g_logFile, "\n");
    }
    if(m_pbnP) {
        fprintf(g_logFile, "P: "); printNum(*m_pbnP); fprintf(g_logFile, "\n");
    }
    if(m_pbnQ) {
        fprintf(g_logFile, "Q: "); printNum(*m_pbnQ); fprintf(g_logFile, "\n");
    }
    if(m_pbnE) {
        fprintf(g_logFile, "E: "); printNum(*m_pbnE); fprintf(g_logFile, "\n");
    }
    if(m_pbnD) {
        fprintf(g_logFile, "D: "); printNum(*m_pbnD); fprintf(g_logFile, "\n");
    }
    if(m_pbnDP) {
        fprintf(g_logFile, "DP: "); printNum(*m_pbnDP); fprintf(g_logFile, "\n");
    }
    if(m_pbnDQ) {
        fprintf(g_logFile, "DQ: "); printNum(*m_pbnDQ); fprintf(g_logFile, "\n");
    }
    fprintf(g_logFile, "\n");
}
#endif


// ------------------------------------------------------------------------


#define NUMSUPPORTEDALGS 2
const char*   g_szSupportedAlgs[NUMSUPPORTEDALGS]= {
    "rsa2048-sha256-pkcspad",
    "rsa1024-sha256-pkcspad"
    };

const char*   g_szFullSupportedAlgs[NUMSUPPORTEDALGS]= {
    "http://www.manferdelli.com/2011/Xml/algorithms/rsa2048-sha256-pkcspad#",
    "http://www.manferdelli.com/2011/Xml/algorithms/rsa1024-sha256-pkcspad#"
};


struct AlgMap {
    int     pkAlg, hashAlg, padAlg;
};


AlgMap g_rgAlgMap[NUMSUPPORTEDALGS]= {
    {RSA2048, SHA256HASH, PKCSPAD},
    {RSA1024, SHA256HASH, PKCSPAD}
};


int pkAlgfromIndex(int iIndex)
{
    return g_rgAlgMap[iIndex].pkAlg;
}


int hashAlgfromIndex(int iIndex)
{
    return g_rgAlgMap[iIndex].hashAlg;
}


int padAlgfromIndex(int iIndex)
{
    return g_rgAlgMap[iIndex].padAlg;
}


int algorithmIndexFromShortName(const char* szAlg)

{
    int     i;

    if(szAlg==NULL)
        return -1;

    for(i=0;i<NUMSUPPORTEDALGS; i++) {
        if(strcmp(szAlg, g_szSupportedAlgs[i])==0) {
            return i;
        }
    }

    return -1;
}


int algorithmIndexFromLongName(const char* szAlg)

{
    int     i;

    if(szAlg==NULL)
        return -1;

    for(i=0;i<NUMSUPPORTEDALGS; i++) {
        if(strcmp(szAlg, g_szFullSupportedAlgs[i])==0) {
            return i;
        }
    }

    return -1;
}


char*   shortAlgNameFromIndex(int iIndex)
{
    if(iIndex>=NUMSUPPORTEDALGS || iIndex<0)
        return NULL;
    return  (char*) g_szSupportedAlgs[iIndex];
}


char*   longAlgNameFromIndex(int iIndex)
{
    if(iIndex>=NUMSUPPORTEDALGS || iIndex<0)
        return NULL;
    return  (char*) g_szFullSupportedAlgs[iIndex];
}


#define NUMSUPPORTEDCIPHERSUITES 2
const char*   g_szSupportedCipher[NUMSUPPORTEDCIPHERSUITES]= {
    "TLS_RSA2048_WITH_AES128_CBC_SHA256",
    "TLS_RSA1024_WITH_AES128_CBC_SHA256"
    };


struct cipherSuiteMap {
    int     pkAlg, skAlg, skMode, hashAlg;
};


cipherSuiteMap g_rgCipherSuiteMap[NUMSUPPORTEDCIPHERSUITES]= {
    {RSA2048, AES128, ECBMODE, SHA256HASH},
    {RSA1024, AES128, ECBMODE, SHA256HASH}
};


int cipherSuiteIndexFromName(const char* szCipherSuite)

{
    int     i;

    if(szCipherSuite==NULL)
        return -1;

    for(i=0;i<NUMSUPPORTEDCIPHERSUITES; i++) {
        if(strcmp(szCipherSuite, g_szSupportedCipher[i])==0) {
            return i;
        }
    }
    return -1;
}


char*   cipherSuiteNameFromIndex(int iIndex)
{
    if(iIndex>=NUMSUPPORTEDCIPHERSUITES|| iIndex<0)
        return NULL;
    return  (char*) g_szSupportedCipher[iIndex];
}


int modeSuitefromIndex(int iIndex)
{
    return g_rgCipherSuiteMap[iIndex].skMode;
}


int pkSuitefromIndex(int iIndex)
{
    return g_rgCipherSuiteMap[iIndex].pkAlg;
}


int hashSuitefromIndex(int iIndex)
{
    return g_rgCipherSuiteMap[iIndex].hashAlg;
}


int skSuitefromIndex(int iIndex)
{
    return g_rgCipherSuiteMap[iIndex].skAlg;
}


// ---------------------------------------------------------------------


