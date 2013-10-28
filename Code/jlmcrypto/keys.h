//
//  File: keys.h
//      John Manferdelli
//
//  Description:  Key formats
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


// -------------------------------------------------------------------------------


#ifndef _KEYS__H
#define _KEYS__H

#include "jlmTypes.h"
#include "jlmUtility.h"
#include "algs.h"
#include "bignum.h"
#include "tinyxml.h"


class KeyInfo {
public:
    u32             m_ukeyType;
    u32             m_uAlgorithm;
    i32             m_ikeySize;
    i32             m_ikeyNameSize;
    char*           m_rgkeyName;
    TiXmlDocument*  m_pDoc;

                    KeyInfo();
                    ~KeyInfo();

    bool            ParsefromString(const char* szXML);
    bool            ParsefromFile(const char* szFileName);
    int             getKeyType(TiXmlDocument*  pDoc);
    int             getKeyTypeFromRoot(TiXmlElement*  pRootElement);
};


class symKey : public KeyInfo {
public:
    i32             m_iByteSizeKey;
    byte            m_rgbKey[GLOBALMAXSYMKEYSIZE];
    i32             m_iByteSizeIV;
    byte            m_rgbIV[GLOBALMAXSYMKEYSIZE];

    symKey();
    ~symKey();

    bool            getDataFromDoc();
    bool            getDataFromRoot(TiXmlElement*  pRootElement);
    char*           SerializetoString();
    bool            SerializetoFile(const char* fileName);
#ifdef TEST
    void            printMe();
#endif
};


class RSAKey : public KeyInfo {
public:
    i32             m_iByteSizeM;
    i32             m_iByteSizeD;
    i32             m_iByteSizeE;
    i32             m_iByteSizeP;
    i32             m_iByteSizeQ;
    i32             m_iByteSizeDP;
    i32             m_iByteSizeDQ;
    i32             m_iByteSizePM1;
    i32             m_iByteSizeQM1;

    //  These should be deleted eventually
    byte            m_rgbM[GLOBALMAXPUBKEYSIZE];
    byte            m_rgbD[GLOBALMAXPUBKEYSIZE];
    byte            m_rgbE[GLOBALMAXPUBKEYSIZE];
    byte            m_rgbP[GLOBALMAXPUBKEYSIZE];
    byte            m_rgbQ[GLOBALMAXPUBKEYSIZE];
    byte            m_rgbDP[GLOBALMAXPUBKEYSIZE];
    byte            m_rgbDQ[GLOBALMAXPUBKEYSIZE];
    byte            m_rgbPM1[GLOBALMAXPUBKEYSIZE];
    byte            m_rgbQM1[GLOBALMAXPUBKEYSIZE];

    bnum*           m_pbnM;
    bnum*           m_pbnP;
    bnum*           m_pbnQ;
    bnum*           m_pbnE;
    bnum*           m_pbnD;
    bnum*           m_pbnDP;
    bnum*           m_pbnDQ;
    bnum*           m_pbnPM1;
    bnum*           m_pbnQM1;

                    RSAKey();
                    ~RSAKey();

    bool            getDataFromDoc();
    bool            getDataFromRoot(TiXmlElement*  pRootElement);
    char*           SerializetoString();
    bool            SerializetoFile(const char* fileName);
    char*           SerializePublictoString();
#ifdef TEST
    void            printMe();
#endif
    void            wipeKeys();
};


int     algorithmIndexFromShortName(const char* szAlg);
int     algorithmIndexFromLongName(const char* szAlg);
char*   shortAlgNameFromIndex(int iIndex);
char*   cipherSuiteNameFromIndex(int iIndex);
int     cipherSuiteIndexFromName(const char* szCipherSuite);
char*   longAlgNameFromIndex(int iIndex);

int     pkAlgfromIndex(int iIndex);
int     hashAlgfromIndex(int iIndex);
int     padAlgfromIndex(int iIndex);

int     cipherSuiteIndexFromName(const char* szCipherSuite);
char*   cipherSuiteNameFromIndex(int iIndex);
int     modeSuitefromIndex(int iIndex);
int     pkSuitefromIndex(int iIndex);
int     hashSuitefromIndex(int iIndex);
int     skSuitefromIndex(int iIndex);


#endif


// -----------------------------------------------------------------------------


