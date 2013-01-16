//
//  jlmUtility.h
//      John Manferdelli
//
//  Description: support classes (lists, etc)
//
//  Copyright (c) 2011, John Manferdelli.  All rights reserved.
//  Some portions Copyright (c) Intel Corporation. All rights reserverd
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
//


// ----------------------------------------------------------------------------


#ifndef _JLMUTILITY__H
#define _JLMUTILITY__H

#include "jlmTypes.h"
#include "tinyxml.h"
#include "time.h"


template <class T>
class aNode {
public:
    T*          pElement;
    aNode<T>*   pNext;

    aNode<T>*   Next();
                aNode();
                ~aNode();
};


template <class T>
class aList {
public:
    aNode<T>*   pFirst;

    bool        isEmpty();
    bool        insert(T* pt);
    bool        append(T* pt);
    bool        deletenode(T* pt);

                aList();
};


class Period {
public:
    struct tm      notBefore;
    struct tm      notAfter;
};


char*  gmTimetoUTCstring(tm* pt);
bool   UTCtogmTime(char* szTime, tm* pt);


template <class T>
aNode<T>*  aNode<T>::Next()
{
    return pNext;
}


template <class T>
aNode<T>::aNode()
{
    pElement= NULL;
    pNext= NULL;
}


template <class T>
aNode<T>::~aNode()
{
}


template <class T>
bool  aList<T>::isEmpty()
{
    return(pFirst==NULL);
}


template <class T>
bool aList<T>::insert(T* pt)
{
    aNode<T>* pNew= new aNode<T>;

    if(pNew==NULL)
        return false;

    pNew->pNext= pFirst;
    pNew->pElement= pt;
    return true;
}


template <class T>
bool aList<T>::append(T* pt)
{
    aNode<T>* pNew= new aNode<T>;
    aNode<T>* pNode= NULL;

    if(pNew==NULL)
        return false;

    if(pFirst==NULL) {
        pFirst= pNew;
        pNew->pNext= NULL;
        pNew->pElement= pt;
        return true;
    }

    pNode= pFirst;
    while(pNode->pNext!=NULL)
        pNode= pNode->pNext;

    pNode->pNext= pNew;
    pNew->pNext= NULL;
    pNew->pElement= pt;

    return true;
}


template <class T>
bool aList<T>::deletenode(T* pt)
{
    aNode<T>* pNew= new aNode<T>;
    aNode<T>* pNode= NULL;

    if(pNew==NULL)
        return false;

    if(pFirst==NULL) {
        pFirst= pNew;
        pNew->pNext= NULL;
        pNew->pElement= pt;
        return true;
    }

    pNode= pFirst;
    while(pNode->pNext!=NULL)
        pNode= pNode->pNext;

    pNode->pNext= pNew;
    pNew->pNext= NULL;
    pNew->pElement= pt;

    return true;
}


template <class T>
aList<T>::aList()
{
    pFirst= NULL;
}

void        revmemcpy(byte* pTo, byte* pFrom, int len);
bool        SafeStringAppend(char** pszCur, char* szToAppend, int* piLeft);
char*       canonicalize(TiXmlNode* pNode);
void        printIndent(char* szItem, int indent, bool fEnd=false);
void        Explore(TiXmlNode* pNode, int indent);
TiXmlNode*  Search(TiXmlNode* pNode, char* szElementName);
bool        testCanonical(char* szInFile, char* szElementName);
int         ConvertToHexString(int iSizeBuf, byte* rgbBuf, int iSizeOut, char* szOut);
int         ConvertFromHexString(char* szIn, int iSizeOut, byte* rgbBuf);
bool        Sha256Hash(int iSizeIn, byte* pIn, int* piOut, byte* pOut);
char*       readandstoreString(char* szFile);
bool        saveBlobtoFile(char* szFile, byte* buf, int size);
bool        getBlobfromFile(char* szFile, byte* buf, int* psize);
char*       canonicalizeXML(char* szXML);


inline bool safeTransfer(char** pp, int* piLeft, char* pFrom)
{
    int k= strlen(pFrom);

    if(k>=*piLeft)
        return false;
    strcpy(*pp, pFrom);
    *pp+= k;
    *piLeft-= k;
    (*pp)[0]= '\0';

    return true;
}


#endif


// ---------------------------------------------------------------------------


