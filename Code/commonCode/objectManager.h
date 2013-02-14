//
//  objectManager.h
//      John Manferdelli
//
//  Description: objectManager
//
//  Copyright (c) 2011, Intel Corporation. Some contributions 
//    (c) John Manferdelli.  All rights reserved.
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


// ------------------------------------------------------------------------------


#ifndef _OBJECTMANAGER__H
#define _OBJECTMANAGER__H

#include "jlmTypes.h"
#include "jlmUtility.h"


#define MAXOBJSIZE 2048


template <class object> 
class objectManager {
private:
    int             m_iMaxObjects;
    int             m_iFilledObjects;
    object**        m_rgObjectTable;
    int             m_iSizeofStringTable;
    int             m_iStringTableUsed;
    char*           m_rgszStringTable;

public:
                    objectManager(int maxSize, int maxString);
                    ~objectManager();
object*             findObject(const char* szObjectName);
object*             getObject(int i);
int                 numObjectsinTable();
bool                addObject(object* pObject);
bool                deleteObject(const char* szName);
bool                DeserializeObjectTable(int iSize, const byte* buf);
bool                SerializeObjectTable(int* pi, byte** pbuf);
};


// --------------------------------------------------------------------------


#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <unistd.h>


//  object must have a name and Serialize/Deserialize methods
//      bool Deserialize(char* szObject) - initializes object from string
//      int  Serialize(char* szObject, int maxBufSize) - places serialized String in szObjects
//            and returns stringsize (or <0 if errror).  If szObject is NULL, 
//            it just returns size


template <class object>
objectManager<object>::objectManager(int maxSize, int maxChar)
{
    m_iMaxObjects= maxSize;
    m_iFilledObjects= 0;
    m_rgObjectTable= new object* [maxSize];
    m_rgszStringTable= (char*) malloc(maxChar);
    if(m_rgszStringTable==NULL) {
        fprintf(g_logFile, "Can't alloc object string table\n");
        throw("Cant alloc object string table\n");
    }
    m_iSizeofStringTable= maxChar;
    m_iStringTableUsed= 0;
}


template <class object>
objectManager<object>::~objectManager()
{
}


template <class object>
int objectManager<object>::numObjectsinTable()
{
    return m_iFilledObjects;
}


template <class object>
object* objectManager<object>::getObject(int i)
{
    return m_rgObjectTable[i];
}


template <class object>
bool  objectManager<object>::DeserializeObjectTable(int iSize, const byte* buf)
{
    int         iNumObjects;
    const char*       sz= reinterpret_cast<const char*>(buf);
    int         i, n;
    bool        fRet= true;
    object*     pObj= NULL;
    object*     pObj2= NULL;

    memcpy(&iNumObjects, sz, sizeof(int));
    sz+= sizeof(int);
#ifdef TEST
    fprintf(g_logFile, "%d bytes %d objects\n", iSize, iNumObjects);
#endif
    iSize-= 2*sizeof(int);

    for(i=0; i<iNumObjects; i++) {
        if((pObj=findObject(sz))==NULL) {
            pObj= new object();
        }
        if(!pObj->Deserialize(reinterpret_cast<const byte*>(sz), &n))
            return false;
        pObj2= findObject(sz);
        if(pObj2!=NULL) {
            *pObj2= *pObj;
        }
        else {
           if(!addObject(pObj))
            return false;
        }
        sz+= n;
    }

    return fRet;
}


//  Layout of buffer is
//      total buffersize (int)
//      numentries (int)
//      serialized data per entry


template <class object>
bool  objectManager<object>::SerializeObjectTable(int* piSize, byte** pbuf)
{
    int     i, n;
    int     iSize= 0;
    bool    fRet= true;
    int     iNumObjects= m_iFilledObjects;
    object* pObj= NULL;
    byte*   pb;

#ifdef TEST
    fprintf(g_logFile, "SerializeObjectTable NumObjects: %d\n", iNumObjects);
#endif
    for(i=0; i<iNumObjects;i++) {
        pObj= m_rgObjectTable[i];
        n= pObj->auxSize();
        if(n<0) {
            fRet= false;
            break;
        }
    iSize+= n;
    }

#ifdef TEST
    fprintf(g_logFile, "SerializeObjectTable size: %d\n", iSize);
#endif
    iSize+= 2*sizeof(int);
    *piSize= iSize;
    pb= (byte*) malloc(iSize);
    if(pb==NULL)
        return false;
    *pbuf= pb;

    memcpy(pb, &iSize, sizeof(int));
    pb+= sizeof(int);
    memcpy(pb, &iNumObjects, sizeof(int));
    pb+= sizeof(int);

    for(i=0; i<iNumObjects;i++) {
        pObj= m_rgObjectTable[i];
        n= pObj->Serialize(pb);
        if(n<0) {
            fRet= false;
            break;
        }
        pb+= n;
    }
    
#ifdef TEST
    fprintf(g_logFile, "SerializeObjectTable returning\n");
#endif
    return fRet;
}


template <class object>
object*  objectManager<object>::findObject(const char* szObjectName)
{
    int i;

#ifdef TEST
    fprintf(g_logFile, "objectManager<object>::findObject(%s)\n", szObjectName);
#endif
    for(i=0;i<m_iFilledObjects;i++) {
        if(strcmp(szObjectName, m_rgObjectTable[i]->getName())==0) {
            return m_rgObjectTable[i];
        }
    }
    return NULL;
}


template <class object>
bool  objectManager<object>::addObject(object* pObject)
{
    object*     pR= findObject(pObject->getName());

    if(pR!=NULL) {
        fprintf(g_logFile, "Duplicate object\n");
        return false;
    }

    if(m_iFilledObjects>=m_iMaxObjects) {
        fprintf(g_logFile, "No room in object table\n");
        return false;
    }
    
    m_rgObjectTable[m_iFilledObjects]= pObject;
    m_iFilledObjects++;
    return true;
}


template <class object>
bool   objectManager<object>::deleteObject(const char* szName)
{
    return false;
}


// ------------------------------------------------------------------------


#endif



