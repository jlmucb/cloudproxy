//
//  File: vault.cpp
//      John Manferdelli
//
//  Description:  tcInterface
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
#include "jlmcrypto.h"
#include "jlmUtility.h"
#include "modesandpadding.h"
#include "sha256.h"

#include "cert.h"
#include "resource.h"

#include "bignum.h"
#include "mpFunctions.h"
#include "encryptedblockIO.h"
#include "vault.h"
#include "algs.h"

#include <pthread.h>
#include <string.h>


#define MAXKEYSIZE 4096
#define MAXNUMKEYS   64

 
// ------------------------------------------------------------------


metaData::metaData()
{
    m_metaDataValid= false;
    m_fEncryptFile= false;
    pthread_mutex_init(&m_mutex, NULL);

    m_szprogramName= NULL;
    m_szdirectoryName= NULL;
    m_szmetadatadirectory= NULL;
    m_szmetadataFile= NULL;

    m_pRM= NULL;
    m_pPM= NULL;
    m_pKM= NULL;
}


metaData::~metaData()
{
}


bool metaData::initFileNames()
{
    char    szName[1024];

#ifdef TEST
    fprintf(g_logFile, "metaData::initFileNames\n");
    fflush(g_logFile);
#endif
    if(m_szdirectoryName==NULL)
        return false;
    if(m_szprogramName==NULL)
        return false;

    sprintf(szName, "%s/metadata", m_szdirectoryName, m_szprogramName);
    m_szmetadataFile= strdup(szName);

#ifdef TEST
    fprintf(g_logFile, "metaData::initFileNames, returned true\n");
    fflush(g_logFile);
#endif
    return true;
}


bool metaData::initMetaData(const char* directory, const char* program,
                            int encType, byte* key)
{
#ifdef TEST
    fprintf(g_logFile, "metaData::initMetaData\n");
    fflush(g_logFile);
#endif
    if(directory==NULL || program==NULL)
        return false;

    m_szdirectoryName= strdup(directory);
    m_szprogramName= strdup(program);

    m_pRM= new objectManager<resource>(NUMRESOURCES, NUMSTRINGS);
    if(m_pRM==NULL) {
        fprintf(g_logFile,"Cant init resource manager\n");
        return false;
    }
    m_pPM= new objectManager<PrincipalCert>(NUMPRINCIPALS, NUMSTRINGS);
    if(m_pPM==NULL) {
        fprintf(g_logFile, "Cant init principal manager\n");
        return false;
    }

    if(encType==DEFAULTENCRYPT) {
        m_encType= encType;
        m_fEncryptFiles= true;
        memcpy(m_rgKeys, key, 32);
    }
    else {
        m_encType= NOENCRYPT;
        m_fEncryptFiles= false;
    }

    m_metaDataValid= true;
#ifdef TEST
    fprintf(g_logFile, "metaData::initMetaData, returns true\n");
    fflush(g_logFile);
#endif
    return true;
}


bool metaData::addResource(resource* pResource)
{
    if(m_pRM==NULL || pthread_mutex_lock(&m_mutex)!=0)
        return false;
    bool fRet= m_pRM->addObject(pResource);
    pthread_mutex_unlock(&m_mutex);
    return fRet;
}


resource* metaData::findResource(const char* szName)
{
    if(m_pRM==NULL || pthread_mutex_lock(&m_mutex)!=0)
        return NULL;
    resource* res= m_pRM->findObject(szName);
    pthread_mutex_unlock(&m_mutex);
    return res;
}


bool metaData::deleteResource(resource* pResource)
{
    if(m_pRM==NULL || pthread_mutex_lock(&m_mutex)!=0)
        return false;
    bool fRet= m_pRM->deleteObject(pResource->m_szResourceName);
    pthread_mutex_unlock(&m_mutex);
    return fRet;
}


bool metaData::addPrincipal(PrincipalCert* pPrin)
{
    if(m_pPM==NULL || pthread_mutex_lock(&m_mutex)!=0)
        return false;
    bool fRet= m_pPM->addObject(pPrin);
    pthread_mutex_unlock(&m_mutex);
    return fRet;
}


PrincipalCert* metaData::findPrincipal(const char* szName)
{
    if(m_pPM==NULL || pthread_mutex_lock(&m_mutex)!=0)
        return NULL;
    PrincipalCert* res= m_pPM->findObject(szName);
    pthread_mutex_unlock(&m_mutex);
    return res;
}


bool metaData::deletePrincipal(PrincipalCert* pPrin)
{
    if(m_pPM==NULL || pthread_mutex_lock(&m_mutex)!=0)
        return false;
    bool fRet= m_pPM->deleteObject(pPrin->m_szPrincipalName);
    pthread_mutex_unlock(&m_mutex);
    return fRet;
}


bool     metaData::addKey(KeyInfo* key)
{
  return false;
}


KeyInfo* metaData::findKey(const char* szName)
{
  return NULL;
}


bool    metaData::saveMetaData()
{
#ifdef TEST
    fprintf(g_logFile, "metaData::saveMetaData\n");
    fflush(g_logFile);
#endif
    bool                fRet= true;
    int                 iSizeP= 0;
    int                 iSizeR= 0;
    byte*               bufP= NULL;
    byte*               bufR= NULL;
    int                 iWrite= -1;
    encryptedFilewrite  encFile;
    int                 filesize= 0;
    int                 datasize= 0;

    if(m_pPM==NULL || m_pRM || pthread_mutex_lock(&m_mutex)!=0)
        return false;

    try {

        if(m_szmetadataFile==NULL)
            throw("metaData::saveMetaData: no metadata file\n");

#ifdef  TEST
        fprintf(g_logFile, "metaData::saveMetaData: file: %s\n", m_szmetadataFile);
        fprintf(g_logFile, "metaData::saveMetaData: Serialize principal table\n");
        fflush(g_logFile);
#endif
        if(!m_pPM->SerializeObjectTable(&iSizeP, &bufP))
            throw("metaData::saveMetaData: Can't serialize principal table\n");
#ifdef  TEST
        fprintf(g_logFile, "metaData::saveMetaData: Serialize resource table\n");
#endif
        if(!m_pRM->SerializeObjectTable(&iSizeR, &bufR))
            throw("metaData::saveMetaData: Can't serialize principal table\n");
#ifdef  TEST
        fprintf(g_logFile, "metaData::saveMetaData: Serialize done %d %d\n",
                iSizeP, iSizeR);
#endif

        datasize= iSizeP+iSizeR;
        if(m_fEncryptFile) {
                // Fix: CBC only
                if((datasize%AES128BYTEBLOCKSIZE)==0) {
                    filesize= datasize+2*AES128BYTEBLOCKSIZE+SHA256_DIGESTSIZE_BYTES;
                }
                else {
                    filesize= AES128BYTEBLOCKSIZE+ SHA256_DIGESTSIZE_BYTES+
                        ((datasize+AES128BYTEBLOCKSIZE-1)/AES128BYTEBLOCKSIZE)*AES128BYTEBLOCKSIZE;
                }
        }
        else {
                filesize= datasize;
        }

        // open encrypted write
        if(m_encType==NOENCRYPT) {
            if(!encFile.initEnc(filesize, datasize, 0, 0, 0, NOALG)) {
                throw("metaData::saveMetaData: Cant init initialize file keys\n");
            }
        }
        else if(m_encType==DEFAULTENCRYPT) {
            if(!encFile.initEnc(filesize, datasize, m_rgKeys, 256,
                            AES128, SYMPAD, CBCMODE, HMACSHA256)) {
                throw("metaData::saveMetaData:: Cant init initialize file keys\n");
            }
        }
        else {
            throw("metaData::saveMetaData: invalid encryption\n");
        }

        // open file and write it out
        iWrite= open(m_szmetadataFile, O_WRONLY | O_CREAT | O_TRUNC, 0666);
        if(iWrite<0) 
            throw("metaData::saveMetaData: Can't create file\n");
        encFile.EncWrite(iWrite, bufP, iSizeP);
        encFile.EncWrite(iWrite, bufR, iSizeR);
    }
    catch(const char* szError) {
        fprintf(g_logFile, "Error: %s\n", szError);
        fflush(g_logFile);
        fRet= false;
    }

    if(iWrite>0)
        close(iWrite);

#ifdef  TEST
    fprintf(g_logFile, "\n");
    PrintBytes("metaData::saveMetaData: princpal table", bufP, iSizeP);
    fprintf(g_logFile, "\n");
    PrintBytes("metaData::saveMetaData: resource table", bufR, iSizeR);
    fprintf(g_logFile, "\n");
    fprintf(g_logFile, "metaData::saveMetaData: returning\n");
    fflush(g_logFile);
#endif

    if(bufR!=NULL) {
        free(bufR);
        bufR= NULL;
    }
    if(bufP!=NULL) {
        free(bufP);
        bufP= NULL;
    }

    pthread_mutex_unlock(&m_mutex);
    return fRet;
}


bool metaData::deleteKey(KeyInfo* key)
{
  return false;
}


bool metaData::restoreMetaData()
{
    bool                fRet= true;
    int                 iSizeP= 0;
    int                 iSizeR= 0;
    byte*               bufP= NULL;
    byte*               bufR= NULL;
    int                 iRead= -1;
    encryptedFileread   encFile;

#ifdef TEST
    fprintf(g_logFile, "metaData::restoreMetaData\n");
    fflush(g_logFile);
#endif
    // open file and read
    if(m_szmetadataFile==NULL) {
        fprintf(g_logFile, "metaData::restoreMetaData: no meta data file name\n");
        return false;
    }
    
    // get file size
    struct stat statBlock;
    if(stat(m_szmetadataFile, &statBlock)<0) {
        fprintf(g_logFile, "metaData::restoreMetaData: can't stat meta data file name\n");
        return false;
    }

    int                 filesize= statBlock.st_size;
    int                 datasize= 0;

    if(pthread_mutex_lock(&m_mutex)!=0)
        return false;

    try {

        // open read file
        iRead= open(m_szmetadataFile, O_RDONLY);
        if(iRead<0)
            throw("metaData::restoreMetaData: No restoreTableFile\n");
   
        // open encrypted read file
        if(m_encType==NOENCRYPT) {
            datasize= filesize;
            if(!encFile.initDec(filesize, datasize, 0, 0, 0, NOALG))
                throw("metaData::restoreMetaData: Cant init initialize file keys\n");
        }
        else if(m_encType==DEFAULTENCRYPT) {
            datasize= filesize-AES128BYTEBLOCKSIZE-SHA256_DIGESTSIZE_BYTES;
            if(!encFile.initDec(filesize, datasize, m_rgKeys, 256,
                                AES128, SYMPAD, CBCMODE, HMACSHA256)) 
                throw("metaData::restoreMetaData:: Cant init initialize file keys\n");
        }
        else {
            throw("metaData::restoreMetaData: invalid encryption\n");
        }

        // read buffers
        encFile.EncRead(iRead, (byte*)&iSizeP, sizeof(int));
#ifdef  TEST
        fprintf(g_logFile, "metaData::restoreMetaData:: iSizeP is %d\n", iSizeP);
#endif
        bufP= (byte*) malloc(iSizeP-sizeof(int));
        if(bufP==NULL)
            throw("metaData::restoreMetaData: Can't malloc principal buffer\n");
        encFile.EncRead(iRead, bufP, iSizeP-sizeof(int));
        encFile.EncRead(iRead, (byte*)&iSizeR, sizeof(int));
#ifdef  TEST
        fprintf(g_logFile, "metaData::restoreMetaData:: iSizeR is %d\n", iSizeR);
#endif
        bufR= (byte*) malloc(iSizeR-sizeof(int));
        if(bufR==NULL)
            throw("metaData::restoreMetaData: Can't malloc resource buffer\n");
        encFile.EncRead(iRead, bufR, iSizeR-sizeof(int));

#ifdef  TEST
        fprintf(g_logFile, 
                "metaData::restoreMetaData: %d bytes in principal, table %d bytes in resource table\n", 
                iSizeP, iSizeR);
#endif

        if(!m_pPM->DeserializeObjectTable(iSizeP, bufP))
            throw("metaData::restoreMetaData: Can't deserialize principal table\n");
        if(!m_pRM->DeserializeObjectTable(iSizeR, bufR)) 
            throw("metaData::restoreMetaData: Can't deserialize resource table\n");

        // go back and fix up owners on resource table
        aNode<PrincipalCert>*       pNode= NULL;
        resource*                   pResource= NULL;
        PrincipalCert*              pPrincipal= NULL;
        int                         i;
        char*                       pName= NULL;

        for(i=0;i<m_pRM->numObjectsinTable();i++) {
            pResource= m_pRM->getObject(i);
            pNode= pResource->m_myOwners.pFirst;
            while(pNode!=NULL) {
                pName= (char*)pNode->pElement;
                pPrincipal= m_pPM->findObject(pName);
                if(pPrincipal==NULL) {
                    fprintf(g_logFile, 
                            "metaData::restoreMetaData: Cant find %s in principal table\n", pName);
                    throw("metaData::restoreMetaData: remaperror\n");
                }
                pNode->pElement= pPrincipal;
                pNode= pNode->pNext;
            }
        }
    }
    catch(const char* szError) {
        fprintf(g_logFile, "Error: %s\n", szError);
        fRet= false;
    }
    close(iRead);

#ifdef  TEST
        fprintf(g_logFile, "\n");
        PrintBytes("metaData::restoreMetaData: princpal table", bufP, iSizeP);
        fprintf(g_logFile, "\n");
        PrintBytes("metaData::restoreMetaData: resource table", bufR, iSizeR);
        fprintf(g_logFile, "\n");
#endif
    if(bufP!=NULL) {
        free(bufP);
        bufP= NULL;
    }
    if(bufR!=NULL) {
        free(bufR);
        bufR= NULL;
    }

#ifdef  TEST
    fprintf(g_logFile, "metaData::restoreMetaData: returning\n");
#endif
    pthread_mutex_unlock(&m_mutex);
    return fRet;
}


// ----------------------------------------------------------------------



