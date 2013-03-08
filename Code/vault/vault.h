//
//  File: vault.h
//      John Manferdelli
//
//  Description:  vault for key management
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
#include "objectManager.h"
#include "keys.h"
#include "sha256.h"
#include "secPrincipal.h"

#include "tao.h"
#include "resource.h"

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>


// -----------------------------------------------------------------------


#ifndef _VAULT__H
#define _VAULT__H


#define NUMPRINCIPALS   512
#define NUMRESOURCES    512
#define NUMKEYS         512
#define NUMSTRINGS     4096


class extString {
public:
    int         m_position;
    int         m_length;
};


class keyEnt {
public:
    char*       m_szkeyName;
    u32         m_keyType;
    KeyInfo*    m_pKeyInfo;

    bool        Deserialize(const char* szObject);
    int         Serialize(const char* szObject, int maxBufSize);
};


class extPrincipalEnt {
public:
    extString           m_principalName;
    u16                 m_uPrincipalType;
    bool                m_fValidated;
    extString           m_principalCert;
};


class extResourceEnt {
public:
    extString               m_resourceName;
    u16                     m_type;
    int                     m_size;
    int                     m_numOwners;
};


class extKeyEnt {
public:
    extString   m_keyName;
    u16         m_keyType;
    extString   m_keyInfo;
};



class metaData {
public:
    bool                m_metaDataValid;
    bool                m_fEncryptFile;
    pthread_mutex_t     m_mutex;

    char*               m_szprogramName;
    char*               m_szdirectoryName;
    char*               m_szmetadatadirectory;
    char*               m_szmetadataFile;

    objectManager<resource>*            
                        m_pRM;
    objectManager<accessPrincipal>*     
                        m_pPM;
    objectManager<KeyInfo>*     
                        m_pKM;

                        metaData();
                        ~metaData();

    bool                initFileNames();
    bool                initMetaData(const char* directory, const char* program);

    bool                restoreMetaData(int encType, byte* key);
    bool                saveMetaData(int encType, byte* key);
    
    bool                addResource(resource* pResource);
    resource*           findResource(const char* szName);
    bool                deleteResource(resource* pResource);
    
    bool                addPrincipal(accessPrincipal* pPrin);
    accessPrincipal*    findPrincipal(const char* szName);
    bool                deletePrincipal(accessPrincipal* pPrin);

    bool                addKey(KeyInfo* key);
    KeyInfo*            findKey(const char* szName);
    bool                deleteKey(KeyInfo* key);
};


/*
 *  Saved meta data is in the following locations:
 *      Sealed keys: directory/program/meta/keys
 *      String tape: directory/program/meta/strings
 *      Access principal table: directory/program/meta/principaltable
 *      Resource table: directory/program/meta/resourcetable
 *      Key table: directory/program/meta/keytable
 *  Table files consist of:
 *      number of entries
 *      entries
 *
 *      For resource table, each entry is followed by numOwner strings
 */


#endif


// ----------------------------------------------------------------------


