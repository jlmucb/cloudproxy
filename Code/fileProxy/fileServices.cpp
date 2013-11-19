//  File: fileServices.cpp
//      John Manferdelli
//
//  Description: file Services
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


#define MAXNAME 2048


// -----------------------------------------------------------------------------


#include "jlmTypes.h"
#include "logging.h"
#include "jlmcrypto.h"
#include "algs.h"
#include "keys.h"
#include "session.h"
#include "channel.h"
#include "safeChannel.h"
#include "jlmUtility.h"
#include "fileServices.h"
#include "sha256.h"
#include "encryptedblockIO.h"
#include "request.h"

#ifndef FILECLIENT
#include "encapsulate.h"
#include "vault.h"
#endif

#ifdef ESCROWKEYPRESENT
#include "escrow.inc"
#else
const char* g_szFileKeyEscrowCert= NULL;
#endif

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


// ------------------------------------------------------------------------



#define MAXPROTECTEDELEMENT 4096


const char* s_szProtectedElement=
"<ProtectedElement>\n"\
"%s"\
"<EncryptedBlob>\n"\
"%s"\
"</EncryptedBlob>\n"\
"</ProtectedElement>\n";


const char*  constructProtectedElement(const char* szMeta, const char* szEncryptedBlob)
{
    if(szMeta==NULL || szEncryptedBlob==NULL) {
        return NULL;
    }
    char    buf[MAXPROTECTEDELEMENT];

    if((strlen(s_szProtectedElement)+strlen(szMeta)+strlen(szEncryptedBlob)+32)>
            MAXPROTECTEDELEMENT)
        return NULL;

    sprintf(buf, s_szProtectedElement, szMeta, szEncryptedBlob);
    return canonicalizeXML(buf);
}


fileServices::fileServices()
{
#ifndef FILECLIENT
    m_pTaoEnv= NULL;
    m_pMetaData= NULL;
    m_pSession= NULL;
    m_metadataKey= NULL;
#endif
    m_ppolicyCert= NULL;
    m_pPolicy= NULL;
    m_szPrefix= strdup("//www.manferdelli.com/Gauss/");
    m_pSafeChannel= NULL;
    m_encType= NOENCRYPT;
}


fileServices::~fileServices()
{
    // DO NOT delete Tao or metadata
}

// ------------------------------------------------------------------------


#ifndef FILECLIENT

//  Server services


bool fileServices::initFileServices(session* psession, PrincipalCert* ppolicyCert,
                                    taoEnvironment* pTaoEnv, 
                                    int encType, byte* metaFileKey, 
                                    metaData* pMeta, safeChannel* pSafeChannel)
{
    int     i;

#ifdef TEST
    fprintf(g_logFile, "fileServices::initFileServices for Server\n");
    fprintf(g_logFile, 
      "session: %08x, policyCert: %08x, tao: %08x, encType: %d, meta: %08x, channel: %08x\n",
      psession, ppolicyCert, pTaoEnv, encType, pMeta, pSafeChannel);
    fflush(g_logFile);
#endif

    if(ppolicyCert==NULL) {
        fprintf(g_logFile, "fileServices::initFileServices: no policy principal cert\n");
        return false;
    }
    m_ppolicyCert= ppolicyCert;
    m_pPolicy= (RSAKey*)ppolicyCert->getSubjectKeyInfo();
    if(pTaoEnv==NULL) {
        fprintf(g_logFile, "fileServices::initFileServices: no Tao\n");
        return false;
    }
    m_pTaoEnv= pTaoEnv;

    if(psession==NULL) {
        fprintf(g_logFile, "fileServices::initFileServices: no session\n");
        return false;
    }
    m_pSession= psession;

    if(pMeta==NULL || !pMeta->m_metaDataValid) {
        fprintf(g_logFile, "fileServices::initFileServices: no metaData or invalid\n");
        return false;
    }
    m_pMetaData= pMeta;
    if(pSafeChannel==NULL ){
        fprintf(g_logFile, "fileServices::initFileServices: no safeChannel\n");
        return false;
    }
    m_pSafeChannel= pSafeChannel;
    m_encType= encType;
    if(metaFileKey==NULL) {
        fprintf(g_logFile, "fileServices::initFileServices: no metadata key\n");
        return false;
    }
    m_metadataKey= metaFileKey;

    // add channel principals to table
#ifdef TEST
        fprintf(g_logFile, 
                "fileServices::initFileServices, initializing %d channel principals\n",
                psession->m_iNumPrincipals);
        fflush(g_logFile);
#endif
    for(i=0; i<psession->m_iNumPrincipals; i++) {
        if(!m_pMetaData->addPrincipal(psession->m_rgPrincipalCerts[i])) {
            fprintf(g_logFile, "fileServices::initFileServices: cant add principalssafeChannel\n");
        }
    }

    // init
     if(!m_guard.m_fValid) {
        if(!m_guard.initGuard((KeyInfo*)m_pPolicy, pMeta, psession->m_iNumPrincipals, 
                              psession->m_rgPrincipalCerts)) {
            fprintf(g_logFile,
                    "theServiceChannel::serviceChannel: initAccessGuard returned false\n");
            return false;
        }
    }
#ifdef TEST
    fprintf(g_logFile, "fileServices::initFileServices, guard initialized\n");
    fflush(g_logFile);
#endif

    return true;
}


bool fileServices::validateCreateRequest(Request& oReq, char** pszFile, resource** ppResource)
{
    bool                    fAllowed= false;
    resource*               pResource= NULL;
    accessRequest           oAR;
    char                    szBuf[MAXNAME];

#ifdef TEST
    fprintf(g_logFile, "validateCreatefileServices\n");
    fflush(g_logFile);
#endif

    // initialize guard
    // Fixed?: this is certainly a bug and potentially a vulnerability in the code,
    szBuf[MAXNAME-1]= '\0';
    strncpy(szBuf, oReq.m_szResourceName, MAXNAME-1);
    char* p= szBuf;
    while(*p!=0)
        p++;
    p--;
    while(*p!='/' && p>szBuf)
        p--;
    if(*p!='/') {
        fprintf(g_logFile, "fileServices::validateCreatefileServices: Bad resource name\n");
        return false;
    }
    *p= 0; 

    oAR.m_szSubject= strdup(oReq.m_szSubjectName);
    oAR.m_szRequest= (char*)"create";
    oAR.m_szResource= strdup(szBuf);
    fAllowed= m_guard.permitAccess(oAR, oReq.m_szEvidence);
    if(!fAllowed) {
        fprintf(g_logFile, "fileServices::validateCreatefileServices: permitAccess returns false\n");
        return false;
    }
#ifdef  TEST
    fprintf(g_logFile, "permitAccess returns true in createResource adding %s\n", 
            oReq.m_szResourceName);
#endif

    pResource= new resource();
    if(pResource==NULL) {
        fprintf(g_logFile, "fileServices::validateCreatefileServices: can't new resource\n");
        return false;
    }
    pResource->m_szResourceName= strdup(oReq.m_szResourceName);
    pResource->m_uType= RESOURCEFILE;
    pResource->m_iSize= oReq.m_iResourceLength;
    if(!m_pMetaData->addResource(pResource)) {
        fprintf(g_logFile, 
               "fileServices::validateCreatefileServices: can't add resource to table\n");
        return false;
    }
    if(!translateResourceNametoLocation(oReq.m_szResourceName, szBuf, MAXREQUESTSIZE)) {
        fprintf(g_logFile, 
               "fileServices::validateCreatefileServices: translateResourceName failed\n");
        return false;
    }
    pResource->m_szLocation= strdup(szBuf);
    *pszFile= pResource->m_szLocation;
    *ppResource= pResource;
    return fAllowed;
}


bool  fileServices::validateGetSendDeleteRequest(Request& oReq, char** pszFile, 
                                                 resource** ppResource)
{
    resource*               pResource= NULL;
    accessRequest           oAR;

#ifdef TEST
    fprintf(g_logFile, "looking for resource %s\n", oReq.m_szResourceName);
#endif
    pResource= m_pMetaData->findResource(oReq.m_szResourceName);
    if(pResource==NULL) {
        fprintf(g_logFile, "fileServices::validateGetSendDeletefileServices: GetSendDelete pResource NULL, %s\n", oReq.m_szResourceName);
        fflush(g_logFile);
        return false;
    }
    if(pResource->m_szLocation==NULL) {
        fprintf(g_logFile, "fileServices::validateGetSendDeletefileServices: location NULL\n");
        return false;
    }

    // Get file location
    *pszFile= pResource->m_szLocation;
    *ppResource= pResource;

    // Access allowed?
    if(oReq.m_szSubjectName==NULL)
        oAR.m_szSubject= NULL;
    else
        oAR.m_szSubject= strdup(oReq.m_szSubjectName);
    // oAR.m_ifileServicesType= m_ifileServicesType;
    oAR.m_szResource= strdup(oReq.m_szResourceName);
    return m_guard.permitAccess(oAR, oReq.m_szEvidence);
}


bool  fileServices::validateAddOwnerRequest(Request& oReq, char** pszFile, 
                                            resource** ppResource)
                    
{
    return false;
}


bool  fileServices::validateAddPrincipalRequest(Request& oReq, char** pszFile, 
                                                resource** ppResource)
{
    return false;
}


bool  fileServices::validateDeletePrincipalRequest(Request& oReq, char** pszFile, 
                                                resource** ppResource)
{
    return false;
}


bool  fileServices::validateRemoveOwnerRequest(Request& oReq, char** pszFile, 
                                                resource** ppResource)
{
    return false;
}

 
bool  fileServices::validateRequest(Request& oReq, char** pszFile, resource** ppResource)
{
#ifdef TEST
    fprintf(g_logFile, "\nvalidateRequest\n");
    fflush(g_logFile);
#endif

    if(oReq.m_szResourceName==NULL) {
        fprintf(g_logFile, 
            "fileServices::validatefileServices: validatefileServices returning false\n");
        fflush(g_logFile);
        return false;
    }

    bool    fAllowed= false;
    if(strcmp(oReq.m_szAction, "createResource")== 0) {
        fAllowed= validateCreateRequest(oReq, pszFile, ppResource);
    }
    else if(strcmp(oReq.m_szAction, "deleteResource")== 0 ||
            strcmp(oReq.m_szAction, "getResource")== 0 ||
            strcmp(oReq.m_szAction, "sendResource")== 0) {
        fAllowed= validateGetSendDeleteRequest(oReq, pszFile, ppResource);
    }
    else if(strcmp(oReq.m_szAction, "addOwner")== 0) {
        fAllowed= validateAddOwnerRequest(oReq, pszFile, ppResource);
    }
    else if(strcmp(oReq.m_szAction, "removeOwner")== 0) {
        fAllowed= validateRemoveOwnerRequest(oReq, pszFile, ppResource);
    }

#ifdef TEST
    if(fAllowed) 
        fprintf(g_logFile, "validatefileServices returning true\n\n");
    else 
        fprintf(g_logFile, "validatefileServices returning false\n\n");
#endif
    return fAllowed;
}


bool fileServices::translateLocationtoResourceName(const char* szLocation, 
                                                   const char* szResourceName, 
                                                   int size)
{
    // FIX 
    return false;
}


bool fileServices::translateResourceNametoLocation(const char* szResourceName, 
                                                   const char* szLocation, 
                                                   int size)
{
    int             n;
    const char*     p= szResourceName;

    // strip prefix
    n= strlen(m_szPrefix);
   if(strncmp(p, m_szPrefix, n)!=0) {
        return false;
    } 

    p+= n;
    if((int)strlen(p)>=size) {
        return false;
    }

    strcpy((char*)szLocation, p);
    return true;
}


bool fileServices::serversendResourcetoclient(Request& oReq, 
                                              timer& accessTimer, 
                                              timer& decTimer)
{
    bool        fError;
    int         iRead= 0;
    int         filesize= 0;
    int         datasize= 0;
    byte        szBuf[MAXREQUESTSIZEWITHPAD];
    int         iLeft= MAXREQUESTSIZE;
    char*       p= (char*)szBuf;
    char*       szFile= NULL;
    const char* szError= NULL;
    int         type= CHANNEL_RESPONSE;
    byte        multi= 0;
    byte        final= 0;
    resource*   pResource= NULL;
    byte*       key= m_metadataKey;

#ifdef  TEST
    fprintf(g_logFile, "serversendResourcetoclient\n");
#endif
    // validate request (including access check) and get file location
    accessTimer.Start();
    fError= !validateRequest(oReq, &szFile, &pResource);
    accessTimer.Stop();

    // open File (if no Error)
    if(!fError) {
        iRead= openFile(szFile, &filesize);
        if(iRead<0) {
            fError= true;
            szError= "serversendResourcetoclient: Cant open file";
            fprintf(g_logFile, "serversendResourcetoclient: Open file error %s\n", szFile);
        }
    }

    if (!fError) {      
        datasize= pResource->m_iSize;
    }

    // construct response
    if(!constructResponse(fError, &p, &iLeft, oReq.m_szResourceName, datasize, NULL, szError)) {
        fprintf(g_logFile, "serversendResourcetoclient: constructResponse error\n");
        return false;
    }

    // send response
    m_pSafeChannel->safesendPacket(szBuf, 
                                   (int)strlen(reinterpret_cast<char*>(szBuf))+1, 
                                   type, multi, final);

    // if we sent an error to the client, then return false
    if (fError) return false;

    // send file
    if(pResource->m_fKeyValid) 
        key= pResource->m_rguKey1;
    else
        key= m_metadataKey;
    if(!sendFile(*m_pSafeChannel, iRead, filesize, datasize, m_encType, key, decTimer)) {
        fprintf(g_logFile, "serversendResourcetoclient: sendFile error\n");
        close(iRead);
        return false;
    }

#ifdef  TEST
    fprintf(g_logFile, "serversendResourcetoclient returns true\n");
#endif
    close(iRead);
    return true;
}


bool fileServices::getProtectedFileKey(Request& oReq, timer& accessTimer)
{
    bool                fError= true;
    byte                buf[MAXREQUESTSIZEWITHPAD];
    int                 iLeft= MAXREQUESTSIZE;
    char*               p= (char*)buf;
    const char*         szError= NULL;
    int                 type= CHANNEL_RESPONSE;
    byte                multi= 0;
    byte                final= 0;
    encapsulatedMessage oM;
    int                 plainKeyBlobsize;
    char                szbase64encryptedKey[8192];
    int                 base64encryptedKeysize= 8192;
    char*               szEncapsulateKeyInfo= NULL;
    RSAKey*             sealingKey= NULL;
    const char*         szProtectedElement= NULL;

#ifdef  TEST
    fprintf(g_logFile, "fileServices::getProtectedFileKey\n");
    oReq.printMe();
    fflush(g_logFile);
#endif

    // oReq.m_szResourceName should be key name but we don't look at it now
    if(g_szFileKeyEscrowCert==NULL) {
        fprintf(g_logFile, "fileServices::getProtectedFileKey: This app does not support excrow\n");
        fError= true;
        goto done;
    }

    // encapsulate and produce metadata
    // get embedded encapsulating key certificate
    oM.m_szCert= strdup(g_szFileKeyEscrowCert);

    // get key from Cert
    szEncapsulateKeyInfo= oM.getSubjectKeyInfo();
    if(szEncapsulateKeyInfo==NULL) {
        fprintf(g_logFile, "fileServices::getProtectedFileKey: cant extract sealing key from %s\n", 
                oM.m_szCert);
        fError= true;
        goto done;
    }

    // Make RSAKey
    sealingKey= (RSAKey*)RSAKeyfromkeyInfo(szEncapsulateKeyInfo);
    if(sealingKey==NULL) {
        fprintf(g_logFile, "fileServices::getProtectedFileKey: cant parse key\n");
        fError= true;
        goto done;
    }

    // get key and encrypt
    if(m_encType==DEFAULTENCRYPT) {
        plainKeyBlobsize= 16;  // AES128
    }
    else {
        fprintf(g_logFile, "fileServices::getProtectedFileKey: unsupported file encryption key\n");
        fError= true;
        goto done;
    }
    if(!oM.setplainMessage(plainKeyBlobsize, m_metadataKey)) {
        fprintf(g_logFile, "fileServices::getProtectedFileKey: cant set plaintext\n");
        fError= true;
        goto done;
    }

    // seal key
    if(!oM.sealKey(sealingKey)) {
        fprintf(g_logFile, "fileServices::getProtectedFileKey: cant seal key\n");
        fError= true;
        goto done;
    }

    if(!oM.encryptMessage()) {
        fprintf(g_logFile, "fileServices::getProtectedFileKey: cant encrypt message\n");
        fError= true;
        goto done;
    }

    // serialize metadata
    oM.m_szXMLmetadata= oM.serializeMetaData();
    if(oM.m_szXMLmetadata==NULL) {
        fprintf(g_logFile, "fileServices::getProtectedFileKey: cant serialize metadata\n");
        fError= true;
        goto done;
    }

    // base64 encode encrypted key
    if(!toBase64(oM.m_sizeEncrypted, oM.m_rgEncrypted, 
                 &base64encryptedKeysize, szbase64encryptedKey)) {
        fprintf(g_logFile, "fileServices::getProtectedFileKey: cant base64 encode blob\n");
        fError= true;
        goto done;
    }
    szProtectedElement= constructProtectedElement(oM.m_szXMLmetadata, 
                                        (const char*) szbase64encryptedKey);
    if(szProtectedElement==NULL) {
        fprintf(g_logFile, "fileServices::getProtectedFileKey: cant construct protected element\n");
        fError= true;
    }
    fError= false;

done: 
    // send response
    p= (char*)buf;
    if(!constructResponse(fError, &p, &iLeft, oReq.m_szResourceName, 0, szProtectedElement, szError)) {
        fprintf(g_logFile, "fileServices::getProtectedFileKey: constructResponse failed\n");
        return false;
    }
    m_pSafeChannel->safesendPacket(buf, strlen((char*)buf)+1, type, multi, final);

    if(szProtectedElement!=NULL) {
        free((void*)szProtectedElement);
        szProtectedElement= NULL;
    }

    return !fError;
}


bool fileServices::servercreateResourceonserver(Request& oReq,
                                                timer& accessTimer)
{
    bool            fAllowed= false;
    bool            fError;
    char            szBuf[MAXREQUESTSIZEWITHPAD];
    int             iLeft= MAXREQUESTSIZE;
    char*           p= (char*)szBuf;
    char*           szFile= NULL;
    const char*     szError= NULL;
    int             type= CHANNEL_RESPONSE;
    byte            multi= 0;
    byte            final= 0;
    resource*       pResource= NULL;
    resource*       pOwnerResource= NULL;
    PrincipalCert*  pSubject= NULL;
    PrincipalCert*  pOwnerPrincipal= NULL;
    Sha256          oHash;

#ifdef  TEST
    fprintf(g_logFile, "servercreateResourceonserver\n");
    oReq.printMe();
    fflush(g_logFile);
#endif
    // Does owner resource exist?
    if(strlen(oReq.m_szResourceName)>=MAXREQUESTSIZEWITHPAD) {
        fprintf(g_logFile, "servercreateResourceonserver: requested resource name too long\n");
        return false;
    }

    strcpy(szBuf, oReq.m_szResourceName);
    while(*p!=0)
        p++;
    p--;
    while(*p!='/' && p>szBuf)
        p--;
    if(*p!='/') {
        fprintf(g_logFile, "servercreateResourceonserver: bad resource name\n");
        return false;
    }
    *p= 0; 

    pOwnerResource= m_pMetaData->findResource(szBuf);
    if(pOwnerResource==NULL) {
#ifdef  TEST
        fprintf(g_logFile, "parent resource doesnt exist: %s\n", szBuf);
        fflush(g_logFile);
#endif
        pOwnerResource= new resource();
        if(pOwnerResource==NULL) {
            fprintf(g_logFile, "servercreateResourceonserver: can't new resource\n");
            return false;
        }
        pOwnerResource->m_szResourceName= strdup(szBuf);
        pOwnerResource->m_uType= RESOURCEDIRECTORY;
        if(!m_pMetaData->addResource(pOwnerResource)) {
            fprintf(g_logFile, "servercreateResourceonserver: can't add resource to table\n");
            return false;
        }

        // owner is the policy principal
        pOwnerPrincipal= m_ppolicyCert;
        if(pOwnerPrincipal==NULL) {
            fprintf(g_logFile, "servercreateResourceonserver: can't get owner principal\n");
            return false;
        }
        pOwnerResource->m_myOwners.append(pOwnerPrincipal);

        if(!translateResourceNametoLocation(pOwnerResource->m_szResourceName, szBuf,
                          MAXREQUESTSIZE)) {
            fprintf(g_logFile, "servercreateResourceonserver: translateResourceName failed %s\n", 
                    pOwnerResource->m_szResourceName);
            return false;
        }
        pOwnerResource->m_szLocation= strdup(szBuf);
        // Create directory if it doesn't exist
        struct stat  sb;
        if(stat(pOwnerResource->m_szLocation, &sb)!=0) {
            if(mkdir(pOwnerResource->m_szLocation, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH)!=0) {
                fprintf(g_logFile, "servercreateResourceonserver: can't make directory %s\n", 
                        pOwnerResource->m_szLocation);
                return false;
            }
            stat(pOwnerResource->m_szLocation, &sb);
        }
        if(!S_ISDIR(sb.st_mode)) {
            fprintf(g_logFile, "servercreateResourceonserver: no directory node\n");
            return false;
        }
    }

    if(oReq.m_szSubjectName==NULL) {
        fprintf(g_logFile, "servercreateResourceonserver: createResource must have subject\n");
        return false;
    }

    pSubject= m_pMetaData->findPrincipal(oReq.m_szSubjectName);
    if(pSubject==NULL) {
        fprintf(g_logFile, "servercreateResourceonserver: Subject principal doesn't exist %s\n", oReq.m_szSubjectName);
        return false;
    }

    fError= false;
    // does it already exist?
#ifdef TEST
    fprintf(g_logFile, "servercreateResourceonserver: find resource %s\n", 
            oReq.m_szResourceName);
    fflush(g_logFile);
#endif
    pResource= m_pMetaData->findResource(oReq.m_szResourceName);
    if(pResource!=NULL) {
        fError= true;
        szError= "servercreateResourceonserver: Resource exists";
    }

    if(!fError) {
        accessTimer.Start();
        fAllowed= validateRequest(oReq, &szFile, &pResource);
        accessTimer.Stop();
        if(fAllowed) {
            if(m_encType==DEFAULTENCRYPT) {
                pResource->m_fKeyValid= true;
                oHash.Init();
                oHash.Update(m_metadataKey, 2*AES128BYTEKEYSIZE);
                oHash.Update((byte*)pResource->m_szResourceName, 
                             strlen(pResource->m_szResourceName));
                oHash.Final();
                oHash.GetDigest(pResource->m_rguKey1);
                pResource->m_myOwners.append(pSubject);
            }
        }
        else {
            fError= true;
            szError= "servercreateResourceonserver: create disallowed";
        }
    }

    // send response
    p= (char*)szBuf;
    if(!constructResponse(fError, &p, &iLeft, oReq.m_szResourceName, 0, NULL, szError)) {
        fprintf(g_logFile, "servercreateResourceonserver: constructResponse failed\n");
        return false;
    }
    m_pSafeChannel->safesendPacket((byte*)szBuf, strlen(szBuf)+1, type, multi, final);

    // Should pResource be deleted?
#ifdef  TEST
    fprintf(g_logFile, "servercreateResourceonserver returning true\n");
    fflush(g_logFile);
#endif
    return !fError;
}


bool fileServices::servergetResourcefromclient(Request& oReq, timer& accessTimer, 
                                               timer& encTimer)
{
    bool            fError;
    int             iWrite= 0;
    int             size= 0;
    byte            szBuf[MAXREQUESTSIZEWITHPAD];
    int             iLeft= MAXREQUESTSIZE;
    char*           p= (char*)szBuf;
    const char*     szError= NULL;
    int             type= CHANNEL_RESPONSE;
    byte            multi= 0;
    byte            final= 0;
    char*           szOutFile= NULL;
    resource*       pResource= NULL;
    byte*           key= m_metadataKey;

#ifdef  TEST
    fprintf(g_logFile, "servergetResourcefromclient %d\n", size);
    fflush(g_logFile);
#endif
    // validate request (including access check) and get file location
    accessTimer.Start();
    fError= !validateRequest(oReq, &szOutFile, &pResource);
    accessTimer.Stop();
    fprintf(g_logFile, "Got fError %s\n", fError ? "true" : "false");   
    fflush(g_logFile);
    if (!fError) {      
        size= oReq.m_iResourceLength;
        pResource->m_iSize= size;
    }

    // open for writing
    if(!fError) {
        fprintf(g_logFile, "servergetResourcefromclient opening file %s\n", szOutFile); 
        fflush(g_logFile);
        iWrite= open(szOutFile, O_WRONLY | O_CREAT | O_TRUNC, 0666);
        if(iWrite<0) {
            fError= true;
            szError= "servergetResourcefromclient: Cant open file for writing\n";
            fprintf(g_logFile, "servergetResourcefromclient: Cant open file %s for writing\n", szOutFile);
        }
    }

    // send response
    if(!constructResponse(fError, &p, &iLeft, oReq.m_szResourceName, size, NULL, szError)) {
        fprintf(g_logFile, "servergetResourcefromclient: constructResponse failed\n");
        return false;
    } else {
        fprintf(g_logFile, "Constructed a response\n");
        fflush(g_logFile);
    }
    m_pSafeChannel->safesendPacket(szBuf, strlen(reinterpret_cast<char*>(szBuf))+1, type, multi, final);

    // if the reply was that there was an error, then return false
    if (fError) return false;

#ifdef  TEST
    fprintf(g_logFile, "servergetResourcefromclient getting file %s, size is %d\n", 
            szOutFile, size);
    fflush(g_logFile);
#endif
    // read file
    if(pResource->m_fKeyValid) 
        key= pResource->m_rguKey1;
    else
        key= m_metadataKey;
    pResource->m_iSize= size;
    if(!getFile(*m_pSafeChannel, iWrite, size, size, m_encType, key, encTimer)) {
        fprintf(g_logFile, "servergetResourcefromclient: getFile failed\n");
        close(iWrite);
        return false;
    }
    if(pResource!=NULL) {
        pResource->m_fIsPresent= true;
    }
    close(iWrite);

#ifdef  TEST
    fprintf(g_logFile, "servergetResourcefromclient returns true\n");
    fflush(g_logFile);
#endif
    return true;
}


bool fileServices::serverchangeownerofResource(Request& oReq, timer& accessTimer)
// includes delete
{
    resource*           pResource= NULL;
    PrincipalCert*      pPrinc= NULL;
    char*               szFile= NULL;

#ifdef  TEST
    fprintf(g_logFile, "serverchangeownerofResource\n");
    fflush(g_logFile);
#endif
    accessTimer.Start();
    if(!validateRequest(oReq, &szFile, &pResource))
        return false;
    accessTimer.Stop();

    if(strcmp(oReq.m_szAction, "addOwner")==0) {
        pPrinc= m_pMetaData->findPrincipal(oReq.m_szResourceName);
        if(pPrinc==NULL)
            return false;
        return pResource->m_myOwners.append(pPrinc);
        
    }

    if(strcmp(oReq.m_szAction, "removeOwner")==0) {
        pPrinc= m_pMetaData->findPrincipal(oReq.m_szResourceName);
        if(pPrinc==NULL)
            return false;
        return pResource->m_myOwners.deletenode(pPrinc);
    }
    return false;
}


bool fileServices::serverdeleteResource(Request& oReq, timer& accessTimer)
{
#if 0       // FIX
    resource*   pResource= NULL;
    char*       szFile= NULL;
    bool        fError;
    int         size= 0;
    char*       szError= NULL;
    char        szBuf[MAXREQUESTSIZEWITHPAD];
    int         type= CHANNEL_RESPONSE;
    byte        multi= 0;
    byte        final= 0;
    int         iLeft= MAXREQUESTSIZE;
    char*       p= szBuf;

#ifdef  TEST
    fprintf(g_logFile, "serverdeleteResource\n");
    fflush(g_logFile);
#endif
    accessTimer.Start();
    fError= !oReq.validateRequest(&szFile, &pResource);
    accessTimer.Stop();

    if(!fError) {
        // delete resource
#ifdef TEST
        fprintf(g_logFile, "serverdeleteResource: deleting %s\n", szFile);
        fflush(g_logFile);
#endif
        unlink(szFile); 
        // remove nodes on owner list and delete from resource table
        pResource->m_fIsDeleted= true;
    }
    else {
        szError= (char*)"serverDeleteResource: authorization error";
    }
    // send response
    if(!constructResponse(fError, &p, &iLeft, oReq.m_szResourceName, size, NULL, szError)) {
        fprintf(g_logFile, "servergetResourcefromclient: constructResponse failed\n");
        return false;
    }
    m_pSafeChannel->safesendPacket((byte*)szBuf, 
                                    strlen(reinterpret_cast<char*>(szBuf))+1, 
                                    type, multi, final);
    return !fError;
#endif
    return false;
}


#else  // end of server fileServices, beginning of client services


//  Client fileServices


bool fileServices::initFileServices(session* psession, PrincipalCert* ppolicyCert,
                                    safeChannel* pSafeChannel)
{
#ifdef TEST
    fprintf(g_logFile, "fileServices::initFileServices for Client\n");
    fflush(g_logFile);
#endif
    if(ppolicyCert==NULL) {
        fprintf(g_logFile, "fileServices::initFileServices: no policy principal cert\n");
        return false;
    }
    m_ppolicyCert= ppolicyCert;
    m_pPolicy= (RSAKey*) ppolicyCert->getSubjectKeyInfo();
    if(pSafeChannel==NULL ){
        fprintf(g_logFile, "fileServices::initFileServices: no safeChannel\n");
        return false;
    }
    m_pSafeChannel= pSafeChannel;
    m_encType= NOENCRYPT;

    return true;
}


bool fileServices::clientgetResourcefromserver(const char* szResourceName, 
                                               const char* szEvidence, 
                                               const char* szOutFile, 
                                               timer& encTimer)
{
    char        szBuf[MAXREQUESTSIZEWITHPAD];
    int         iLeft= MAXREQUESTSIZE;
    char*       p= szBuf;
    Response    oResponse;
    int         n= 0;
    int         type= CHANNEL_REQUEST;
    byte        multi=0;
    byte        final= 0;
    byte*       key= m_metadataKey;;

#ifdef  TEST
    fprintf(g_logFile, "clientgetResourcefromserver(%s, %s)\n", 
            szResourceName, szOutFile);
#endif
    // send request
    if(!constructRequest(&p, &iLeft, "getResource", NULL, szResourceName, 0, szEvidence)) {
        return false;
    }
    if((n=m_pSafeChannel->safesendPacket((byte*)szBuf, 
                                         strlen(szBuf)+1, CHANNEL_REQUEST, 0, 0)) <0) {
        return false;
    }

    // should be a CHANNEL_RESPONSE, not multipart
    n= m_pSafeChannel->safegetPacket((byte*)szBuf, MAXREQUESTSIZE, &type, &multi, &final);
    if(n<0) {
        fprintf(g_logFile, "clientgetResourcefromserver: getResource error %d\n", n);
        fprintf(g_logFile, "clientgetResourcefromserver: clientgetResourcefromserver %s\n",
                szBuf);
        return false;
    }
    szBuf[n]= 0;
    oResponse.getDatafromDoc(szBuf);

    // check response
    if(strcmp(oResponse.m_szAction, "accept")!=0) {
        fprintf(g_logFile, "Error: %s\n", oResponse.m_szErrorCode);
        return false;
    }

    // read and write file
    int         iWrite= open(szOutFile, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if(iWrite<0) {
        emptyChannel(*m_pSafeChannel, oResponse.m_iResourceLength, 0, NULL, 0, NULL);
        fprintf(g_logFile, "clientgetResourcefromserver: Cant open out file\n");
        return false;
    }
    // FIX: key
    if(!getFile(*m_pSafeChannel, iWrite, oResponse.m_iResourceLength, 
                oResponse.m_iResourceLength, 
                m_encType, key, encTimer)) {
        fprintf(g_logFile, "clientgetResourcefromserver: Can't get file\n");
        return false;
    }

    close(iWrite);
#ifdef  TEST
    fprintf(g_logFile, "clientgetResourcefromserver returns true\n");
#endif
    return true;
}


bool fileServices::clientcreateResourceonserver(const char* szResourceName, 
                                                const char* szSubject, 
                                                const char* szEvidence)
{
    char        szBuf[MAXREQUESTSIZEWITHPAD];
    int         iLeft= MAXREQUESTSIZE;
    char*       p= szBuf;
    Response    oResponse;
    int         n= 0;
    int         type= CHANNEL_REQUEST;
    byte        multi=0;
    byte        final= 0;

#ifdef  TEST
    fprintf(g_logFile, "clientcreateResourceonserver(%s)\n", szResourceName);
    fflush(g_logFile);
#endif
    // send request
    if(!constructRequest(&p, &iLeft, "createResource", szSubject, 
                                    szResourceName, 0, szEvidence)) {
        fprintf(g_logFile, "clientcreateResourceonserver: constructRequest returns false\n");
        return false;
    }

    if((n=m_pSafeChannel->safesendPacket((byte*)szBuf, strlen(szBuf)+1, CHANNEL_REQUEST, 0, 0)) <0) {
        fprintf(g_logFile, "clientcreateResourceonserver: safesendPacket after constructRequest returns false\n");
        return false;
    }

#ifdef  TEST1
    fprintf(g_logFile, "clientcreateResourceonserver just sent\n%s\n", szBuf);
    fflush(g_logFile);
#endif

    // should be a CHANNEL_RESPONSE, not multipart
    n= m_pSafeChannel->safegetPacket((byte*)szBuf, MAXREQUESTSIZE, &type, &multi, &final);
    if(n<0) {
        fprintf(g_logFile, "clientcreateResourceonserver: createResource error %d\n", n);
        return false;
    }
    szBuf[n]= 0;
#ifdef  TEST
    fprintf(g_logFile, "clientcreateResourceonserver got response\n%s\n", szBuf);
    fflush(g_logFile);
#endif
    oResponse.getDatafromDoc(szBuf);

    // check to see if the resource already exists or if it was successfully created. 
    // Either case is success.
    bool success = false;
    if (oResponse.m_szAction != NULL) {
        if (strcmp(oResponse.m_szAction, "accept") == 0) {
            success = true;
        } 
    else if (strcmp(oResponse.m_szErrorCode, "servercreateResourceonserver: Resource exists") == 0) {
            // then the resource already exists, so this is also success
            success = true;
#ifdef TEST
            fprintf(g_logFile, "Success in creation because the resource already exists\n");
#endif
        }
    }

    return success;
}


bool fileServices::clientsendResourcetoserver(const char* szSubject, 
                                              const char* szResourceName, 
                                              const char* szEvidence, 
                                              const char* szInFile, 
                                              timer& decTimer)
{
    char        szBuf[MAXREQUESTSIZEWITHPAD];
    int         iLeft= MAXREQUESTSIZE;
    char*       p= szBuf;
    Response    oResponse;
    int         n= 0;
    int         filesize= 0;
    int         datasize= 0;
    int         type= CHANNEL_REQUEST;
    byte        multi=0;
    byte        final= 0;
    int         iRead= 0;
    byte*       key= m_metadataKey;;

#ifdef  TEST
    fprintf(g_logFile, "clientsendResourcetoserver(%s, %s)\n", szResourceName, szInFile);
    fflush(g_logFile);
#endif

    // named owner should be in evidence.  If evidence is empty, pick first user
    // principal as user.   Later: compound principal?
    // Fix: Subject

    // open file and get size
    iRead= openFile(szInFile, &filesize);
    if(iRead<0) {
        fprintf(g_logFile, "clientsendResourcetoserver: Can't open file %s\n", szInFile);
        return false;
    }
    datasize= filesize;

    // send request
    if(!constructRequest(&p, &iLeft, "sendResource", szSubject, szResourceName, 
                         filesize, szEvidence)) {
        fprintf(g_logFile, "clientsendResourcetoserver: constructRequest returns false\n");
        return false;
    }
    if((n=m_pSafeChannel->safesendPacket((byte*)szBuf, strlen(szBuf)+1, CHANNEL_REQUEST, 0, 0)) <0) {
        fprintf(g_logFile, "clientsendResourcetoserver: safesendPacket after constructRequest returns false\n");
        return false;
    }

    // should be a CHANNEL_RESPONSE, not multipart
    n= m_pSafeChannel->safegetPacket((byte*)szBuf, MAXREQUESTSIZE, &type, &multi, &final);
    if(n<0) {
        fprintf(g_logFile, "clientsendResourcetoserver: sendResource error %d\n", n);
        return false;
    }
    szBuf[n]= 0;
    oResponse.getDatafromDoc(szBuf);

    // check response
    if(oResponse.m_szAction==NULL || strcmp(oResponse.m_szAction, "accept")!=0) {
        fprintf(g_logFile, "clientsendResourcetoserver: response is false\n");
        return false;
    }

#ifdef  TEST
    fprintf(g_logFile, "clientsendResourcetoserver sending file\n");
    fflush(g_logFile);
#endif
    // send file
    // Fix: key
    if(!sendFile(*m_pSafeChannel, iRead, filesize, datasize, m_encType, key, decTimer)) {
        close(iRead);
        return false;
    }
    close(iRead);   

#ifdef  TEST
    fprintf(g_logFile, "clientsendResourcetoserver returns true\n");
    fflush(g_logFile);
#endif
    return true;
}


bool fileServices::clientchangeownerResource(const char* szAction, 
                                             const char* szResourceName,
                                             const char* szEvidence, 
                                             const char* szOutFile)
{
    char        szBuf[MAXREQUESTSIZEWITHPAD];
    int         iLeft= MAXREQUESTSIZE;
    char*       p= (char*)szBuf;
    Response    oResponse;
    int         n= 0;
    int         type= CHANNEL_REQUEST;
    byte        multi=0;
    byte        final= 0;

#ifdef  TEST
    fprintf(g_logFile, "clientchangeownerofResource(%s, %s)\n", 
            szResourceName, szOutFile);
    fflush(g_logFile);
#endif

    // send request
    if(!constructRequest(&p, &iLeft, szAction, NULL, szResourceName, 0, szEvidence)) {
        fprintf(g_logFile, "clientchangeownerResource: constructRequest returns false\n");
        return false;
    }
    if((n=m_pSafeChannel->safesendPacket((byte*)szBuf, strlen(szBuf)+1, CHANNEL_REQUEST, 0, 0)) <0) {
        return false;
    }

    // should be a CHANNEL_RESPONSE, not multipart
    n= m_pSafeChannel->safegetPacket((byte*)szBuf, MAXREQUESTSIZE, &type, &multi, &final);
    if(n<0) {
        fprintf(g_logFile, "clientchangeownerResource: sendResource error %d\n", n);
        return false;
    }
    szBuf[n]= 0;
    oResponse.getDatafromDoc(szBuf);
    if(strcmp(oResponse.m_szAction, "accept")==0)
        return true;
    if(oResponse.m_szErrorCode!=NULL)
        fprintf(g_logFile, "Error in %s: %s\n", oResponse.m_szAction, oResponse.m_szErrorCode);

#ifdef  TEST
    fprintf(g_logFile, "clientchangeownerofResource returns false\n");
#endif
    return false;
}


bool fileServices::clientdeleteResource(const char* szResourceName,
                                        const char* szEvidence, 
                                        const char* szFile)
{
    char        szBuf[MAXREQUESTSIZEWITHPAD];
    int         iLeft= MAXREQUESTSIZE;
    char*       p= (char*)szBuf;
    Response    oResponse;
    int         n= 0;
    int         type= CHANNEL_REQUEST;
    byte        multi=0;
    byte        final= 0;

#ifdef  TEST
    fprintf(g_logFile, "clientdeleteResource(%s, %s)\n", szResourceName, szFile);
    fflush(g_logFile);
#endif
    // send request
    if(!constructRequest(&p, &iLeft, "deleteResource", NULL, szResourceName, 0, szEvidence)) {
        fprintf(g_logFile, "clientdeleteResource: constructRequest returns false\n");
        return false;
    }
#ifdef  TEST1
    fprintf(g_logFile, "clientdeleteResource request\n%s\n", szBuf);
    fflush(g_logFile);
#endif
    if((n=m_pSafeChannel->safesendPacket((byte*)szBuf, strlen(szBuf)+1, CHANNEL_REQUEST, 0, 0)) <0) {
        return false;
    }

    // should be a CHANNEL_RESPONSE, not multipart
    n= m_pSafeChannel->safegetPacket((byte*)szBuf, MAXREQUESTSIZE, &type, &multi, &final);
    if(n<0) {
        fprintf(g_logFile, "clientdeleteResource: sendResource error %d\n", n);
        return false;
    }
    szBuf[n]= 0;
    oResponse.getDatafromDoc(szBuf);
    if(strcmp(oResponse.m_szAction, "accept")==0)
        return true;
    if(oResponse.m_szErrorCode!=NULL)
        fprintf(g_logFile, "Error in %s: %s\n", oResponse.m_szAction, oResponse.m_szErrorCode);

#ifdef  TEST
    fprintf(g_logFile, "clientdeleteResource returns false\n");
    fflush(g_logFile);
#endif
    return false;
}

#endif // client interfaces


// ---------------------------------------------------------------------------------


