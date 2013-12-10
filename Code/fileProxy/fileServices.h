//
//  File: fileServices.h
//  Desciption: File utilities for fileServer
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


// -----------------------------------------------------------------------------


#ifndef _FILESERVICES__H
#define _FILESERVICES__H

#include "jlmTypes.h"
#include "jlmUtility.h"
#include "keys.h"
#include "session.h"
#include "channel.h"
#include "safeChannel.h"
#include "timer.h"
#include "request.h"
#include "fileRequest.h"
#include "channelServices.h"

#ifndef FILECLIENT
#include "accessControl.h"
#include "resource.h"
#include "tao.h"
#endif


class fileServices {
public:
    PrincipalCert*  m_ppolicyCert;
    RSAKey*         m_pPolicy;
#ifndef FILECLIENT
    taoEnvironment* m_pTaoEnv;
    metaData*       m_pMetaData;
    session*        m_pSession;
    accessGuard     m_guard;
#endif
    safeChannel*    m_pSafeChannel;
    int             m_encType;  
    byte*           m_metadataKey;
    char*           m_szPrefix;

                    fileServices();
                    ~fileServices();

#ifndef FILECLIENT
    bool            initFileServices(session* session, PrincipalCert* ppolicyCert,
                                 taoEnvironment* pTaoEnv, 
                                 int encType, byte* metakey, 
                                 metaData* pMeta,
                                 safeChannel* pSafeChannel);
#else
    bool            initFileServices(session* session, PrincipalCert* ppolicyCert, 
                                     safeChannel* pSafeChannel);
#endif

#ifndef FILECLIENT
    bool            validateAddPrincipalRequest(fileRequest& oReq, char** pszFile, 
                                            resource** ppResource);
    bool            validateDeletePrincipalRequest(fileRequest& oReq, char** pszFile, 
                                               resource** ppResource);
    bool            validateCreateRequest(fileRequest& oReq, char** pszFile, 
                                            resource** ppResource);
    bool            validateGetSendDeleteRequest(fileRequest& oReq, char** pszFile, 
                                             resource** ppResource);
    bool            validateAddOwnerRequest(fileRequest& oReq, char** pszFile, 
                                            resource** ppResource);
    bool            validateRemoveOwnerRequest(fileRequest& oReq, char** pszFile, 
                                           resource** ppResource);
    bool            validateRequest(fileRequest& oReq, char** pszFile, 
                                            resource** ppResource);

    bool            translateLocationtoResourceName(const char* szLocation, 
                                                const char* szResourceName, 
                                                int size);
    bool            translateResourceNametoLocation(const char* szResourceName, 
                                                const char* szLocation, 
                                                int size);

    bool            serversendResourcetoclient(fileRequest& oReq, 
                                           timer& accessTimer, timer& decTimer);
    bool            servergetResourcefromclient(fileRequest& oReq, 
                                            timer& accessTimer, timer& encTimer);

    bool            serverchangeownerofResource(fileRequest& oReq, timer& accessTimer);

    bool            servercreateResourceonserver(fileRequest& oReq, timer& accessTimer);
    bool            serverdeleteResource(fileRequest& oReq, timer& accessTimer);

    bool            servergetProtectedFileKey(fileRequest& oReq, timer& accessTimer);

#else  // end of server services, beginning of client services

    bool            clientgetResourcefromserver(const char* szResourceName, 
                                            const char* szEvidence, 
                                            const char* szFile, 
                                            timer& encTimer);
    bool            clientsendResourcetoserver(const char* szSubject, 
                                           const char* szResourceName, 
                                           const char* szEvidence, 
                                           const char* szFile, timer& decTimer);
    bool            clientchangeownerResource(const char* szAction, 
                                          const char* szResourceName, 
                                          const char* szEvidence, 
                                          const char* szOutFile);
    bool            clientcreateResourceonserver(const char* szResourceName, 
                                             const char* szSubject, 
                                             const char* szEvidence);
    bool            clientdeleteResource(const char* szResourceName,
                                         const char* szEvidence, 
                                         const char* szFile);

    bool            clientgetProtectedFileKey(const char* file, timer& accessTimer);
#endif  //client services
};


#ifndef FILECLIENT


class filechannelServices : public channelServices {
public:
    fileServices    m_oFileServices;

    filechannelServices(u32);
    ~filechannelServices();

#ifndef FILECLIENT
    bool servergetProtectedFileKey(fileRequest& oReq, timer& accessTimer);
#else
    bool clientgetProtectedFileKey(const char* file, timer& accessTimer);
#endif
};


class fileServer;
class fileServerLocals{
public:
    fileServer*     m_pServerObj;
};

#endif


#endif  // FILESERVICES_H


// --------------------------------------------------------------------------------------


