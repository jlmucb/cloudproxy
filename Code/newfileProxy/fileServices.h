//
//  fileServices.h
//      John Manferdelli
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

#ifndef FILECLIENT
#include "accessControl.h"
#include "resource.h"
#include "tao.h"
#endif


class fileServices{
public:
    RSAKey*         m_pPolicy;
#ifndef FILECLIENT
    taoEnvironment* m_pTaoEnv;
    metaData*       m_pMetaData;
    session*        m_pSession;
    accessGuard     m_guard;
#endif
    safeChannel*    m_pSafeChannel;
    int             m_encType;  
    char*           m_szPrefix;

                fileServices();
                ~fileServices();

#ifndef FILECLIENT
    bool        initFileServices(session* session, RSAKey* pPolicy, 
                                 taoEnvironment* pTaoEnv, 
                                 int encType, metaData* pMeta,
                                 safeChannel* pSafeChannel);
#else
    bool        initFileServices(session* session, RSAKey* pPolicy, safeChannel* pSafeChannel);
#endif

#ifndef FILECLIENT
    bool        validateAddPrincipalRequest(Request& oReq,
                                            char** pszFile, 
                                            resource** ppResource);
    bool        validateDeletePrincipalRequest(Request& oReq,
                                               char** pszFile, 
                                               resource** ppResource);
    bool        validateCreateRequest(Request& oReq,
                                      char** pszFile, 
                                      resource** ppResource);
    bool        validateGetSendDeleteRequest(Request& oReq,
                                             char** pszFile, 
                                             resource** ppResource);
    bool        validateAddOwnerRequest(Request& oReq,
                                        char** pszFile, 
                                        resource** ppResource);
    bool        validateRemoveOwnerRequest(Request& oReq,
                                           char** pszFile, 
                                           resource** ppResource);
    bool        validateRequest(Request& oReq,
                                char** pszFile, 
                                resource** ppResource);

    bool        translateLocationtoResourceName(const char* szLocation, 
                                                const char* szResourceName, 
                                                int size);
    bool        translateResourceNametoLocation(const char* szResourceName, 
                                                const char* szLocation, 
                                                int size);

    bool        serversendResourcetoclient(Request& oReq, 
                                           timer& accessTimer, timer& decTimer);
    bool        servergetResourcefromclient(Request& oReq, 
                                            timer& accessTimer, timer& encTimer);

    bool        serverchangeownerofResource(Request& oReq, timer& accessTimer);

    bool        servercreateResourceonserver(Request& oReq, timer& accessTimer);
    bool        serverdeleteResource(Request& oReq, timer& accessTimer);

#else  // end of server services, beginning of client services

    bool        clientgetResourcefromserver(const char* szResourceName, 
                                            const char* szEvidence, 
                                            const char* szFile, 
                                            timer& encTimer);
    bool        clientsendResourcetoserver(const char* szSubject, 
                                           const char* szResourceName, 
                                           const char* szEvidence, 
                                           const char* szFile, timer& decTimer);
    bool        clientchangeownerResource(const char* szAction, 
                                          const char* szResourceName, 
                                          const char* szEvidence, 
                                          const char* szOutFile);
    bool        clientcreateResourceonserver(const char* szResourceName, 
                                             const char* szSubject, 
                                             const char* szEvidence);
    bool        clientdeleteResource(const char* szResourceName,
                                     const char* szEvidence, 
                                     const char* szFile);
#endif  //client services
};


#endif


// -----------------------------------------------------------------------------------------


