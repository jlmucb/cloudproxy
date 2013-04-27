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

#ifndef FILECLIENT
#include "accessControl.h"
#include "resource.h"
#endif


class fileServices{
public:
#ifndef FILECLIENT
    accessGuard m_guard;
#endif

                fileServices();
                ~fileServices();

#ifndef FILECLIENT
    bool        initFileServices(session& session, RSAKey* pPolicy, metaData* pMeta);
#else
    bool        initFileServices(session& session, RSAKey* pPolicy);
#endif

#ifndef FILECLIENT
    bool        validateAddPrincipalRequest(char** pszFile, 
                        resource** ppResource);
    bool        validateDeletePrincipalRequest(char** pszFile, 
                        resource** ppResource);
    bool        validateCreateRequest(char** pszFile, resource** ppResource);
    bool        validateGetSendDeleteRequest(char** pszFile, 
                        resource** ppResource);
    bool        validateAddOwnerRequest(char** pszFile, 
                        resource** ppResource);
    bool        validateRemoveOwnerRequest(char** pszFile, 
                        resource** ppResource);
    bool        validateRequest(char** pszFile, resource** ppResource);

    bool        translateLocationtoResourceName(const char* szLocation, const char* szResourceName, 
                    int size);
    bool        translateResourceNametoLocation(const char* szResourceName, char* szLocation, 
                    int size);

    bool        serversendResourcetoclient(safeChannel& fc, Request& oReq, 
                    int encType, byte* key, timer& accessTimer, timer& decTimer);
    bool        servergetResourcefromclient(safeChannel& fc, Request& oReq, 
                    int encType, byte* key, timer& accessTimer, timer& encTimer);

    bool        serverchangeownerofResource(safeChannel& fc, Request& oReq, 
                    int encType, byte* key, timer& accessTimer);

    bool        servercreateResourceonserver(safeChannel& fc, Request& oReq, 
                    int encType, byte* key, timer& accessTimer);
    bool        serverdeleteResource(safeChannel& fc, Request& oReq, 
                    int encType, byte* key, timer& accessTimer);

#else  // end of server services, beginning of client services

    bool        clientgetResourcefromserver(safeChannel& fc, const char* szResourceName, 
                    const char* szEvidence, const char* szFile, 
                    int encType, byte* key, timer& encTimer);
    bool        clientsendResourcetoserver(safeChannel& fc, const char* szSubject, 
                    const char* szResourceName, const char* szEvidence, 
                    const char* szFile, int encType, byte* key, timer& decTimer);
    bool        clientchangeownerResource(safeChannel& fc, const char* szAction, 
                    const char* szResourceName, const char* szEvidence, 
                    const char* szOutFile, int encType, byte* key);
    bool        clientcreateResourceonserver(safeChannel& fc, const char* szResourceName, 
                    const char* szSubject, const char* szEvidence, 
                    int encType, byte* key);
    bool        clientdeleteResource(safeChannel& fc, const char* szResourceName,
                    const char* szEvidence, const char* szFile, int encType, byte* key);
#endif  //client services
};


#endif


// -----------------------------------------------------------------------------------------


