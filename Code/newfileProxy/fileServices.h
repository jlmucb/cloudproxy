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
#include "fileServices.h"
#include "accessControl.h"
#include "resource.h"
#include "channel.h"
#include "safeChannel.h"
#include "timer.h"


class fileServices{
public:
                fileServices();
                ~fileServices();

    bool        validateAddPrincipalRequest(session& oKeys, char** pszFile, 
                        resource** ppResource);
    bool        validateDeletePrincipalRequest(session& oKeys, char** pszFile, 
                        resource** ppResource);
    bool        validateCreateRequest(session& oKeys, char** pszFile, resource** ppResource);
    bool        validateGetSendDeleteRequest(session& oKeys, char** pszFile, 
                        resource** ppResource);
    bool        validateAddOwnerRequest(session& oKeys, char** pszFile, 
                        resource** ppResource);
    bool        validateRemoveOwnerRequest(session& oKeys, char** pszFile, 
                        resource** ppResource);
    bool        validateRequest(session& oKeys, char** pszFile, resource** ppResource);

    bool    	createResource(safeChannel& fc, const string& subject, 
                    const string& evidenceFileName, const string& resource);
    bool        deleteResource(safeChannel& fc, const string& subject, 
                    const string& evidenceFileName, const string& resource);
    bool        readResource(safeChannel& fc, const string& subject, const string& evidenceFileName, 
                    const string& remoteResource, const string& localOutput);
    bool        writeResource(safeChannel& fc, const string& subject, const string& evidenceFileName, 
                    const string& remoteResource, const string& fileName);

    bool        translateLocationtoResourceName(const char* szLocation, const char* szResourceName, 
                    int size);
    bool        translateResourceNametoLocation(const char* szResourceName, char* szLocation, 
                    int size);

    bool        clientgetResourcefromserver(safeChannel& fc, const char* szResourceName, 
                    const char* szEvidence, const char* szFile, 
                    int encType, byte* key, timer& encTimer);
    bool        clientsendResourcetoserver(safeChannel& fc, const char* szSubject, 
                    const char* szResourceName, const char* szEvidence, 
                    const char* szFile, int encType, byte* key, timer& decTimer);

    bool        serversendResourcetoclient(safeChannel& fc, Request& oReq, session& oKeys, 
                    int encType, byte* key, timer& accessTimer, timer& decTimer);
    bool        servergetResourcefromclient(safeChannel& fc, Request& oReq, session& oKeys, 
                    int encType, byte* key, timer& accessTimer, timer& encTimer);

    bool        clientchangeownerResource(safeChannel& fc, const char* szAction, 
                    const char* szResourceName, const char* szEvidence, 
                    const char* szOutFile, int encType, byte* key);
    bool        serverchangeownerofResource(safeChannel& fc, Request& oReq, session& oKeys, 
                    int encType, byte* key, timer& accessTimer);

    bool        clientcreateResourceonserver(safeChannel& fc, const char* szResourceName, 
                    const char* szSubject, const char* szEvidence, 
                    int encType, byte* key);
    bool        servercreateResourceonserver(safeChannel& fc, Request& oReq, session& oKeys, 
                    int encType, byte* key, timer& accessTimer);
    bool        clientdeleteResource(safeChannel& fc, const char* szResourceName,
                    const char* szEvidence, const char* szFile, int encType, byte* key);
    bool        serverdeleteResource(safeChannel& fc, Request& oReq, session& oKeys, 
                    int encType, byte* key, timer& accessTimer);
};


#endif


// -----------------------------------------------------------------------------------------


