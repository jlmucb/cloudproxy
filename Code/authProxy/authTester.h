//  File: fileTester.h
//      Tom Roeder
//
//  Description: tester for fileClient
//
//  Copyright (c) 2013, Google Inc. All rights reserved
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


// ------------------------------------------------------------------------

#ifndef __AUTHTESTER__H
#define __AUTHTESTER__H

#include "authClient.h"
#include "safeChannel.h"
#include "timer.h"
#include "tinyxml.h"

#include <sys/types.h>
#include <sys/socket.h>

#include <list>
#include <string>
using std::list;
using std::string;

// A class for performing authClient tests as specified in a test XML file
// Usage example:
//   authTester ft("/home/jlm/jlmcrypt/authClient/tests/basicTest/", "tests.xml");
//   ft.Run("/home/jlm/jlmcrypt/");
class authTester {
  public:
    authTester(const string& path, const string& testFile);
    virtual ~authTester();

    // Run the tests specified by the file. Writes the output to stdout.
    void Run(const char* directory);

  private:
    // a struct for holding the large set of parameters for a test
    struct fileTestParams {
        bool timed;
        bool expectSuccess;
        int repetitions;
        string name;
        string action;
        string authFile;
        string keyFile;
        string certFile;
        string subject;
        string remoteObject;
        string localObject;
        string match;
    };

    fileClient m_defaultClient;
    safeChannel m_defaultChannel;
    fileTestParams m_defaultParams;
    string m_testFileName;
    TiXmlDocument m_testsDoc;
    list<fileTestParams> m_tests;
    bool m_reuseConnection;
    list<string> m_filesToDelete;
    string m_serverAddress;
    u_short m_serverPort;
    bool m_printToStdout;

    void createResources(const string& parentPath, const TiXmlNode* parent);

    // generates a random file of a given length for use in testing
    // and stores the name of the file in a list to be deleted
    // at destructor time
    void generateRandomFile(int length, const string& filePath);

    // gets the parameter settings from a Default or Test node
    void getParams(const TiXmlNode* parent, const string& parentPath, fileTestParams& params);

    // runs an individual test and return success or failure, as well as the 
    // timing of the test, if any
    bool runTest(fileClient& client,
            safeChannel& channel,
            const fileTestParams& params,
            timer& testTimer); 

    // disallow copy construction and assignment
    authTester(const authTester&);
    authTester& operator=(const authTester&);
};

#endif /* ndef __AUTHTESTER__H */
