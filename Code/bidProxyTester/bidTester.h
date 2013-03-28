//  File: bidTester.h
//      Tom Roeder
//
//  Description: tester for bidClient
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

#ifndef __BIDTESTER__H
#define __BIDTESTER__H

#include "timer.h"
#include "tinyxml.h"

#include <sys/types.h>
#include <sys/socket.h>

#include <list>
#include <string>
using std::list;
using std::string;
using std::pair;

// A class for performing bidClient tests as specified in a test XML file
// Usage example:
//   bidTester bt("/home/jlm/jlmcrypt/bidClient/tests/basicTest/", "tests.xml");
//   bt.Run("/home/jlm/jlmcrypt/");
class bidTester {
  public:
    bidTester(const string& path, const string& testFile);
    virtual ~bidTester();

    // Run the tests specified by the file. Writes the output to stdout.
    void Run(const char* directory);

  private:
    // a client to bid for an item
    class clientParams {
        string authFile;
        string keyFile;
        string certFile;
        string subject;
    };

    typedef pair<clientParams, int> bidClientParams;

    // a struct for holding the large set of parameters for a test
    // note that default copy construction here will copy the list correctly
    class bidTestParams {
        bool timed;
        bool expectSuccess;
        int repetitions;
        string name;
        list<bidClientParams> bids;
        clientParams seller;
        string expectedWinner;
    };

    bidTestParams m_defaultParams;
    string m_testFileName;
    TiXmlDocument m_testsDoc;
    list<bidTestParams> m_tests;
    bool m_reuseConnection;
    string m_serverAddress;
    u_short m_serverPort;
    string m_sellerClientAddress;
    string m_sellerClientPort;
    bool m_printToStdout;

    void copyParams(const bidTestParams& inParams, bidTestParams& outParams);

    // gets the parameter settings from a Default or Test node
    void getParams(const TiXmlNode* parent, const string& parentPath, bidTestParams& params);

    // runs an individual test and return success or failure, as well as the 
    // timing of the test, if any
    bool runTest(const char* directory, const bidTestParams& params);

    // disallow copy construction and assignment
    bidTester(const bidTester&);
    bidTester& operator=(const bidTester&);
};

#endif /* ndef __BIDTESTER__H */
