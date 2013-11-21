//  File: fileTester.cpp
//      Tom Roeder
//
//  Description: test manager for fileClient
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

#include "logging.h"
#include "fileTester.h"
#include "fileServer.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <iostream>
#include <fstream>
#include <sstream>
using std::ifstream;
using std::ofstream;
using std::stringstream;

fileTester::fileTester(const string& path, const string& testFile) 
    : m_defaultClient(),
    m_defaultChannel(),
    m_defaultParams(),
    m_testFileName(path + testFile),
    m_testsDoc(path + testFile),
    m_tests(),
    m_reuseConnection(false),
    m_filesToDelete(),
    m_serverAddress("127.0.0.1"),
    m_serverPort(SERVICE_PORT)
{
    // parse the xml and construct the default parameters and any required resources
    m_testsDoc.LoadFile();

#if 0
    const char* szDesignatedKeyNegoServer= getenv("CPFileServerAddress");
    if(szDesignatedKeyNegoServer!=NULL) {
        m_serverAddress= strcpy();
    }
#endif
    
    const TiXmlElement* curElt = m_testsDoc.RootElement();
    // look at the attributes on the root to see if we are to reuse the connection or 
    // establish a new connection for each test
    bool connection = false;
    if (curElt->QueryBoolAttribute("reuseConnection", &connection) == TIXML_SUCCESS) {
        m_reuseConnection = connection;
    }

    // get the server IP address from the config file, if any
    string serverAddress;
    if (curElt->QueryStringAttribute("serverAddress", &serverAddress) == TIXML_SUCCESS) {
        m_serverAddress = serverAddress;
    }

    int port = 0;
    if (curElt->QueryIntAttribute("serverPort", &port) == TIXML_SUCCESS) {
        m_serverPort = static_cast<u_short>(port);
    }

    bool print = false;
    if (curElt->QueryBoolAttribute("print", &print) == TIXML_SUCCESS) {
        m_printToStdout = print;
    }

    // walk the children of the root and handle Default, Resources, and Test children
    const TiXmlNode* child = NULL;
    while((child = curElt->IterateChildren(child))) {
        const string& name = child->ValueStr();
        if (name.compare("Default") == 0) {
            // convert the values to a parameter set
            getParams(child, path, m_defaultParams);
        } else if (name.compare("Resources") == 0) {
            createResources(path, child);
        } else if (name.compare("Test") == 0) {
            // copy the default params and update them with the parameters from the test 
            fileTestParams params = m_defaultParams;            
            getParams(child, path, params);
    
            // store this test for later execution
            m_tests.push_back(params);
        } else {
            throw "Unknown test element\n";
        }
    } 
}    

fileTester::~fileTester() {
    // don't delete the test files: this makes multiple test runs more efficient,
    // since they can reuse the test files (and the encryption is still different
    // since the IV is different)
//    // delete all the files we created for this test
//    list<string>::iterator it = m_filesToDelete.begin();
//    for( ; m_filesToDelete.end() != it; ++it) {
//        unlink(it->c_str());
//    }
}

void fileTester::createResources(const string& parentPath, const TiXmlNode* parent) {
    const TiXmlNode* child = NULL;
    while((child = parent->IterateChildren(child))) {
        const TiXmlElement* elt = child->ToElement();
        string fileName;
        int size = 0;
        if (elt->QueryStringAttribute("name", &fileName) == TIXML_SUCCESS &&
            elt->QueryIntAttribute("size", &size) == TIXML_SUCCESS) {
            string filePath = parentPath + fileName;

            // only generate the file if it's not there or is the wrong size
            struct stat fileStatus;
            int rv = stat(filePath.c_str(), &fileStatus);
            bool goodFile = (rv == 0) && (fileStatus.st_size == size);
            if (!goodFile) generateRandomFile(size, filePath);
        
            // we don't currently clean up the files we create, since it 
            // puts too much load on the disk for a large test suite
            //m_filesToDelete.push_back(filePath);
        } else {
            throw "Could not get the name and size of this resource\n";
        }
    }
}

void fileTester::generateRandomFile(int length, const string& filePath) {
    if (length <= 0) {
        throw "Can't generate a random file of length <= 0";
    }

    // read from /dev/urandom and write to the filename given
    ifstream randFile;
    ofstream outFile;
    randFile.open("/dev/urandom", ifstream::binary | ifstream::in);
    outFile.open(filePath.c_str(), ofstream::binary | ofstream::trunc | ofstream::out);

    // use a buffer of a convenient length    
    char buf[MAXREQUESTSIZE];
    int bytesRemaining = length;
    
    // read bytes from /dev/urandom and write them to the randFile
    while(bytesRemaining > 0) {
        int readAmount = bytesRemaining < MAXREQUESTSIZE ? bytesRemaining : MAXREQUESTSIZE;
        randFile.read(buf, readAmount);
        outFile.write(buf, readAmount);
        bytesRemaining -= readAmount;
    } 

    randFile.close();
    outFile.close();
    return;
}

void fileTester::getParams(const TiXmlNode* parent, const string& parentPath, fileTestParams& params) {
    // check for the 'timed', 'repetitions', and 'name' attributes
    bool timed = false;
    const TiXmlElement* elt = parent->ToElement();
    if (elt->QueryBoolAttribute("timed",  &timed) == TIXML_SUCCESS) {
        params.timed = timed;
    }
    
    // the default is to repeat the test exactly once, unless otherwise specified
    int repetitions = 1;
    if (elt->QueryIntAttribute("repetitions", &repetitions) == TIXML_SUCCESS) {
        params.repetitions = repetitions; 
    }

    string testName;
    if (elt->QueryStringAttribute("name", &testName) == TIXML_SUCCESS) {
        params.name = testName;
    }

    string expectation;
    if (elt->QueryStringAttribute("expect", &expectation) == TIXML_SUCCESS) {
        if (expectation.compare("pass") == 0) {
            params.expectSuccess = true;
        } else if (expectation.compare("fail") == 0) {
            params.expectSuccess = false;
        } else {
            throw "Unknown 'expect' attribute in Test or Defaults\n";
        }
    } else {
        // unless otherwise specified, tests are expected to pass
        params.expectSuccess = true;
    }

    // iterate over the children to get the appropriate parameters
    const TiXmlNode* child = NULL;
    while((child = parent->IterateChildren(child))) {
        const string& name = child->ValueStr();
        const TiXmlElement* childElt = child->ToElement();
        const string& text(childElt->GetText());
        if (name.compare("Action") == 0) {
            params.action = text;
        } else if (name.compare("Authorization") == 0) {
            params.authFile = parentPath + text;
        } else if (name.compare("PrivateKeys") == 0) {
            params.keyFile = parentPath + text;
        } else if (name.compare("PublicKeys") == 0) {
            params.certFile = parentPath + text;
        } else if (name.compare("Subject") == 0) {
            params.subject = text;
        } else if (name.compare("RemoteObject") == 0) {
            params.remoteObject = text;
        } else if (name.compare("LocalObject") == 0) {
            params.localObject = parentPath + text;
        } else if (name.compare("Match") == 0) {
            params.match = parentPath + text;
        } else {
            throw "Unknown parameter name\n";
        }
    }
}

void fileTester::Run(const char* directory) {
    bool establishedDefaultConnection = false;
#ifdef TEST
    fprintf(g_logFile, "Entering  fileTester::Run\n");
    fflush(g_logFile);
#endif 

    // establish the default channel as long as there 
    // is a default keyFile and certFile
    if (!m_defaultParams.keyFile.empty() && !m_defaultParams.certFile.empty()) {
        if (!m_defaultClient.establishConnection(
                            m_defaultParams.keyFile.c_str(),
                            m_defaultParams.certFile.c_str(),
                            directory,
                            m_serverAddress.c_str(),
                            m_serverPort)) {
        } else {
            establishedDefaultConnection = true;
        }
    }
                           
#ifdef TEST
    fprintf(g_logFile, "establishConnection returned in fileTester::Run\n");
    fflush(g_logFile);
#endif 
    list<fileTestParams>::iterator it = m_tests.begin();
    for( ; m_tests.end() != it; ++it) {
        if (m_printToStdout) printf("%s: ", it->name.c_str());

        bool result = false;
        if (it->repetitions <= 0) {
            if (m_printToStdout) printf("[FAILED]\n");
            fprintf(g_logFile, "%s: (Bad number of repetitions %d) [FAILED]\n", it->name.c_str(), it->repetitions);
            continue;
        }

        timer testTimer;
        if (establishedDefaultConnection && m_reuseConnection) {
            try {
                for(int i = 0; i < it->repetitions; ++i) {
                    result = runTest(m_defaultClient,
                                m_defaultChannel,
                                *it,
                                testTimer);
                    if (it->timed) {
                        fprintf(g_logFile, "Timers for test %s: ", it->name.c_str());
                        m_defaultClient.printTimers(g_logFile);
                        m_defaultClient.resetTimers();
                    }
                }
            } catch (const char* err) {
                if (m_printToStdout) printf("Error: '%s' ", err);
                fprintf(g_logFile, "Error: %s\n", err);
                result = false;
            }
        } else {
            // establish a new connection for this test
            for(int i = 0; i < it->repetitions; ++i) {
                fileClient client;
                result = client.establishConnection(
                        it->keyFile.c_str(),
                        it->certFile.c_str(),
                        directory,
                        m_serverAddress.c_str(),
                        m_serverPort);

                try {
                    result = runTest(client,
                                client.m_fc,
                                *it,
                                testTimer);
                    if (it->timed) {
                        fprintf(g_logFile, "Timers for test %s: ", it->name.c_str());
                        client.printTimers(g_logFile);
                        client.resetTimers();
                    }
                } catch (const char* err) {
                    if (m_printToStdout) printf("Error: '%s' ", err);
                    fprintf(g_logFile, "Error: %s\n", err); 
                    result = false;
                }
                client.closeConnection();
            }
        }
    
        bool pass = (result == it->expectSuccess);
        if (m_printToStdout) printf("[%s]\n",  pass ? "OK" : "FAILED");
        fprintf(g_logFile, "Result for test %s [%s]\n", it->name.c_str(), pass ? "OK" : "FAILED");
        if (result && it->timed) {
            fprintf(g_logFile, "testTimes = ");
            testTimer.print(g_logFile);
        }
    }

    if (establishedDefaultConnection) {
        m_defaultClient.closeConnection();
    }

    if (m_printToStdout) printf("Finished running tests in file %s\n", m_testFileName.c_str());
    return;
}

bool fileTester::runTest(fileClient& client, 
                        safeChannel& channel,
                        const fileTestParams& params,
                        timer& testTimer)
{
    bool result = false;
    try {
        if (params.action.compare("create") == 0) {
            if (params.timed) testTimer.Start();
#ifdef TEST
        fprintf(g_logFile, "fileTester::runTest create %s %s\n", 
                  params.subject.c_str(), params.authFile.c_str());
        fflush(g_logFile);
#endif
            result = client.createResource(
                            params.subject,
                            params.authFile,
                            params.remoteObject);            
#ifdef TEST
            if(result)
                fprintf(g_logFile, "fileTester::runTest createResource returns true\n");
            else
                fprintf(g_logFile, "fileTester::runTest createResource returns false\n");
            fflush(g_logFile);
#endif
            if (params.timed) testTimer.Stop();
        } 
#if 0
        else if (params.action.compare("getserverfilekey") == 0) {
#ifdef TEST
            fprintf(g_logFile, "fileTester::runTest get key %s\n", params.subject.c_str());
            fflush(g_logFile);
#endif
            if (params.timed) testTimer.Start();
            result = client.getserverfilekey(params.subject);
            if (params.timed) testTimer.Stop();
            if (!result) return result;
        } 
#endif
        else if (params.action.compare("read") == 0) {
#ifdef TEST
        fprintf(g_logFile, "fileTester::runTest read %s %s\n", 
                  params.subject.c_str(), params.authFile.c_str());
        fflush(g_logFile);
#endif
            if (params.timed) testTimer.Start();
            result = client.readResource(
                            params.subject,
                            params.authFile,
                            params.remoteObject,
                            params.localObject);
            if (params.timed) testTimer.Stop();
            if (!result) return result;
        
            // don't count the time to check the result, only the time to get it
            result = client.compareFiles(params.localObject, params.match);
        } else if (params.action.compare("write") == 0) {
#ifdef TEST
        fprintf(g_logFile, "fileTester::runTest write %s %s\n", 
                  params.subject.c_str(), params.authFile.c_str());
        fflush(g_logFile);
#endif
            if (params.timed) testTimer.Start();
            result = client.writeResource(
                            params.subject,
                            params.authFile,
                            params.remoteObject,
                            params.localObject);
            if (params.timed) testTimer.Stop();
        } else if (params.action.compare("delete") == 0) {
            if (params.timed) testTimer.Start();
            result = client.deleteResource(
                            params.subject,
                            params.authFile,
                            params.remoteObject);
            if (params.timed) testTimer.Stop();
        } else {
            throw "Unknown fileTester action\n";
        }
    } catch (const char* err) {
        fprintf(g_logFile, "Test failed with error message '%s'\n", err);
        return false;
    }

    return result;
}
