//  File: bidTester.cpp
//      Tom Roeder
//
//  Description: test manager for bidClient
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
#include "bidClient.h"
#include "safeChannel.h"
#include "bidServer.h"
#include "sellerClient.h"

#include "bidTester.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

bidTester::bidTester(const string& path, const string& testFile) 
    : m_defaultParams(),
    m_testFileName(path + testFile),
    m_testsDoc(path + testFile),
    m_tests(),
    m_reuseConnection(false),
    m_serverAddress("127.0.0.1"),
    m_serverPort(SERVICE_PORT)
{
    // parse the xml and construct the default parameters and any required resources
    m_testsDoc.LoadFile();

    const TiXmlElement* curElt = m_testsDoc.RootElement();

    // get the server IP address from the config bid, if any
    string serverAddress;
    if (curElt->QueryStringAttribute("serverAddress", &serverAddress) == TIXML_SUCCESS) {
        m_serverAddress = serverAddress;
    }

    int port = 0;
    if (curElt->QueryIntAttribute("serverPort", &port) == TIXML_SUCCESS) {
        m_serverPort = static_cast<u_short>(port);
    }

    // check to see if we should print to stdout or only to the log file
    bool print = false;
    if (curElt->QueryBoolAttribute("print", &print) == TIXML_SUCCESS) {
        m_printToStdout = print;
    }

    // walk the children of the root and handle Default and Test children
    const TiXmlNode* child = NULL;
    while((child = curElt->IterateChildren(child))) {
        const string& name = child->ValueStr();
        if (name.compare("Default") == 0) {
            // convert the values to a parameter set
            getParams(child, path, m_defaultParams);
        } else if (name.compare("Test") == 0) {
            // copy the default params and update them with the parameters from the test 
            bidTestParams params = m_defaultParams;
            getParams(child, path, params);
    
            // add the test to our list to be executed later
            m_tests.push_back(params);

        } else {
            throw "Unknown test element\n";
        }
    } 
}    

bidTester::~bidTester() {
}

void bidTester::getClientParams(const TiXmlNode* parent, 
                                const string& parentPath,
                                clientParams& params) {
    const TiXmlNode* child = NULL;
    while((child = parent->IterateChildren(child))) {
        const string& name = child->ValueStr();
        const TiXmlElement* childElt = child->ToElement();
        const string& text(childElt->GetText());
        if (name.compare("Authorization") == 0) {
            params.authFile = parentPath + text;
        } else if (name.compare("PrivateKeys")) {
            params.keyFile = parentPath + text;
        } else if (name.compare("PublicKeys")) {
            params.certFile = parentPath + text;
        } else if (name.compare("Subject")) {
            params.subject = text;
        } else {
            throw "Unknown node in Client\n";
        }
    }
}

void bidTester::getParams(const TiXmlNode* parent, const string& parentPath, bidTestParams& params) {
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
        if (name.compare("Seller") == 0) {
            // get the seller client parameters
            const TiXmlElement* clientNode = child->FirstChild();
            if (NULL == clientNode) {
                throw "Seller nodes must have a child Client node\n";
            }

            getClientParams(clientNode, params.seller);
        } else if (name.compare("Clients") == 0) {
            // iterate through the Bidder children to get their Client and Bid information
            const TiXmlNode* bidderChild = NULL;
            while((bidderChild = child->IterateChildren(bidderChild))) {
                // check that this child is a Bidder
                const string& bidderNodeName = bidderChild->ValueStr();
                if (!bidderNodeName.equals("Bidder")) {
                    throw "The child of a Clients node must be a Bidder\n";
                }

                const TiXmlNode* bidderChildNode = NULL;
                bidClientParams bcp;
                bool foundClient = false;
                bool foundBid = false;
                while ((bidderChildNode = bidderChild->IterateChildren(bidderChildNode))) {
                    const string& bidderChildName = bidderChildNode.ValueStr();
                    if (bidderChildName.equals("Client")) {
                        // handle the Client case
                        if (foundClient) {
                            throw "Bidder nodes cannot have more than one Client child node\n";
                        }

                        foundClient = true;
                        getClientParams(clientChild, bcp.first);
                    } else if (bidderChildName.equals("Bid")) {
                        // handle the Bid case
                        if (foundBid) {
                            throw "Bidder nodes cannot have more than one Bid child node\n";
                        }

                        foundBid = true;
                        
                        const TiXmlElt* bidderChildElt = bidderChildNode->ToElement();
                        int bidValue = 0;
                        if (bidderChildElt->QueryIntAttribute("value", &bidValue) != TIXML_SUCCESS) {
                            throw "Bid nodes must have a 'value' attribute\n";
                        } else {
                            bcp.second = bidValue;
                        }
                    } else {
                        throw "The only valid children of Bidder are Client and Bid\n";
                    }
                }

                // add the client
                if (!foundBid || !foundClient) {
                    throw "Bidder nodes must contain exactly one child Client node and one child Bid node\n";
                }
                
                params.bid.push_back(bcp);
            }
        } else if (name.compare("Winner") == 0) {
            // get the name attribute as the expectedWinner
            string winnerName;
            if (childElt->QueryStringAttribute("name", &winnerName) != TIXML_SUCCESS) {
                throw "Bid nodes must have a 'value' attribute\n";
            }

            params.expectedWinner = winnerName;
        } else {
            throw "Unknown parameter name\n";
        }
    }
}

void bidTester::Run(const char* directory) {
    list<bidTestParams>::iterator it = m_tests.begin();
    for( ; m_tests.end() != it; ++it) {
        runTest(directory, *it);
    }
}

bool bidTester::runTest(const char* directory,
                        const bidTestParams& params)
{
    bool result = false;
    try {
            if (m_printToStdout) printf("%s: ", params.name.c_str());

            if (params.repetitions <= 0) {
                if (m_printToStdout) printf("[FAILED]\n");
                fprintf(g_logFile, "%s: (Bad number of repetitions %d) [FAILED]\n", params.name.c_str(), params.repetitions);
                continue;
            }

            timer bidTestTimer;
            timer sellerTestTimer;
            for(int i = 0; i < params.repetitions; ++i) {
                list<bidClientParams>::iterator it = params.bids.begin();
                while(params.bids.end() != it) {
                    // set up a bid client and get a channel for it to talk to the server
                    bidClient client;
                    safeChannel channel;
                    result = client.establishConnection(channel,
                            it->first.keyFile.c_str(),
                            it->first.certFile.c_str(),
                            directory,
                            m_serverAddress.c_str(),
                            m_serverPort);

                    try {
                        // send the bid to the server
                        if (params.timed) bidTestTimer.Start();
                        result = client.sendBid(channel,
                                            it->first.subject,
                                            it->first.authFile,
                                            it->second);
                        if (params.timed) {
                            bidTestTimer.Stop();
                            fprintf(g_logFile, "Timers for test %s: ", params.name.c_str());
                            client.printTimers(g_logFile);
                            client.resetTimers();
                        }
                    } catch (const char* err) {
                        if (m_printToStdout) printf("Error: '%s' ", err);
                        fprintf(g_logFile, "Error: %s\n", err); 
                        result = false;
                    }
                    
                    client.closeConnection(channel);                    

                    ++it;
                }
            }
        
            // now have the sellerClient connect and compute the winner
            sellerClient sellerClient;
            safeChannel sellerChannel;
           
            result = sellerClient.establishConnection(sellerChannel,
                                    params.seller.keyFile,
                                    params.seller.certFile,
                                    directory,
                                    m_serverAddres.c_str(),
                                    m_serverPort);
                                     
            try {
                if (params.timed) sellerTestTimer.Start();

                // try to get the bids to compute the results
                result = sellerClient.getResults(sellerChannel,
                                        params.seller.subject,
                                        params.seller.authFile); 
                if (params.timed) {
                    sellerTestTimer.Stop();
                    fprintf(g_logFile, "Seller timers for test %s: ", params.name.c_str());
                    sellerClient.printTimers(g_logFile);
                    sellerClient.resetTimers();
                }
            } catch (const char* err) {
                if (m_printToStdout) printf("Error: '%s' ", err);
                fprintf(g_logFile, "Error: %s\n", err);
                result = false;
            }
    
            sellerClient.closeConnection(sellerChannel);

            string winner = sellerClient.getWinner();
            bool pass = result && winner.equals(params.expectedWinner);

            if (m_printToStdout) printf("[%s]\n",  pass ? "OK" : "FAILED");
            fprintf(g_logFile, "Result for test %s [%s]\n", params.name.c_str(), pass ? "OK" : "FAILED");
            if (result && params.timed) {
                fprintf(g_logFile, "bidTestTimes = ");
                bidTestTimer.print(g_logFile);

                fprintf(g_logFile, "sellerTestTimes = ");
                sellerTestTimer.print(g_logFile);
            }
        }
    }

    return result;
}

