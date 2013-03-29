#!/usr/bin/env python

from __future__ import print_function
from subprocess import check_call
import os, sys

scriptPath = os.path.dirname(__file__)

if not os.path.exists("basicBidTest"):
    os.makedirs("basicBidTest")

testXML = """<Tests print="true">
    <Default timed="true" repetitions="1">
        <Seller>
            <Client>
                <Authorization>UserPublicKey.xml</Authorization>
                <PrivateKeys>UserPrivateKey.xml</PrivateKeys>
                <PublicKeys>UserPublicKey.xml</PublicKeys>
                <Subject>//www.manferdelli.com/User/User</Subject>
            </Client>
        </Seller>
    </Default>
    <Test name="oneBid">
        <Clients>
            <Bidder>
                <Client>
                    <Authorization>UserPublicKey.xml</Authorization>
                    <PrivateKeys>UserPrivateKey.xml</PrivateKeys>
                    <PublicKeys>UserPublicKey.xml</PublicKeys>
                    <Subject>//www.manferdelli.com/User/User</Subject>
                </Client>
                <Bid value="1" />
            </Bidder>
        </Clients>
        <Winner name="//www.manferdelli.com/User/User" />
    </Test>
</Tests>"""

check_call([os.path.join(scriptPath, "createPrincipal.py"), "3", "User"])

check_call([os.path.join(scriptPath, "createEvidenceCollection.py"), "-o", "basicBidTest/UserPublicKey.xml", "-l", "UserPublicKey.xml"])
check_call([os.path.join(scriptPath, "createPrivateKeyList.py"), "-o", "basicBidTest/UserPrivateKey.xml", "UserPrivateKey.xml"])
check_call(["rm", "UserPublicKey.xml", "UserPrivateKey.xml"]) 

with open('basicBidTest/tests.xml', 'wb') as testFile:
    print(testXML, file=testFile)
