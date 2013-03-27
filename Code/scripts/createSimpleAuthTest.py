#!/usr/bin/env python

from __future__ import print_function
from subprocess import check_call
import os, sys

scriptPath = os.path.dirname(__file__)

if not os.path.exists("basicAuthTest"):
    os.makedirs("basicAuthTest")

testXML = """<Test>
  <IdentityCert>IdentityProviderPrivateKey.xml</IdentityCert>
  <UserCert>UserPublicKey.xml</UserCert>
  <Key>PrototypePublicKey.xml</Key>
</Tests>"""

check_call([os.path.join(scriptPath, "createPrincipal.py"), "3", "IdentityProvider"])
check_call(["mv", "IdentityProviderPrivateKey.xml", "IdentityProviderPublicKey.xml", "basicAuthTest"])

check_call([os.path.join(scriptPath, "createPrincipal.py"), "--policyPrivateKey", "basicAuthTest/IdentityProviderPrivateKey.xml", "4", "User"])
check_call(["mv", "UserPublicKey.xml", "UserPrivateKey.xml", "basicAuthTest"])

check_call(["./cryptUtility.exe", "-GenKey", "RSA1024", "PrototypePrivateKey.xml"])


# cat | grep -v for removing private info and making a public key
with open('PrototypePrivateKey.xml', 'r') as inFile:
    with open('basicAuthTest/PrototypePublicKey.xml', 'wb') as outFile:
        for line in inFile.readline():
            if (not "ds:P" in line) and (not "ds:D" in line) and (not "ds:Q" in line):
                print(line, file=outFile)

check_call(["mv", "PrototypePrivateKey.xml", "basicAuthTest"])

with open('basicAuthTest/tests.xml', 'wb') as testFile:
    print(testXML, file=testFile)
