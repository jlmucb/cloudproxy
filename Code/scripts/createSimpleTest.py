#!/usr/bin/env python

from __future__ import print_function
from subprocess import check_call
import os

if not os.path.exists("basicTest"):
    os.makedirs("basicTest")

if not os.path.exists("basicTest/files"):
    os.makedirs("basicTest/files")

check_call(["principals/createPrincipal.py", "1", "JohnManferdelli/0001"])
check_call(["principals/createEvidenceList.py", "JohnManferdelli_0001PublicKey.xml", "-o", "basicTest/principalPublicKeys.xml"])
check_call(["principals/createPrivateKeyList.py", "JohnManferdelli_0001PrivateKey.xml", "-o", "basicTest/principalPrivateKeys.xml"])

with open('testpolicy', 'wb') as f:
    print("//www.manferdelli.com/User/JohnManferdelli/0001 maycreate //www.manferdelli.com/Gaus/fileProxy/files", file=f)
	
check_call(["principals/createPolicy.py", "testpolicy", "1"])
check_call(["principals/createEvidenceList.py", "authorizationRuleSigned.xml", "-o", "basicTest/authRule1Signed.xml"])

with open('basicTest/files/file.test', 'wb') as f:
    print("This is the test file.\n", file=f)

# clean up the extra XML files
os.remove("JohnManferdelli_0001PublicKey.xml")
os.remove("JohnManferdelli_0001PrivateKey.xml")
os.remove("authorizationRuleSigned.xml")
os.remove("testpolicy")

testXML = """
<Tests reuseConnection="true">
    <Default time="false" repetitions="1"> 
        <Authorization>authRule1Signed.xml</Authorization>
        <PrivateKeys>principalPrivateKeys.xml</PrivateKeys>
        <PublicKeys>principalPublicKeys.xml</PublicKeys>
        <Subject>//www.manferdelli.com/User/JohnManferdelli/0001</Subject>
        <RemoteObject>//www.manferdelli.com/Gauss/fileProxy/files/file.test</RemoteObject>
        <LocalObject>files/file.test</LocalObject>
    </Default>
    <Test name="basicFileCreate">
        <Action>create</Action>
    </Test>
    <Test name="basicFileWrite">
        <Action>write</Action>
    </Test>
    <Test name="basicFileRead">
        <Action>read</Action>
        <LocalObject>files/file.test.out</LocalObject>
        <Match>files/file.test</Match>
    </Test>
</Tests>
""" 

with open('basicTest/tests.xml', 'wb') as f:
    print(testXML, file=f)
