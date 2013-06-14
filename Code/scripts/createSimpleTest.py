#!/usr/bin/env python

from __future__ import print_function
import cloud_proxy
from subprocess import check_call
import os

if not os.path.exists('basicTest'):
    os.makedirs('basicTest')

if not os.path.exists('basicTest/files'):
    os.makedirs('basicTest/files')

# create a new user JohnManferdelli/0001
cloud_proxy.create_principal(1, 'JohnManferdelli/0001')
cloud_proxy.create_evidence_collection([['JohnManferdelli_0001PublicKey.xml']], 'basicTest/principalPublicKeys.xml')
cloud_proxy.create_private_keys(['JohnManferdelli_0001PrivateKey.xml'], 'basicTest/principalPrivateKeys.xml')

# create a simple policy that gives the user create authority on the directory
with open('testpolicy', 'wb') as f:
    print('//www.manferdelli.com/User/JohnManferdelli/0001 maycreate //www.manferdelli.com/Gauss/fileProxy/files', file=f)
	
cloud_proxy.create_policy('testpolicy', 1)
cloud_proxy.create_evidence_collection([['authorizationRuleSigned.xml']], 'basicTest/authRule1Signed.xml')

# create a simple test file to transfer between the client and server
with open('basicTest/files/file.test', 'wb') as f:
    print('This is the test file.\n', file=f)

# clean up the extra XML files
os.remove('JohnManferdelli_0001PublicKey.xml')
os.remove('JohnManferdelli_0001PrivateKey.xml')
os.remove('authorizationRuleSigned.xml')
os.remove('testpolicy')

# write the simple test XML to the directory
test_xml = """
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
    print(test_xml, file=f)
