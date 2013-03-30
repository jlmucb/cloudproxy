#!/usr/bin/env python

from __future__ import print_function

import cloud_proxy
from subprocess import check_call
import os

# TODO: generalize this code to generate arbitrary auth tests

if not os.path.exists('basicAuthTest'):
    os.makedirs('basicAuthTest')

testXML = """<Test>
  <IdentityCert>IdentityProviderPrivateKey.xml</IdentityCert>
  <UserCert>UserPublicKey.xml</UserCert>
  <UserKey>UserPrivateKey.xml</UserKey>
  <Key>PrototypePublicKey.xml</Key>
</Tests>"""

# create an IdentityProvider
cloud_proxy.create_principal(3, 'IdentityProvider')
check_call(['mv', 'IdentityProviderPrivateKey.xml', 'IdentityProviderPublicKey.xml', 'basicAuthTest'])

# create a User with an identity signed by the IdentityProvider
cloud_proxy.create_principal(4, 'User', policy_private_key='basicAuthTest/IdentityProviderPrivateKey.xml')

# the User is signed by the IdentityProvider, which is signed by the policy principal
# create an EvidenceCollection that reflects this
file_lists = [['UserPublicKey.xml', 'basicAuthTest/IdentityProviderPublicKey.xml']]
cloud_proxy.create_evidence_collection(file_lists, 'basicAuthTest/UserPublicKey.xml') 

# put the user's private key in a PrivateKeys list
cloud_proxy.create_private_keys(['UserPrivateKey.xml'], 'basicAuthTest/UserPrivateKey.xml')

# get rid of the generated public/private key pair
check_call(['rm', 'UserPublicKey.xml', 'UserPrivateKey.xml']) 

# create a key for a new user (TODO: this should be in cloud_proxy)
check_call(['./cryptUtility.exe', '-GenKey', 'RSA1024', 'PrototypePrivateKey.xml'])

# cat | grep -v for removing private info and making a public key
with open('PrototypePrivateKey.xml', 'r') as inFile:
    with open('basicAuthTest/PrototypePublicKey.xml', 'wb') as outFile:
        for line in inFile:
            if (not 'ds:P' in line) and (not 'ds:D' in line) and (not 'ds:Q' in line):
                print(line, file=outFile, end='')

check_call(['mv', 'PrototypePrivateKey.xml', 'basicAuthTest'])

with open('basicAuthTest/tests.xml', 'wb') as testFile:
    print(testXML, file=testFile)
