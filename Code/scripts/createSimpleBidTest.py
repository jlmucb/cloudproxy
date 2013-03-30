#!/usr/bin/env python

from __future__ import print_function
import cloud_proxy
from subprocess import check_call
import os

scriptPath = os.path.dirname(__file__)

if not os.path.exists("basicBidTest"):
    os.makedirs("basicBidTest")

testXML = """<Tests print="true">
    <Default timed="true" repetitions="1">
        <Seller>
            <Client>
                <Authorization>SellerPublicKey.xml</Authorization>
                <PrivateKeys>SellerPrivateKey.xml</PrivateKeys>
                <PublicKeys>SellerPublicKey.xml</PublicKeys>
                <Subject>//www.manferdelli.com/User/Seller</Subject>
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

# create a User for the bid test
cloud_proxy.create_principal(3, 'User')
cloud_proxy.create_evidence_collection([['UserPublicKey.xml']], 'basicBidTest/UserPublicKey.xml')
cloud_proxy.create_private_keys(['UserPrivateKey.xml'], 'basicBidTest/UserPrivateKey.xml')

# get rid of the excess XML
check_call(['rm', 'UserPublicKey.xml', 'UserPrivateKey.xml']) 

# create a Seller for the bid test
cloud_proxy.create_principal(3, 'Seller')
cloud_proxy.create_evidence_collection([['SellerPublicKey.xml']], 'basicBidTest/SellerPublicKey.xml')
cloud_proxy.create_private_keys(['SellerPrivateKey.xml'], 'basicBidTest/SellerPrivateKey.xml')

# get rid of the excess XML
check_call(['rm', 'SellerPublicKey.xml', 'SellerPrivateKey.xml']) 

with open('basicBidTest/tests.xml', 'wb') as testFile:
    print(testXML, file=testFile)
