#!/usr/bin/env python

from __future__ import print_function

import argparse
from subprocess import check_call
import os, sys

parser = argparse.ArgumentParser(description="Creates a BidProxy test with a given number of servers")
parser.add_argument("n", type=int, help="The number of bidders to create. Bidders are named from 1 to n")
scriptPath = os.path.dirname(__file__)

args = parser.parse_args()

dirName = "basicBidTest." + str(args.n)
if not os.path.exists(dirName):
    os.makedirs(dirName)

test_xml_prefix_template = """<Tests print="true">
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
    <Test name="{0}">
        <Clients>"""
bidder_template = """
            <Bidder>
                <Client>
                    <Authorization>{0}</Authorization>
                    <PrivateKeys>{1}</PrivateKeys>
                    <PublicKeys>{0}</PublicKeys>
                    <Subject>//www.manferdelli.com/User/{2}</Subject>
                </Client>
                <Bid value="{2}" />
            </Bidder>"""

test_xml_suffix_template = """
        </Clients>
        <Winner name="//www.manferdelli.com/User/{0}" />
    </Test>
</Tests>"""


# create the Seller principal
check_call([os.path.join(scriptPath, "createPrincipal.py"), "0", "Seller"])
public_key_name = "SellerPublicKey.xml"
private_key_name = "SellerPrivateKey.xml"
check_call([os.path.join(scriptPath, "createEvidenceCollection.py"), "-o", dirName + "/" + public_key_name, "-l", public_key_name])
check_call([os.path.join(scriptPath, "createPrivateKeyList.py"), "-o", dirName + "/" + private_key_name, private_key_name])
check_call(["rm", public_key_name, private_key_name]) 

# create all the bidder principals from 1 to n
test_xml = test_xml_prefix_template.format(str(args.n) + "BidTest")
for i in range(1, args.n + 1):
    check_call([os.path.join(scriptPath, "createPrincipal.py"), str(i), str(i)])
    public_key_name = str(i) + "PublicKey.xml"
    private_key_name = str(i) + "PrivateKey.xml"
    check_call([os.path.join(scriptPath, "createEvidenceCollection.py"), "-o", dirName + "/" + public_key_name, "-l", public_key_name])
    check_call([os.path.join(scriptPath, "createPrivateKeyList.py"), "-o", dirName + "/" + private_key_name, private_key_name])
    check_call(["rm", public_key_name, private_key_name]) 

    test_xml += bidder_template.format(public_key_name, private_key_name, str(i))

# the winner will be the user args.n, since it will have the highest bid
test_xml += test_xml_suffix_template.format(str(args.n))

with open(dirName + '/tests.xml', 'wb') as testFile:
    print(test_xml, file=testFile)
