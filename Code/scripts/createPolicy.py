#!/usr/bin/env python

import argparse
import tempfile
import re
from xml.etree import ElementTree as ET
from subprocess import check_call

# set up a parser to read the command line arguments
parser = argparse.ArgumentParser(description="Creates a new policy from a set of policy statements. This is meant to be executed in the root executable directory of the FileProxy tree.")
parser.add_argument("policyFile", help="A text file of policy statements, one per line")
parser.add_argument("certId", type=int, help="The ordinal identifier of this certificate in the Policy namespace")
parser.add_argument("id", help="A string identifier for this policy")
parser.add_argument("cryptUtility", nargs="?", help="The path to cryptUtility.exe (default ./cryptUtility.exe)", default="./cryptUtility.exe")
parser.add_argument("privateKeyFile", nargs="?", help="The path to the private key file to use to sign this policy (default policy/privatePolicyKey.xml)", default="policy/privatePolicyKey.xml")
parser.add_argument("output", nargs="?", help="The name of the signed authorization file to output (default authorizationRuleSigned.xml)", default="authorizationRuleSigned.xml")

args = parser.parse_args()

# the authorization template for policies
policyTemplate = """
<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <ds:CanonicalizationMethod Algorithm="http://www.manferdelli.com/2011/Xml/canonicalization/tinyxmlcanonical#" />
    <ds:SignatureMethod Algorithm="http://www.manferdelli.com/2011/Xml/algorithms/rsa1024-sha256-pkcspad#" />
    <SignedGrant Id="http://www.manferdelli.com/2011/Cert/" version="1">
        <SerialNumber></SerialNumber>
        <IssuerName>manferdelli.com</IssuerName>
        <IssuerID>manferdelli.com</IssuerID>
        <ValidityPeriod>
            <NotBefore>2011-01-01Z00:00.00</NotBefore>
            <NotAfter>2021-01-01Z00:00.00</NotAfter>
        </ValidityPeriod>
        <SubjectName>//www.manferdelli.com/</SubjectName>
        <SubjectKey>
            <ds:KeyInfo KeyName="">
                <KeyType>RSAKeyType</KeyType>
                <ds:KeyValue>
                    <ds:RSAKeyValue size="1024">
                        <ds:M></ds:M>
                        <ds:E></ds:E>
                    </ds:RSAKeyValue>
                </ds:KeyValue>
            </ds:KeyInfo>
        </SubjectKey>
        <SubjectKeyID>//www.manferdelli.com/</SubjectKeyID>
        <RevocationPolicy>Local-check-only</RevocationPolicy>
        <Assertions count="0">
        </Assertions>
    </SignedGrant>
</ds:SignedInfo>
"""

dsns="{http://www.w3.org/2000/09/xmldsig#}"

# parse the policy template as XML
tree = ET.fromstring(policyTemplate)

# get the arguments to fill in the XML

# find the Assertion node to fill with assertions from the policyFile
assertionsNode = tree.find("SignedGrant/Assertions".format(dsns))

# create the list of Assertions by transforming the lines of the policyFile file
f = open(args.policyFile, 'r');
assertionCount = 0
for line in f:
    assertNode = ET.SubElement(assertionsNode, "Assertion")
    assertNode.text = line
    assertionCount += 1

assertionsNode.set("count", str(assertionCount))

# append certID to the certificate ID and write it as the serial number
grantNode = tree.find("SignedGrant")
curCertID = grantNode.get("Id")
newCertID = curCertID + str(args.certId)
grantNode.set("Id", newCertID)

serialNode = grantNode.find("SerialNumber")
serialNode.text = "{0}".format(args.certId);

# write the policy name (like "fileProxyPolicy/001") to the SubjectName, the 
# KeyInfo KeyName attribute, and the SubjectKeyID
subjectNameNode = grantNode.find("SubjectName")
subjectNameNode.text = subjectNameNode.text + args.id

keyInfoNode = grantNode.find("SubjectKey/{0}KeyInfo".format(dsns))
keyInfoNode.set("KeyName", args.id)

subjectKeyIDNode = grantNode.find("SubjectKeyID")
subjectKeyIDNode.text = subjectKeyIDNode.text + args.id

# write the resulting XML to a temp file and perform the signing operation
temp = tempfile.NamedTemporaryFile()
xmlStr = ET.tostring(tree)

# convert the default ns0 from elementtree to ds to compensate for the 
# lack of correct namespace handling in TinyXML
namespacePatt = re.compile('ns0:')
namespacePatt2 = re.compile(':ns0=')
nsXmlStr = namespacePatt2.sub(":ds=", namespacePatt.sub('ds:', xmlStr))

# this temp file will be signed by cryptUtility
temp.write(nsXmlStr)
temp.flush() 

# perform the signing operation using cryptUtility
check_call([args.cryptUtility, "-Sign", args.privateKeyFile, "rsa1024-sha256-pkcspad", temp.name, args.output])
