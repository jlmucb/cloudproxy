#!/usr/bin/env python

from __future__ import print_function
import re
from subprocess import check_call
import tempfile
from xml.etree import ElementTree as ET

# the public-key template for creating principals
principal_template = """
<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <ds:CanonicalizationMethod Algorithm="http://www.manferdelli.com/2011/Xml/canonicalization/tinyxmlcanonical#" />
    <ds:SignatureMethod Algorithm="http://www.manferdelli.com/2011/Xml/algorithms/rsa1024-sha256-pkcspad#" />
    <Certificate Id="//www.manferdelli.com/2011/Cert/User/" version="1">
        <SerialNumber></SerialNumber>
        <PrincipalType>User</PrincipalType>
        <IssuerName>manferdelli.com</IssuerName>
        <IssuerID>manferdelli.com</IssuerID>
        <ValidityPeriod>
            <NotBefore>2011-01-01Z00:00.00</NotBefore>
            <NotAfter>2021-01-01Z00:00.00</NotAfter>
        </ValidityPeriod>
        <SubjectName>//www.manferdelli.com/User/</SubjectName>
        <SubjectKey>
            <ds:KeyInfo KeyName="//www.manferdelli.com/Keys/">
                <KeyType>RSAKeyType</KeyType>
                <ds:KeyValue>
                    <ds:RSAKeyValue size="1024">
                        <ds:M></ds:M>
                        <ds:E></ds:E>
                    </ds:RSAKeyValue>
                </ds:KeyValue>
            </ds:KeyInfo>
        </SubjectKey>
        <SubjectKeyID>//www.manferdelli.com/Keys/</SubjectKeyID>
        <RevocationPolicy>Local-check-only</RevocationPolicy>
    </Certificate>
</ds:SignedInfo>
"""

# the XML DSig namespace used by signed elements
dsns='{http://www.w3.org/2000/09/xmldsig#}'

def transform_namespace(xml_str):
    # convert the default ns0 from elementtree to ds to compensate for the 
    # lack of correct namespace handling in TinyXML
    namespace_patt = re.compile('ns0:')
    namespace_patt2 = re.compile(':ns0=')
    return namespace_patt2.sub(':ds=', namespace_patt.sub('ds:', xml_str))


def create_principal(ordinal, subject, private_key=None, crypt_utility='./cryptUtility.exe', policy_private_key='./policy/privatePolicyKey.xml', output=None):
    # set up private_key and output if they weren't specified
    if private_key is None:
        private_key = subject + 'PrivateKey.xml'
    if output is None:
        output = subject + 'PublicKey.xml'

    # parse the policy template as XML
    tree = ET.fromstring(principal_template)

    # get the arguments to fill in the XML

    # append id to the Id of Certificate and write it as the serial number
    grant_node = tree.find('Certificate')
    cur_cert_id = grant_node.get('Id')
    new_cert_id = cur_cert_id + str(ordinal)
    grant_node.set('Id', new_cert_id)

    serial_node = grant_node.find('SerialNumber')
    serial_node.text = '{0}'.format(ordinal);

    # write the subject name to the SubjectName
    subject_name_node = grant_node.find('SubjectName')
    slash_re = re.compile(r'/')
    subject_file_name = slash_re.sub('_', subject)
    subject_name_node.text = subject_name_node.text + subject

    # write the key name to the KeyInfo KeyName 
    # attribute, and the SubjectKeyID
    key_info_node = grant_node.find('SubjectKey/{0}KeyInfo'.format(dsns))
    key_prefix = key_info_node.get('KeyName')
    key_info_node.set('KeyName', key_prefix + subject)

    subject_key_id_node = grant_node.find('SubjectKeyID')
    subject_key_id_node.text = subject_key_id_node.text + subject

    # get the old key or generate a new key and get the modulus and exponent
    private_key_file_name = private_key
    if private_key_file_name is None:
        # get a temp file to write the private key and rewrite it to the named location 
        private_temp = tempfile.NamedTemporaryFile()
        private_key_file_name = subject_file_name + 'PrivateKey.xml'
        check_call([crypt_utility, '-GenKey', 'RSA1024', private_temp.name])
        
        # rewrite the name of the key to match our public key
        private_tree = ET.parse(private_temp.name)
        private_root = private_tree.getroot()
        private_root.set('KeyName', key_prefix + subject)
        
        # write to the specified file name after transforming the namespace
        private_xml_str = transform_namespace(ET.tostring(private_root))
        private_file = open(private_key_file_name, 'wb')
        private_file.write(private_xml_str)
        private_file.close() 
        
    pk_tree = ET.parse(private_key_file_name)
    rsa_node = pk_tree.find('{0}KeyValue/{0}RSAKeyValue'.format(dsns))
    modulus_node = rsa_node.find('{0}M'.format(dsns))
    exponent_node = rsa_node.find('{0}E'.format(dsns))

    pk_rsa_node = key_info_node.find('{0}KeyValue/{0}RSAKeyValue'.format(dsns))
    pk_modulus_node = pk_rsa_node.find('{0}M'.format(dsns))
    pk_exponent_node = pk_rsa_node.find('{0}E'.format(dsns))

    # copy the public key portions from the private key file to the
    # public key to be signed
    pk_modulus_node.text = modulus_node.text
    pk_exponent_node.text = exponent_node.text

    # write the resulting XML to a temp file and perform the signing operation
    temp = tempfile.NamedTemporaryFile()
    xml_str = transform_namespace(ET.tostring(tree))

    # this temp file will be signed by cryptUtility
    temp.write(xml_str)
    temp.flush() 

    # perform the signing operation using cryptUtility
    check_call([crypt_utility, '-Sign', policy_private_key, 'rsa1024-sha256-pkcspad', temp.name, output])


# the XML to fill out for policy creation
policy_template = """
<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <ds:CanonicalizationMethod Algorithm="http://www.manferdelli.com/2011/Xml/canonicalization/tinyxmlcanonical#" />
    <ds:SignatureMethod Algorithm="http://www.manferdelli.com/2011/Xml/algorithms/rsa1024-sha256-pkcspad#" />
    <SignedGrant Id="http://www.manferdelli.com/2011/Cert/Policy/" version="1">
        <SerialNumber></SerialNumber>
        <IssuerName>manferdelli.com</IssuerName>
        <IssuerID>manferdelli.com</IssuerID>
        <ValidityPeriod>
            <NotBefore>2011-01-01Z00:00.00</NotBefore>
            <NotAfter>2021-01-01Z00:00.00</NotAfter>
        </ValidityPeriod>
        <SubjectName>//www.manferdelli.com/</SubjectName>
        <RevocationPolicy>Local-check-only</RevocationPolicy>
        <Assertions count="0">
        </Assertions>
    </SignedGrant>
</ds:SignedInfo>
"""

def create_policy(policy_file, cert_id, authority='fileProxyPolicy/0001', crypt_utility='./cryptUtility.exe', private_key='./policy/privatePolicyKey.xml', output='authorizationRuleSigned.xml'):
    # parse the policy template as XML
    tree = ET.fromstring(policy_template)

    # get the arguments to fill in the XML

    # find the Assertion node to fill with assertions from the policyFile
    assertions_node = tree.find('SignedGrant/Assertions'.format(dsns))

    # create the list of Assertions by transforming the lines of the policyFile file
    f = open(policy_file, 'r');
    assertion_count = 0
    for line in f:
        assert_node = ET.SubElement(assertions_node, 'Assertion')
        assert_node.text = line
        assertion_count += 1

    assertions_node.set('count', str(assertion_count))

    # append certID to the certificate ID and write it as the serial number
    grant_node = tree.find('SignedGrant')
    cur_cert_id = grant_node.get('Id')
    new_cert_id = cur_cert_id + str(cert_id)
    grant_node.set('Id', new_cert_id)

    serial_node = grant_node.find('SerialNumber')
    serial_node.text = '{0}'.format(cert_id);

    subject_name_node = grant_node.find('SubjectName')
    subject_name_node.text = subject_name_node.text + authority

    # write the resulting XML to a temp file and perform the signing operation
    temp = tempfile.NamedTemporaryFile()
    xml_str = transform_namespace(ET.tostring(tree))

    # this temp file will be signed by cryptUtility
    temp.write(xml_str)
    temp.flush() 

    # perform the signing operation using cryptUtility
    check_call([cryptUtility, '-Sign', privateKey, 'rsa1024-sha256-pkcspad', temp.name, output])


# code to generate an EvidenceCollection from a set of lists

# the XML components needed to make a list
evidence_collection_prefix_template = '<EvidenceCollection count="{0}">'
evidence_collection_suffix = '</EvidenceCollection>'

evidence_list_prefix_template = '<EvidenceList count="{0}">'
evidence_list_suffix = '\n</EvidenceList>'

def create_evidence_collection(file_lists, output_file):
    # open the output file for writing and add the evidence lists
    with open(output_file, 'wb') as output:
        print(evidence_collection_prefix_template.format(len(file_lists)), file=output)

        # go through each list and collect it into the list
        for file_list in file_lists:
            print(evidence_list_prefix_template.format(len(file_list)), file=output)
            for file_name in file_list:
                with open(file_name, 'rb') as f:
                    for line in f:
                        print(line, end='', file=output)
            print(evidence_list_suffix, file=output)
        print(evidence_collection_suffix, file=output)
        

# code to generate a PrivateKeys list

# the XML components needed to make a PrivateKeys node
private_keys_prefix_template = '<PrivateKeys count="{0}">'
private_keys_suffix = '</PrivateKeys>'

def create_private_keys(files, output_file):
    # open the output file for writing and add the private keys
    with open(output_file, "wb") as output:
        print(private_keys_prefix_template.format(len(files)), file=output)

        for file_name in files:
            with open(file_name, 'rb') as f:
                for line in f:
                    print(line, end='', file=output)
            # private key files generated by create_principal don't end in a newline
            print('', file=output)	
        print(private_keys_suffix, file=output)

