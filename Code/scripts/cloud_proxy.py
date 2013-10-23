#!/usr/bin/env python

from __future__ import print_function
import re
from subprocess import check_call
import tempfile
from xml.etree import ElementTree as ET

ROOT_DIR = '/home/jlm/jlmcrypt/'
CRYPT_UTILITY = ROOT_DIR + 'cryptUtility.exe'
POLICY_KEY = ROOT_DIR + 'policy/policyPrivateKey.xml'

# JLM CHANGE: rsa1024-sha256-pkcspad --> rsa2048-sha256-pkcspad
# JLM CHANGE: size="1024" --> size="2048"
policy_key_template = """
<ds:SignedInfo>
    <ds:CanonicalizationMethod Algorithm='http://www.manferdelli.com/2011/Xml/canonicalization/tinyxmlcanonical#' />
    <ds:SignatureMethod Algorithm='http://www.manferdelli.com/2011/Xml/algorithms/rsa2048-sha256-pkcspad#' />
    <Certificate Id='www.manferdelli.com/certs/' version='1'>
        <SerialNumber></SerialNumber>
        <PrincipalType>Policy</PrincipalType>
        <IssuerName>manferdelli.com</IssuerName>
        <IssuerID>manferdelli.com</IssuerID>
        <ValidityPeriod>
            <NotBefore>2011-01-01Z00:00.00</NotBefore>
            <NotAfter>2021-01-01Z00:00.00</NotAfter>
        </ValidityPeriod>
        <SubjectName>//www.manferdelli.com/</SubjectName>
        <SubjectKey>
            <ds:KeyInfo KeyName="//www.manferdelli.com/Keys/">
                <KeyType>RSAKeyType</KeyType>
                <ds:KeyValue>
                    <ds:RSAKeyValue size="2048">
                        <ds:M></ds:M>
                        <ds:E></ds:E>
                    </ds:RSAKeyValue>
                </ds:KeyValue>
            </ds:KeyInfo>
        </SubjectKey>
        <SubjectKeyID>CloudProxyPolicyKey</SubjectKeyID>
        <RevocationPolicy>Local-check-only</RevocationPolicy>
    </Certificate>
</ds:SignedInfo>
"""

# the public-key template for creating principals
# JLM CHANGE: rsa1024-sha256-pkcspad --> rsa2048-sha256-pkcspad
principal_template = """
<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <ds:CanonicalizationMethod Algorithm="http://www.manferdelli.com/2011/Xml/canonicalization/tinyxmlcanonical#" />
    <ds:SignatureMethod Algorithm="http://www.manferdelli.com/2011/Xml/algorithms/rsa2048-sha256-pkcspad#" />
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

def _transform_namespace(xml_str):
    # convert the default ns0 from elementtree to ds to compensate for the 
    # lack of correct namespace handling in TinyXML
    namespace_patt = re.compile('ns0:')
    namespace_patt2 = re.compile(':ns0=')
    return namespace_patt2.sub(':ds=', namespace_patt.sub('ds:', xml_str))


def _fill_xml_parameters(tree, subject, cert_num=1, serial_num=1):
    # append id to the Id of Certificate and write it as the serial number
    grant_node = tree.find('Certificate')
    cur_cert_id = grant_node.get('Id')
    new_cert_id = cur_cert_id + str(cert_num)
    grant_node.set('Id', new_cert_id)

    serial_node = grant_node.find('SerialNumber')
    serial_node.text = '{0}'.format(serial_num);

    # write the subject name to the SubjectName
    subject_name_node = grant_node.find('SubjectName')
    subject_name_node.text = subject_name_node.text + subject

    # write the key name to the KeyInfo KeyName 
    # attribute, and the SubjectKeyID
    key_info_node = grant_node.find('SubjectKey/{0}KeyInfo'.format(dsns))
    key_prefix = key_info_node.get('KeyName')
    key_info_node.set('KeyName', key_prefix + subject)

    subject_key_id_node = grant_node.find('SubjectKeyID')
    subject_key_id_node.text = subject_key_id_node.text + subject

    return key_prefix


def create_private_key(subject, prefix, output=None, signing_key=POLICY_KEY,
                       crypt_utility=CRYPT_UTILITY):
    # get a temp file to write the private key and rewrite it to the named location 
    with tempfile.NamedTemporaryFile() as private_temp:
        private_key_file_name = output
        if private_key_file_name is None:
            slash_re = re.compile(r'/')
            subject_file_name = slash_re.sub('_', subject)
            private_key_file_name = subject_file_name + 'PrivateKey.xml'
        check_call([crypt_utility, '-GenKey', 'RSA1024', private_temp.name])
        
        # rewrite the name of the key to match our public key
        private_tree = ET.parse(private_temp.name)
        private_root = private_tree.getroot()
        private_root.set('KeyName', prefix + subject)
        
        # write to the specified file name after transforming the namespace
        private_xml_str = _transform_namespace(ET.tostring(private_root))
        with open(private_key_file_name, 'wb') as private_file:
            private_file.write(private_xml_str)

        return private_key_file_name

def _copy_public_portion(private_key, tree):
    pk_tree = ET.parse(private_key)
    rsa_node = pk_tree.find('{0}KeyValue/{0}RSAKeyValue'.format(dsns))
    modulus_node = rsa_node.find('{0}M'.format(dsns))
    exponent_node = rsa_node.find('{0}E'.format(dsns))

    pk_rsa_node = tree.find('Certificate/SubjectKey/{0}KeyInfo/{0}KeyValue/{0}RSAKeyValue'.format(dsns))
    pk_modulus_node = pk_rsa_node.find('{0}M'.format(dsns))
    pk_exponent_node = pk_rsa_node.find('{0}E'.format(dsns))

    # copy the public key portions from the private key file to the
    # public key to be signed
    pk_modulus_node.text = modulus_node.text
    pk_exponent_node.text = exponent_node.text


# JLM CHANGE rsa1024-sha256-pkcspad --> rsa2048-sha256-pkcspad
def _sign_tree(tree, output, crypt_utility=CRYPT_UTILITY, private_key=POLICY_KEY):
    # write the resulting XML to a temp file and perform the signing operation
    with tempfile.NamedTemporaryFile(delete=False) as temp:
        xml_str = _transform_namespace(ET.tostring(tree))

        # this temp file will be signed by cryptUtility
        temp.write(xml_str + '\n')
        temp.flush() 

        # perform the signing operation using cryptUtility
        c = [crypt_utility, '-Sign', private_key, 'rsa2048-sha256-pkcspad', temp.name, output];
        check_call(c)


def create_policy_key(crypt_utility=CRYPT_UTILITY, 
                    policy_private_key=POLICY_KEY,
                    output=(ROOT_DIR + 'policyCert.xml')):
    tree = ET.fromstring(policy_key_template)
    
    _fill_xml_parameters(tree, 'CloudProxyPolicy')
    _copy_public_portion(policy_private_key, tree)
    _sign_tree(tree, output, crypt_utility, policy_private_key)
    

def create_principal(ordinal, subject, private_key=None, crypt_utility=CRYPT_UTILITY,
                    policy_private_key=POLICY_KEY, output=None):
    # set up private_key and output if they weren't specified
    slash_re = re.compile(r'/')
    subject_file_name = slash_re.sub('_', subject)
    if output is None:
        output = subject_file_name + 'PublicKey.xml'

    # parse the policy template as XML
    tree = ET.fromstring(principal_template)

    # get the arguments to fill in the XML
    prefix = _fill_xml_parameters(tree, subject, ordinal, ordinal)

    # get the old key or generate a new key and get the modulus and exponent
    private_key_file_name = private_key
    if private_key_file_name is None:
        private_key_file_name = subject_file_name + 'PrivateKey.xml'
        create_private_key(subject, prefix, 
                           private_key_file_name, policy_private_key, crypt_utility)
        
    _copy_public_portion(private_key_file_name, tree)
    _sign_tree(tree, output, crypt_utility, policy_private_key)


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

def create_policy(policy_file, cert_id, authority='CloudProxyPolicy', 
                crypt_utility=CRYPT_UTILITY, private_key=POLICY_KEY, 
                output='authorizationRuleSigned.xml'):
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

    _sign_tree(tree, output, crypt_utility, private_key)


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

