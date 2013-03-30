import re
from subprocess import check_call
import tempfile
from xml.etree import ElementTree as ET

# set up a parser to read the command line arguments
parser = argparse.ArgumentParser(description="Creates a new policy from a set of policy statements")
parser.add_argument("id", type=int, help="The ordinal identifier of this certificate in the User namespace")
parser.add_argument("subject", help="The name of the principal to create. This name will also be used as the name of the key. If used in file name, characters that are invalid for file names will be replaced with underscore.")
parser.add_argument("--privateKey", help="The private key file to use. If none is specified, then a new file will be generated with the name <subject>PrivateKey.xml")
parser.add_argument("--cryptUtility", default="./cryptUtility.exe", help="The path to cryptUtility.exe (default ./cryptUtility.exe)")
parser.add_argument("--policyPrivateKey", default="policy/privatePolicyKey.xml", help="The path to the private key file to use to sign this policy (default policy/privatePolicyKey.xml)")
parser.add_argument("--output", help="The name of the signed public key file to output (default <subject>PublicKey.xml)")

args = parser.parse_args()

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

dsns='{http://www.w3.org/2000/09/xmldsig#}'

def create_principal(id, subject, private_key, cryptUtility, policyPrivateKey, output):
    # parse the policy template as XML
    tree = ET.fromstring(principalTemplate)

    # get the arguments to fill in the XML

    # append id to the Id of Certificate and write it as the serial number
    grantNode = tree.find("Certificate")
    curCertID = grantNode.get("Id")
    newCertID = curCertID + str(args.id)
    grantNode.set("Id", newCertID)

    serialNode = grantNode.find("SerialNumber")
    serialNode.text = "{0}".format(args.id);

    # write the subject name to the SubjectName
    subjectNameNode = grantNode.find("SubjectName")
    slashRe = re.compile(r'/')
    subjectFileName = slashRe.sub("_", args.subject)
    subjectNameNode.text = subjectNameNode.text + args.subject

    # write the key name to the KeyInfo KeyName 
    # attribute, and the SubjectKeyID
    keyInfoNode = grantNode.find("SubjectKey/{0}KeyInfo".format(dsns))
    keyPrefix = keyInfoNode.get("KeyName")
    keyInfoNode.set("KeyName", keyPrefix + args.subject)

    subjectKeyIDNode = grantNode.find("SubjectKeyID")
    subjectKeyIDNode.text = subjectKeyIDNode.text + args.subject

    def transformNamespace(xmlStr):
        # convert the default ns0 from elementtree to ds to compensate for the 
        # lack of correct namespace handling in TinyXML
        namespacePatt = re.compile('ns0:')
        namespacePatt2 = re.compile(':ns0=')
        return namespacePatt2.sub(":ds=", namespacePatt.sub('ds:', xmlStr)) 

    # get the old key or generate a new key and get the modulus and exponent
    privateKeyFileName = args.privateKey
    if privateKeyFileName is None:
        # get a temp file to write the private key and rewrite it to the named location 
        privateTemp = tempfile.NamedTemporaryFile()
        privateKeyFileName = subjectFileName + "PrivateKey.xml"
        check_call([args.cryptUtility, "-GenKey", "RSA1024", privateTemp.name])
        
        # rewrite the name of the key to match our public key
        privateTree = ET.parse(privateTemp.name)
        privateRoot = privateTree.getroot()
        privateRoot.set("KeyName", keyPrefix + args.subject)
        
        # write to the specified file name after transforming the namespace
        privateXmlStr = transformNamespace(ET.tostring(privateRoot))
        privateFile = open(privateKeyFileName, "wb")
        privateFile.write(privateXmlStr)
        privateFile.close() 
        
    pkTree = ET.parse(privateKeyFileName)
    rsaNode = pkTree.find("{0}KeyValue/{0}RSAKeyValue".format(dsns))
    modulusNode = rsaNode.find("{0}M".format(dsns))
    exponentNode = rsaNode.find("{0}E".format(dsns))

    pkRsaNode = keyInfoNode.find("{0}KeyValue/{0}RSAKeyValue".format(dsns))
    pkModulusNode = pkRsaNode.find("{0}M".format(dsns))
    pkExponentNode = pkRsaNode.find("{0}E".format(dsns))

    # copy the public key portions from the private key file to the
    # public key to be signed
    pkModulusNode.text = modulusNode.text
    pkExponentNode.text = exponentNode.text

    # write the resulting XML to a temp file and perform the signing operation
    temp = tempfile.NamedTemporaryFile()
    xmlStr = transformNamespace(ET.tostring(tree))

    # this temp file will be signed by cryptUtility
    temp.write(xmlStr)
    temp.flush() 

    # use the provided output file or the file <subject>PublicKey.xml
    outputFile = args.output
    if outputFile is None:
        outputFile = subjectFileName + "PublicKey.xml"

    # perform the signing operation using cryptUtility
    check_call([args.cryptUtility, "-Sign", args.policyPrivateKey, "rsa1024-sha256-pkcspad", temp.name, outputFile])
