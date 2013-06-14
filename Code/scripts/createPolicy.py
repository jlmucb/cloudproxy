#!/usr/bin/env python

import argparse
from cloud_proxy import create_policy

# set up a parser to read the command line arguments
parser = argparse.ArgumentParser(description='Creates a new policy from a set'
                                             ' of policy statements. This is'
                                             ' meant to be executed in the root'
                                             ' executable directory of the'
                                             ' FileProxy tree.')
parser.add_argument('policy_file', help='A text file of policy statements, one'
                                        ' per line')
parser.add_argument('cert_id', type=int, help='The ordinal identifier of this'
                                              ' certificate in the Policy'
                                              ' namespace')
parser.add_argument('--authority', default='fileProxyPolicy/0001', 
                    help='The principal that is asserting this policy. Should'
                         ' be the principal corresponding to the private key'
                         ' (default fileProxyPolicy/0001)')
parser.add_argument('--crypt_utility', help='The path to cryptUtility.exe'
                    ' (default ./cryptUtility.exe)',
                    default='./cryptUtility.exe')
parser.add_argument('--private_key',
                    help='The path to the private key file to use to sign this'
                         ' policy (default policy/privatePolicyKey.xml)', 
                    default='policy/privatePolicyKey.xml')
parser.add_argument('--output', 
                    help='The name of the signed authorization file to output'
                         ' (default authorizationRuleSigned.xml)',
                    default='authorizationRuleSigned.xml')

args = parser.parse_args()

create_policy(args.policy_file, args.cert_id, args.authority,
              args.crypt_utility, args.private_key, args.output)
