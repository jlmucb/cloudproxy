#!/usr/bin/env python

import argparse
from cloud_proxy import create_principal

# set up a parser to read the command line arguments
parser = argparse.ArgumentParser(description='Creates a new policy from a set of policy statements')
parser.add_argument('id', type=int, help='The ordinal identifier of this certificate in the User namespace')
parser.add_argument('subject', help='The name of the principal to create. This name will also be used as the name of the key. If used in file name, characters that are invalid for file names will be replaced with underscore.')
parser.add_argument('--private_key', help='The private key file to use. If none is specified, then a new file will be generated with the name <subject>PrivateKey.xml')
parser.add_argument('--crypt_utility', default='./cryptUtility.exe', help='The path to cryptUtility.exe (default ./cryptUtility.exe)')
parser.add_argument('--policy_private_key', default='policy/privatePolicyKey.xml', help='The path to the private key file to use to sign this policy (default policy/privatePolicyKey.xml)')
parser.add_argument('--output', help='The name of the signed public key file to output (default <subject>PublicKey.xml)')
parser.add_argument('--algorithm',
                    help='The name of the algorithm to use for signing',
                    default='rsa2048-sha256-pkcspad')
parser.add_argument('--key_size',
                    help='The size of key to generate',
                    default=2048)

args = parser.parse_args()

create_principal(args.id, args.subject, args.private_key, args.crypt_utility, args.policy_private_key, args.output,
                 args.algorithm, args.key_size)
