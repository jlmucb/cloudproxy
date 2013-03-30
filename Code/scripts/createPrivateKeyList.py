#!/usr/bin/env python

import argparse
from cloud_proxy import create_private_keys

parser = argparse.ArgumentParser(description="Creates a PrivateKeys file from files specified on the command line")
parser.add_argument("files", nargs="*", help="A list of files to insert into the PrivateKeys structure")
parser.add_argument("-o", "--output", required="true", help="The name of the PrivateKeys XML file to output")
args = parser.parse_args()

create_private_keys(args.files, args.output)
