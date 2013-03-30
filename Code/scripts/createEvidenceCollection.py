#!/usr/bin/env python

import argparse
from cloud_proxy import create_evidence_collection

parser = argparse.ArgumentParser(description='Creates an EvidenceCollection consisting of EvidenceLists, one for each file specified on the command line')
parser.add_argument('-l', '--lists', nargs='*', action='append', help='A list of files to combine as an EvidenceList in the EvidenceCollection. This can be specified multiple times to provide multiple lists. Note that the list should go from the leaf cert to the root cert.')
parser.add_argument('-o', '--output', required='true', help='The name of the EvidenceCollection XML file to output')
args = parser.parse_args()

create_evidence_collection(args.lists, args.output)
