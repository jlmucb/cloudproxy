#!/usr/bin/env python

from __future__ import print_function
import argparse
from xml.etree import ElementTree as ET

parser = argparse.ArgumentParser(description='Creates an EvidenceCollection consisting of EvidenceLists, one for each file specified on the command line')
parser.add_argument('-l', '--lists', nargs='*', action='append', help='A list of files to combine as an EvidenceList in the EvidenceCollection. This can be specified multiple times to provide multiple lists. Note that the list should go from the leaf cert to the root cert.')
parser.add_argument('-o', '--output', required='true', help='The name of the EvidenceCollection XML file to output')
args = parser.parse_args()

# the XML components needed to make a list
evidence_collection_prefix = '<EvidenceCollection count="{0}">'.format(len(args.lists))
evidence_collection_suffix = '</EvidenceCollection>'

evidence_list_prefix_template = '<EvidenceList count="{0}">'
evidence_list_suffix = '\n</EvidenceList>'

# open the output file for writing and add the evidence lists
with open(args.output, 'wb') as output:
    print(evidence_collection_prefix, file=output)

    for file_list in args.lists:
        print(evidence_list_prefix_template.format(len(file_list)), file=output)
        for file_name in file_list:
            with open(file_name, 'rb') as f:
                for line in f:
                    print(line, end='', file=output)
        print(evidence_list_suffix, file=output)
    print(evidence_collection_suffix, file=output)
