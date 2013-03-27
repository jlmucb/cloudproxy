#!/usr/bin/env python

from __future__ import print_function
import argparse
from xml.etree import ElementTree as ET

parser = argparse.ArgumentParser(description="Creates an EvidenceCollection consisting of EvidenceLists, one for each file specified on the command line")
parser.add_argument("files", nargs="*", help="A list of files to combine as EvidenceLists in an EvidenceCollection")
parser.add_argument("-o", "--output", required="true", help="The name of the EvidenceCollection XML file to output")
args = parser.parse_args()

# the XML components needed to make a list
evidenceCollectionPrefix = '<EvidenceCollection count="{0}">'.format(len(args.files))
evidenceCollectionSuffix = '</EvidenceCollection>'

evidenceListPrefix = '<EvidenceList count="1">'
evidenceListSuffix = '\n</EvidenceList>'

# open the output file for writing and add the evidence lists
with open(args.output, "wb") as output:
    print(evidenceCollectionPrefix, file=output)

    for fileName in args.files:
        print(evidenceListPrefix, file=output)
        with open(fileName, 'rb') as f:
            for line in f.readlines():
                print(line, end='', file=output)
        print(evidenceListSuffix, file=output)
    print(evidenceCollectionSuffix, file=output)
