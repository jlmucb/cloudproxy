#!/usr/bin/env python

from __future__ import print_function
from subprocess import check_call
import os
import argparse

parser = argparse.ArgumentParser(description="Generates the keys for authServer.exe")
parser.add_argument("--scriptPath", required="true", help="The path to the directory that contains the scripts used by provisionAuthServer.py")

args = parser.parse_args()

check_call([os.path.join(args.scriptPath, "createPrincipal.py"), "5", "AuthServer"])
check_call(["./cryptUtility.exe", "-EncapsulateMessage", "AuthServerPublicKey.xml", "authServer/signingKeyMetaData", "AuthServerPrivateKey.xml", "authServer/signingKey"])
check_call(["cp", "AuthServerPublicKey.xml", "authServer/signingCert"])
