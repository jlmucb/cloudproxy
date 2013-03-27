#!/usr/bin/env python

from subprocess import check_call
import os, sys

scriptPath = os.path.dirname(__file__)

check_call([os.path.join(scriptPath, "createPrincipal.py"), "5", "AuthServer"])
check_call(["./cryptUtility.exe", "-EncapsulateMessage", "authServer/cert", "authServer/signingKeyMetaData", "AuthServerPrivateKey.xml", "authServer/signingKey"])
check_call(["cp", "AuthServerPublicKey.xml", "authServer/signingCert"])
