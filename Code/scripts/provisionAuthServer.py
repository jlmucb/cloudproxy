#!/usr/bin/env python

import cloud_proxy
from subprocess import check_call

cloud_proxy.create_principal(5, 'AuthServer')

# this should be added to cloud_proxy
check_call(["./cryptUtility.exe", "-EncapsulateMessage", "authServer/cert", "authServer/signingKeyMetaData", "AuthServerPrivateKey.xml", "authServer/signingKey"])
check_call(["cp", "AuthServerPublicKey.xml", "authServer/signingCert"])
