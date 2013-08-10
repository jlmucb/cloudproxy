#!/bin/bash
rm -fr b_meas/* bootstrap_files/* boots*
mkdir bootstrap_files
cp ~/src/fileProxy/Code/cloudproxy/src/out/Default/bin/bootstrap .
cp ~/src/fileProxy/Code/cloudproxy/src/out/Default/bin/server .
cat sample_whitelist.pb2 | sed "s/REPLACE_ME/`cat server | ./getHash.sh`/g" > whitelist.pb2
cat whitelist.pb2 | protoc -I/home/tmroeder/src/fileProxy/Code/cloudproxy/src/tao/ --encode=tao.Whitelist /home/tmroeder/src/fileProxy/Code/cloudproxy/src/tao/hosted_programs.proto > whitelist
~/src/fileProxy/Code/cloudproxy/src/out/Default/bin/sign_whitelist 
