#!/bin/sh

# this test assumes that the authServer has been set up and provisioned using provisionAuthTests.sh
(rm -f authClient/*) &>/dev/null
(./authClient.exe -initProg) &>/dev/null
sleep 5

grep "<ErrorCode>accept</ErrorCode>" authClient.log &>/dev/null
status=$?
if [ $status -eq 0 ]; then
  echo -ne "authClient\t"
else 
  echo "authClient failed"
  exit $status
fi 

# get the test execution time in seconds
grep "Test time =" authClient.log | sed 's/.*= \[\([0-9.][0-9.]*\)\].*/\1/' | awk '{print $1/1000000}'
