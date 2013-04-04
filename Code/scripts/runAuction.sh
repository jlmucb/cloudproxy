#!/bin/sh

# This code assumes that the auction system has been provisioned using the steps in provisionAuction.sh
# TODO: This code also assumes that the test file has only one auction specification in it

rm bidServer/bids/* sellerClient/bids/* sellerClient/resolve

# run the client programs
./bidClient.exe -initProg
sleep 5

# copy the bids over the to sellerClient
cp bidServer/bids/* sellerClient/bids/

# tell the sellerClient to resolve auction 1
echo 1 >> sellerClient/resolve

./sellerClient.exe -initProg
sleep 3

# process the log to see if the auction was successfully concluded
grep "auction successfully concluded" sellerClient.log
if [ $? -ne 0 ]; then
  echo "The auction failed"
  exit 1
else
  echo "The auction passed"
fi

winner=`cat sellerClient.log | awk '/<WinnerCert>/,/<\/WinnerCert>/' | grep SubjectName | sed 's/^.*SubjectName>\(.*\)<\/SubjectName>.*$/\1/'`
xmlWinner=`cat bidClient/tests/basicBidTest/tests.xml | grep "Winner name" | sed 's/^.*Winner name="\(.*\)".*$/\1/'`

if [ "$winner" = "$xmlWinner" ]; then
  echo "The auction succeeded as expected"
else 
  echo "The auction failed. Expected winner $xmlWinner but got winner $winner"
  exit 1
fi
