#!/bin/sh

# get rid of all the sealed keys and bids from previous auctions
rm bidServer/* bidServer/bids/* sellerClient/* sellerClient/bids/* bidClient/*

# initialize the bidServer to get its sealed keys set up
./bidServer.exe -initProg
sleep 3

# initialize the sellerClient to get its sealed keys set up
./sellerClient.exe -initProg
sleep 3

# copy the seller's key as the sealing key and the bidServer as the signing key
cp sellerClient/cert bidServer/sealingCert
cp bidServer/cert bidServer/signingCert

# start the bidServer for real
./bidServer.exe -initProg
