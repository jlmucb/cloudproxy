#!/bin/sh

# clear out any tests that might already be in the tests directory
rm -fr bidClient/tests/* &>/dev/null

# get a list of all the directories in bidClient/testSets and use them to run auctions and get results
testSets=`ls bidClient/testSets`
for dir in $testSets; do
    # copy the dir over to bidClient/tests
    cp -r bidClient/testSets/$dir bidClient/tests/
    ./runAuction.sh | awk "{ printf \"%-15s\t%-15f\\n\", \"$dir\" , \$2}" 

    # clean up the directory
    rm -fr bidClient/tests/$dir &>/dev/null
done


