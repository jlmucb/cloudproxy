#! /bin/sh

for i in *.dl
do
  b=`basename $i .dl`
  ./datalog $i | sort > $b.out
  diff -u $b.txt $b.out
done
