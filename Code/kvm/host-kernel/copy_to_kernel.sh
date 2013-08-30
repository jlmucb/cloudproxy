#!/bin/sh

if [[ "$1" == "" ]]; then
    KERNEL_DIR=/usr/src/linux-3.10.1
else
    KERNEL_DIR=$1
fi

for i in `find . -not -name "*.patch" -and -not -type d`; do 
    dir=`dirname $i`
    mkdir -p ${KERNEL_DIR}/$dir
    cp $i ${KERNEL_DIR}/$i
done



