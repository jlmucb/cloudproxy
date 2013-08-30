#!/bin/sh

if [[ "$1" == "" ]]; then
    KERNEL_DIR=/usr/src/linux-3.10.1
else
    KERNEL_DIR=$1
fi

cur_dir=`pwd`
for i in `find . -name "*.patch"`; do 
    dir=`dirname $i`
    (cd ${KERNEL_DIR}/$dir && patch -p0 < ${cur_dir}/$i)
done



