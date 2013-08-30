#!/bin/sh

if [[ "$1" == "" ]]; then
    KERNEL_DIR=/usr/src/linux-3.10.1-guest
else
    KERNEL_DIR=$1
fi

for i in `find . -name "*.c" -or -name "*.h" -or -name "Makefile" -or -name "Kbuild"`; do 
    cp $i ${KERNEL_DIR}/$i
done



