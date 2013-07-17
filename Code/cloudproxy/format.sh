#!/bin/bash

for i in *.cc *.h; do 
  ../../bin/clang-format -i --style=Google $i
done
