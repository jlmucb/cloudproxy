#!/bin/bash

for i in *.cpp *.cc *.h; do 
  ../../bin/clang-format -i --style=Google $i
done
