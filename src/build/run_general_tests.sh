#!/bin/bash

for i in out/Release/bin/*_unittests; do
  $i
done
