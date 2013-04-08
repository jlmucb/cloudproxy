#!/bin/sh

for count in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    for j in 1 100 500 1000; do
        for t in none tls enc full; do
            ./dummyServer 10.0.0.3 12345 $t > file.${j}.${t}.enc
            echo "Server finished $t"
        done
    done
done
