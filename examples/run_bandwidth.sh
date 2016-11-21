#!/bin/bash

export LD_LIBRARY_PATH=`pwd`
for ((i=31;i<33;i++))
do
    rm -Rf /mnt/*
    ./traildb-s3-server -blocksize 16000 -max-size 200000 -root /mnt &
    for ((j=0;j<$i;j++))
    do
        ./count_events s3://traildb.io/data/wikipedia-history.tdb random 1000000 &
    done
    sleep 30
    pkill -f count_events
    pkill -f traildb
    du /mnt > $i.res
done
