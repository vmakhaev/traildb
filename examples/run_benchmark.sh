#!/bin/bash

export LD_LIBRARY_PATH=`pwd`
for ((i=0;i<2000;i+=10))
do
    echo "Round $i"
    pkill -f traildb-s3-server
    rm -Rf /mnt/*
    ./traildb-s3-server -max-size 200000 -root /mnt &
    sleep 1
    /usr/bin/time -p ./count_events s3://traildb.io/data/wikipedia-history-small.tdb random $i > "random.$i" 2> "random.err.$i"
done
