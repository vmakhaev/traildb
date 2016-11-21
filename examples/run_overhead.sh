#!/bin/bash

#!/bin/bash

export LD_LIBRARY_PATH=`pwd`
for ((i=12;i<28;i+=1))
do
    echo "Round $i"
    pkill -f traildb-s3-server
    rm -Rf /mnt/*
    BS=$(python -c "print 2**$i / 1024")
    ./traildb-s3-server -blocksize $BS -max-size 200000 -root /mnt &
    sleep 1
    ./tdb dump -i s3://traildb.io/data/wikipedia-history-small.tdb >/dev/null
    /usr/bin/time -p ./tdb dump -i s3://traildb.io/data/wikipedia-history-small.tdb > /dev/null 2> "time.$i"
done
