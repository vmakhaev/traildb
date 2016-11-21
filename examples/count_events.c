
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <traildb.h>

static uint64_t count_events(tdb *db, int num, int is_random)
{
    int i;
    uint64_t max = tdb_num_trails(db) - 1;
    tdb_cursor *cursor = tdb_cursor_new(db);
    uint64_t trail_id;
    uint64_t total = 0;

    for (i = 0; i < num; i++){
        if (is_random)
            trail_id = (rand() / (float)RAND_MAX) * max;
        else
            trail_id = i;

        tdb_get_trail(cursor, trail_id);
        total += tdb_get_trail_length(cursor);
    }

    return total;
}

int main(int argc, char **argv)
{
    tdb_error err;
    tdb* db = tdb_init();
    int num;
    uint64_t total;

    srand(getpid());

    if (argc < 4){
        printf("Usage: count_events tdb ['random'|'sequential'] num-trails\n");
        exit(1);
    }
    num = atoi(argv[3]);

    if ((err = tdb_open(db, argv[1]))){
        printf("Opening TrailDB at %s failed: %s\n", argv[1], tdb_error_str(err));
        exit(1);
    }

    if (!(num < tdb_num_trails(db))){
        printf("num-trails must be smaller than the actual number of trails\n");
        exit(1);
    }

    if (!strcmp(argv[2], "random")){
        printf("Counting events for random %u trails\n", num);
        total = count_events(db, num, 1);
    }else if (!strcmp(argv[2], "sequential")){
        printf("Counting events for the first %u trails\n", num);
        total = count_events(db, num, 0);
    }else{
        printf("The second argument needs to be either 'random' or 'sequential'\n");
        exit(1);
    }

    printf("Total events: %lu\n", total);
    return 0;
}
