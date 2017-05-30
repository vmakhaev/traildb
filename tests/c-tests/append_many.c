
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include <traildb.h>
#include <tdb_io.h>

#include "tdb_test.h"

static tdb *merge(const char *root,
                  const char **fields,
                  uint32_t num_fields,
                  tdb** dbs,
                  uint32_t num_dbs)
{
    char path[TDB_MAX_PATH_SIZE];
    tdb_path(path, "%s.merge", root);
    tdb_cons* c = tdb_cons_init();
    test_cons_settings(c);
    assert(tdb_cons_open(c, path, fields, num_fields) == 0);
    assert(tdb_cons_append_many(c, (const tdb**)dbs, num_dbs) == 0);
    assert(tdb_cons_finalize(c) == 0);
    tdb_cons_close(c);

    tdb *db = tdb_init();
    assert(tdb_open(db, path) == 0);
    return db;
}

static void empty_tdbs(const char *root)
{
    const uint32_t NUM = 5;
    uint32_t i;
    char path[TDB_MAX_PATH_SIZE];
    const char *fields[] = {};
    tdb *dbs[NUM];

    for (i = 0; i < NUM; i++){
        tdb_path(path, "%s.%u", root, i);
        tdb_cons* c1 = tdb_cons_init();
        test_cons_settings(c1);
        assert(tdb_cons_open(c1, path, fields, 0) == 0);
        assert(tdb_cons_finalize(c1) == 0);
        tdb_cons_close(c1);
        dbs[i] = tdb_init();
        assert(tdb_open(dbs[i], path) == 0);
    }

    tdb *db = merge(root, fields, 0, dbs, NUM);
    assert(tdb_num_trails(db) == 0);
    assert(tdb_num_fields(db) == 1);
    tdb_close(db);
}

static void mixed_size_tdbs(const char *root)
{
    const uint32_t NUM = 10;
    uint32_t i, j;
    char path[TDB_MAX_PATH_SIZE];
    const char *fields[] = {"f1", "f2"};
    char v1, v2;
    char *values[] = {&v1, &v2};
    const uint64_t lengths[] = {1, 1};
    static uint8_t uuid[16];
    tdb *dbs[NUM];
    uint32_t trail1_len = 0;
    uint32_t trail2_len = 0;

    for (i = 0; i < NUM; i++){
        tdb_path(path, "%s.%u", root, i);
        tdb_cons* c1 = tdb_cons_init();
        test_cons_settings(c1);
        assert(tdb_cons_open(c1, path, fields, 2) == 0);

        uuid[0] = 0;
        for (j = 0; j < i; j++){
            v1 = (char)('A' + i);
            v2 = 'x';
            assert(tdb_cons_add(c1, uuid, i * NUM + j, (const char**)values, lengths) == 0);
            trail1_len++;
        }
        uuid[0] = 1;
        for (j = 0; j < (i % 2); j++){
            v1 = (char)('a' + i);
            v2 = 'y';
            assert(tdb_cons_add(c1, uuid, i * NUM + j, (const char**)values, lengths) == 0);
            trail2_len++;
        }

        assert(tdb_cons_finalize(c1) == 0);
        tdb_cons_close(c1);
        dbs[i] = tdb_init();
        assert(tdb_open(dbs[i], path) == 0);
    }

    tdb *db = merge(root, fields, 2, dbs, NUM);
    assert(tdb_num_trails(db) == 2);
    assert(tdb_lexicon_size(db, 1) == 15);
    assert(tdb_lexicon_size(db, 2) == 3);
    tdb_cursor *cursor = tdb_cursor_new(db);
    assert(tdb_get_trail(cursor, 0) == 0);
    assert(tdb_get_trail_length(cursor) == trail1_len);
    assert(tdb_get_trail(cursor, 1) == 0);
    assert(tdb_get_trail_length(cursor) == trail2_len);
}

static void mismatching_fields(const char *root)
{
    char path[TDB_MAX_PATH_SIZE];
    const char *fields1[] = {"a", "b", "c"};
    const char *fields2[] = {"d", "e"};
    tdb *dbs[2];

    tdb_path(path, "%s.%u", root, 1);
    tdb_cons* c1 = tdb_cons_init();
    test_cons_settings(c1);
    assert(tdb_cons_open(c1, path, fields1, 2) == 0);
    assert(tdb_cons_finalize(c1) == 0);
    dbs[0] = tdb_init();
    assert(tdb_open(dbs[0], path) == 0);

    tdb_path(path, "%s.%u", root, 2);
    tdb_cons* c2 = tdb_cons_init();
    test_cons_settings(c2);
    assert(tdb_cons_open(c2, path, fields1, 3) == 0);
    assert(tdb_cons_finalize(c2) == 0);
    dbs[1] = tdb_init();
    assert(tdb_open(dbs[1], path) == 0);

    tdb_path(path, "%s.merged", root);
    tdb_cons* c = tdb_cons_init();
    test_cons_settings(c);
    assert(tdb_cons_open(c, path, fields2, 2) == 0);
    assert(tdb_cons_append_many(c, (const tdb**)dbs, 2) == TDB_ERR_APPEND_FIELDS_MISMATCH);
}

int main(int argc, char** argv)
{
    empty_tdbs(getenv("TDB_TMP_DIR"));
    mixed_size_tdbs(getenv("TDB_TMP_DIR"));
    mismatching_fields(getenv("TDB_TMP_DIR"));
}
