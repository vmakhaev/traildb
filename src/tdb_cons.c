#define _DEFAULT_SOURCE /* ftruncate() */
#define _GNU_SOURCE

#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#undef JUDYERROR
#define JUDYERROR(CallerFile, CallerLine, JudyFunc, JudyErrno, JudyErrID) \
{                                                                         \
   if ((JudyErrno) == JU_ERRNO_NOMEM)                                     \
       goto out_of_memory;                                                \
}
#include <Judy.h>

#include "judy_str_map.h"
#include "tdb_internal.h"
#include "tdb_error.h"
#include "tdb_io.h"
#include "tdb_package.h"
#include "arena.h"

#include "pqueue/pqueue.h"

#ifndef EVENTS_ARENA_INCREMENT
#define EVENTS_ARENA_INCREMENT 1000000
#endif

#ifndef CONS_APPEND_MANY_NUM_EVENTS
#define CONS_APPEND_MANY_NUM_EVENTS 10000
#endif

struct jm_fold_state{
    FILE *out;
    uint64_t offset;
    tdb_error ret;
    uint64_t width;
};

static void *lexicon_store_fun(uint64_t id,
                               const char *value,
                               uint64_t len,
                               void *state)
{
    struct jm_fold_state *s = (struct jm_fold_state*)state;
    int ret = 0;

    if (s->ret)
        return state;

    /* NOTE: vals start at 1, otherwise we would need to +1 */
    TDB_SEEK(s->out, id * s->width);
    TDB_WRITE(s->out, &s->offset, s->width);

    TDB_SEEK(s->out, s->offset);
    TDB_WRITE(s->out, value, len);

done:
    s->ret = ret;
    s->offset += len;
    return state;
}

static tdb_error lexicon_store(const struct judy_str_map *lexicon,
                               const char *path)
{
    /*
    Lexicon format:
    [ number of values N ] 4 or 8 bytes
    [ value offsets ...  ] N * (4 or 8 bytes)
    [ last value offset  ] 4 or 8 bytes
    [ values ...         ] X bytes
    */

    struct jm_fold_state state;
    uint64_t count = jsm_num_keys(lexicon);
    uint64_t size = (count + 2) * 4 + jsm_values_size(lexicon);
    int ret = 0;

    state.offset = (count + 2) * 4;
    state.width = 4;

    if (size > UINT32_MAX){
        size = (count + 2) * 8 + jsm_values_size(lexicon);
        state.offset = (count + 2) * 8;
        state.width = 8;
    }

    if (size > TDB_MAX_LEXICON_SIZE)
        return TDB_ERR_LEXICON_TOO_LARGE;

    state.out = NULL;
    state.ret = 0;

    TDB_OPEN(state.out, path, "w");
    TDB_TRUNCATE(state.out, (off_t)size);
    TDB_WRITE(state.out, &count, state.width);

    jsm_fold(lexicon, lexicon_store_fun, &state);
    if ((ret = state.ret))
        goto done;

    TDB_SEEK(state.out, (count + 1) * state.width);
    TDB_WRITE(state.out, &state.offset, state.width);

done:
    TDB_CLOSE_FINAL(state.out);
    return ret;
}

static tdb_error store_lexicons(tdb_cons *cons)
{
    tdb_field i;
    FILE *out = NULL;
    char path[TDB_MAX_PATH_SIZE];
    int ret = 0;

    TDB_PATH(path, "%s/fields", cons->root);
    TDB_OPEN(out, path, "w");

    for (i = 0; i < cons->num_ofields; i++){
        TDB_PATH(path, "%s/lexicon.%s", cons->root, cons->ofield_names[i]);
        if ((ret = lexicon_store(&cons->lexicons[i], path)))
            goto done;
        TDB_FPRINTF(out, "%s\n", cons->ofield_names[i]);
    }
    TDB_FPRINTF(out, "\n");
done:
    TDB_CLOSE_FINAL(out);
    return ret;
}

static tdb_error store_version(tdb_cons *cons)
{
    FILE *out = NULL;
    char path[TDB_MAX_PATH_SIZE];
    int ret = 0;

    TDB_PATH(path, "%s/version", cons->root);
    TDB_OPEN(out, path, "w");
    TDB_FPRINTF(out, "%llu", TDB_VERSION_LATEST);
done:
    TDB_CLOSE_FINAL(out);
    return ret;
}

static void *store_uuids_fun(__uint128_t key,
                             Word_t *value __attribute__((unused)),
                             void *state)
{
    struct jm_fold_state *s = (struct jm_fold_state*)state;
    int ret = 0;
    TDB_WRITE(s->out, &key, 16);
done:
    s->ret = ret;
    return s;
}

static tdb_error store_uuids(tdb_cons *cons)
{
    char path[TDB_MAX_PATH_SIZE];
    struct jm_fold_state state = {.ret = 0};
    uint64_t num_trails = j128m_num_keys(&cons->trails);
    int ret = 0;

    /* this is why num_trails < TDB_MAX)NUM_TRAILS < 2^59:
       (2^59 - 1) * 16 < LONG_MAX (off_t) */
    if (num_trails > TDB_MAX_NUM_TRAILS)
        return TDB_ERR_TOO_MANY_TRAILS;

    TDB_PATH(path, "%s/uuids", cons->root);
    TDB_OPEN(state.out, path, "w");
    TDB_TRUNCATE(state.out, ((off_t)(num_trails * 16)));

    j128m_fold(&cons->trails, store_uuids_fun, &state);
    ret = state.ret;

done:
    TDB_CLOSE_FINAL(state.out);
    return ret;
}

int is_fieldname_invalid(const char* field)
{
    uint64_t i;

    if (!strcmp(field, "time"))
        return 1;

    for (i = 0; i < TDB_MAX_FIELDNAME_LENGTH && field[i]; i++)
        if (!index(TDB_FIELDNAME_CHARS, field[i]))
            return 1;

    if (i == 0 || i == TDB_MAX_FIELDNAME_LENGTH)
        return 1;

    return 0;
}

static tdb_error find_duplicate_fieldnames(const char **ofield_names,
                                           uint64_t num_ofields)
{
    Pvoid_t check = NULL;
    tdb_field i;
    Word_t tmp;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-compare"
    for (i = 0; i < num_ofields; i++){
        Word_t *ptr;
        JSLI(ptr, check, (const uint8_t*)ofield_names[i]);
        if (*ptr){
            JSLFA(tmp, check);
            return TDB_ERR_DUPLICATE_FIELDS;

        }
        *ptr = 1;
    }
    JSLFA(tmp, check);
#pragma GCC diagnostic pop
    return 0;

out_of_memory:
    return TDB_ERR_NOMEM;
}

TDB_EXPORT tdb_cons *tdb_cons_init(void)
{
    tdb_cons *c = calloc(1, sizeof(tdb_cons));
    if (c){
        /*
        this will fail if libarchive is not found but it is ok, we just
        fall back to the directory mode
        */
        tdb_cons_set_opt(c,
                         TDB_OPT_CONS_OUTPUT_FORMAT,
                         opt_val(TDB_OPT_CONS_OUTPUT_FORMAT_PACKAGE));
    }
    return c;
}

TDB_EXPORT tdb_error tdb_cons_open(tdb_cons *cons,
                                   const char *root,
                                   const char **ofield_names,
                                   uint64_t num_ofields)
{
    tdb_field i;
    int fd;
    int ret = 0;

    /*
    by handling the "cons == NULL" case here gracefully, we allow the return
    value of tdb_init() to be used unchecked like here:

    int err;
    tdb_cons *cons = tdb_cons_init();
    if ((err = tdb_cons_open(cons, path, fields, num_fields)))
        printf("Opening cons failed: %s", tdb_error(err));
    */
    if (!cons)
        return TDB_ERR_HANDLE_IS_NULL;

    if (cons->events.item_size)
        return TDB_ERR_HANDLE_ALREADY_OPENED;

    if (num_ofields > TDB_MAX_NUM_FIELDS)
        return TDB_ERR_TOO_MANY_FIELDS;

    if ((ret = find_duplicate_fieldnames(ofield_names, num_ofields)))
        goto done;

    if (!(cons->ofield_names = calloc(num_ofields, sizeof(char*))))
        return TDB_ERR_NOMEM;

    for (i = 0; i < num_ofields; i++){
        if (is_fieldname_invalid(ofield_names[i])){
            ret = TDB_ERR_INVALID_FIELDNAME;
            goto done;
        }
        if (!(cons->ofield_names[i] = strdup(ofield_names[i]))){
            ret = TDB_ERR_NOMEM;
            goto done;
        }
    }

    j128m_init(&cons->trails);

    if (!(cons->root = strdup(root))){
        ret = TDB_ERR_NOMEM;
        goto done;
    }

    cons->uuid_ptr = NULL;
    cons->min_timestamp = UINT64_MAX;
    cons->num_ofields = num_ofields;
    cons->events.arena_increment = EVENTS_ARENA_INCREMENT;
    cons->events.item_size = sizeof(struct tdb_cons_event);
    cons->items.item_size = sizeof(tdb_item);

    /* Opportunistically try to create the output directory.
       We don't care if it fails, e.g. because it already exists */
    mkdir(root, 0755);
    TDB_PATH(cons->tempfile, "%s/tmp.items.XXXXXX", root);
    if ((fd = mkstemp(cons->tempfile)) == -1){
        ret = TDB_ERR_IO_OPEN;
        goto done;
    }

    if (!(cons->items.fd = fdopen(fd, "w"))){
        ret = TDB_ERR_IO_OPEN;
        goto done;
    }

    if (cons->num_ofields > 0)
        if (!(cons->lexicons = calloc(cons->num_ofields,
                                      sizeof(struct judy_str_map)))){
            ret = TDB_ERR_NOMEM;
            goto done;
        }

    for (i = 0; i < cons->num_ofields; i++)
        if (jsm_init(&cons->lexicons[i])){
            ret = TDB_ERR_NOMEM;
            goto done;
        }

done:
    return ret;
}

TDB_EXPORT void tdb_cons_close(tdb_cons *cons)
{
    if(cons){
        uint64_t i;
        for (i = 0; i < cons->num_ofields; i++){
            if (cons->ofield_names)
                free(cons->ofield_names[i]);
            if (cons->lexicons)
                jsm_free(&cons->lexicons[i]);
        }
        free(cons->lexicons);
        if (cons->items.fd)
            fclose(cons->items.fd);
        if (cons->events.data)
            free(cons->events.data);
        if (cons->items.data)
            free(cons->items.data);

        j128m_free(&cons->trails);
        free(cons->ofield_names);
        free(cons->root);
        free(cons);
    }
}

/*
Append an event in this cons.
*/
TDB_EXPORT tdb_error tdb_cons_add(tdb_cons *cons,
                                  const uint8_t uuid[16],
                                  const uint64_t timestamp,
                                  const char **values,
                                  const uint64_t *value_lengths)
{
    tdb_field i;
    struct tdb_cons_event *event;
    Word_t *uuid_ptr;
    __uint128_t uuid_key;

    for (i = 0; i < cons->num_ofields; i++)
        if (value_lengths[i] > TDB_MAX_VALUE_SIZE)
            return TDB_ERR_VALUE_TOO_LONG;

    memcpy(&uuid_key, uuid, 16);

    /* optimization:
    it is typical to insert many events for a UUID consecutively.
    We don't need to lookup the same UUID repeatedly, we can use
    the previously looked up value, cons->uuid_ptr, instead
    */
    if (cons->uuid_ptr && uuid_key == cons->prev_uuid)
        uuid_ptr = cons->uuid_ptr;
    else{
        cons->prev_uuid = uuid_key;
        uuid_ptr = cons->uuid_ptr = j128m_insert(&cons->trails, uuid_key);
    }

    if (!(event = (struct tdb_cons_event*)arena_add_item(&cons->events)))
        return TDB_ERR_NOMEM;

    event->item_zero = cons->items.next;
    event->num_items = 0;
    event->timestamp = timestamp;
    event->prev_event_idx = *uuid_ptr;
    *uuid_ptr = cons->events.next;

    if (timestamp < cons->min_timestamp)
        cons->min_timestamp = timestamp;

    for (i = 0; i < cons->num_ofields; i++){
        /*
        To conserve space (and time), only store non-empty values.
        Missing fields are intepreted as nulls during encoding.
        */
        if (value_lengths[i]){
            tdb_field field = (tdb_field)(i + 1);
            tdb_val val = 0;
            tdb_item item;
            void *dst;

            if (!(val = (tdb_val)jsm_insert(&cons->lexicons[i],
                                            values[i],
                                            value_lengths[i])))
                return TDB_ERR_NOMEM;

            item = tdb_make_item(field, val);
            if (!(dst = arena_add_item(&cons->items)))
                /*
                cons->items is a file-backed arena, so this is most
                likely caused by disk being full, hence an IO error.
                */
                return TDB_ERR_IO_WRITE;

            memcpy(dst, &item, sizeof(tdb_item));
            ++event->num_items;
        }
    }
    return 0;
}

static tdb_error append_event_str(tdb_cons *cons,
                                  const tdb *db,
                                  const uint8_t *uuid,
                                  const tdb_event *event,
                                  const char **values,
                                  uint64_t *lengths,
                                  uint64_t num_fields)
{
    uint64_t i;
    tdb_error ret;
    memset(lengths, 0, num_fields * sizeof(uint64_t));

    for (i = 0; i < event->num_items; i++){
        tdb_field field = tdb_item_field(event->items[i]);
        tdb_val val = tdb_item_val(event->items[i]);
        values[field - 1] = tdb_get_value(db,
                                          field,
                                          val,
                                          &lengths[field - 1]);
    }

    return tdb_cons_add(cons,
                        uuid,
                        event->timestamp,
                        values,
                        lengths);
}

/*
this function adds events from db to cons one by one, using the
public API. We need to use this with filtered dbs or otherwise when
we need to re-create lexicons.
*/
static tdb_error tdb_cons_append_subset_lexicon(tdb_cons *cons, const tdb *db)
{
    const char **values = NULL;
    uint64_t *lengths = NULL;
    uint64_t trail_id;
    int ret = 0;
    const uint64_t num_fields = tdb_num_fields(db);

    tdb_cursor *cursor = tdb_cursor_new(db);
    if (!cursor)
        return TDB_ERR_NOMEM;

    if (!(values = malloc(num_fields * sizeof(char*)))){
        ret = TDB_ERR_NOMEM;
        goto done;
    }

    if (!(lengths = malloc(num_fields * sizeof(uint64_t)))){
        ret = TDB_ERR_NOMEM;
        goto done;
    }

    for (trail_id = 0; trail_id < tdb_num_trails(db); trail_id++){
        const tdb_event *event;

        if ((ret = tdb_get_trail(cursor, trail_id)))
            goto done;
        /*
        lookup UUID only if there are events:
        expensive to perform many unnecessary lookups with selective filters
        */
        if (tdb_cursor_peek(cursor)){
            const uint8_t *uuid = tdb_get_uuid(db, trail_id);
            while ((event = tdb_cursor_next(cursor))){
                if ((ret = append_event_str(cons,
                                            db,
                                            uuid,
                                            event,
                                            values,
                                            lengths,
                                            num_fields)))
                    goto done;
            }
        }
    }

done:
    free(values);
    free(lengths);
    tdb_cursor_free(cursor);
    return ret;
}

/*
Append the lexicons of an existing TrailDB, db, to this cons. Used by
tdb_cons_append().
*/
static uint64_t **append_lexicons(tdb_cons *cons, const tdb *db)
{
    tdb_val **lexicon_maps;
    tdb_val i;
    tdb_field field;

    if (!(lexicon_maps = calloc(cons->num_ofields, sizeof(tdb_val*))))
        return NULL;

    for (field = 0; field < cons->num_ofields; field++){
        struct tdb_lexicon lex;
        uint64_t *map;

        tdb_lexicon_read(db, field + 1, &lex);

        if (!(map = lexicon_maps[field] = malloc(lex.size * sizeof(tdb_val))))
            goto error;

        for (i = 0; i < lex.size; i++){
            uint64_t value_length;
            const char *value = tdb_lexicon_get(&lex, i, &value_length);
            tdb_val val;
            if ((val = (tdb_val)jsm_insert(&cons->lexicons[field],
                                            value,
                                            value_length)))
                map[i] = val;
            else
                goto error;
        }
    }
    return lexicon_maps;
error:
    for (i = 0; i < cons->num_ofields; i++)
        free(lexicon_maps[i]);
    free(lexicon_maps);
    return NULL;
}

/*
Take an event from the old db, translate its items to new vals
and append to the new cons
*/
static tdb_error append_event_map(tdb_cons *cons,
                                  const tdb_event *event,
                                  Word_t *uuid_ptr,
                                  tdb_val **lexicon_maps)
{
    uint64_t i;
    struct tdb_cons_event *new_event =
        (struct tdb_cons_event*)arena_add_item(&cons->events);

    if (!new_event)
        return TDB_ERR_NOMEM;

    new_event->item_zero = cons->items.next;
    new_event->num_items = 0;
    new_event->timestamp = event->timestamp;
    new_event->prev_event_idx = *uuid_ptr;
    *uuid_ptr = cons->events.next;

    for (i = 0; i < event->num_items; i++){
        tdb_val val = tdb_item_val(event->items[i]);
        /*
        To conserve space (and time), only store non-empty values.
        Missing fields are intepreted as nulls during encoding.
        */
        if (val){
            tdb_field field = tdb_item_field(event->items[i]);
            /* translate val */
            tdb_val new_val = lexicon_maps[field - 1][val - 1];
            tdb_item item = tdb_make_item(field, new_val);
            void *dst = arena_add_item(&cons->items);
            if (!dst)
                /*
                cons->items is a file-backed arena, so this is most
                likely caused by disk being full, hence an IO error.
                */
                return TDB_ERR_IO_WRITE;
            memcpy(dst, &item, sizeof(tdb_item));
            ++new_event->num_items;
        }
    }
    return TDB_ERR_OK;
}

/*
this function is an optimized version of tdb_cons_append_subset_lexicon():
instead of mapping items to strings and back, we know that all entries from
the lexicon will be needed, so we can merge the lexicons and add remap items
in db to items in cons, without going through strings.
*/
static tdb_error tdb_cons_append_full_lexicon(tdb_cons *cons, const tdb *db)
{
    tdb_val **lexicon_maps = NULL;
    uint64_t i, trail_id;
    int ret = 0;

    tdb_cursor *cursor = tdb_cursor_new(db);
    if (!cursor)
        return TDB_ERR_NOMEM;

    if (db->min_timestamp < cons->min_timestamp)
        cons->min_timestamp = db->min_timestamp;

    if (!(lexicon_maps = append_lexicons(cons, db))){
        ret = TDB_ERR_NOMEM;
        goto done;
    }

    for (trail_id = 0; trail_id < tdb_num_trails(db); trail_id++){
        __uint128_t uuid_key;
        Word_t *uuid_ptr;
        const tdb_event *event;

        if ((ret = tdb_get_trail(cursor, trail_id)))
            goto done;

        /*
        lookup UUID only if there are events:
        expensive to perform many unnecessary lookups with selective filters
        */
        if (tdb_cursor_peek(cursor)){
            memcpy(&uuid_key, tdb_get_uuid(db, trail_id), 16);
            uuid_ptr = j128m_insert(&cons->trails, uuid_key);
            while ((event = tdb_cursor_next(cursor)))
                if ((ret = append_event_map(cons,
                                            event,
                                            uuid_ptr,
                                            lexicon_maps)))
                    goto done;
        }
    }
done:
    if (lexicon_maps){
        for (i = 0; i < cons->num_ofields; i++)
            free(lexicon_maps[i]);
        free(lexicon_maps);
    }
    tdb_cursor_free(cursor);
    return ret;
}

/*
Merge an existing tdb to the new cons.
*/
TDB_EXPORT tdb_error tdb_cons_append(tdb_cons *cons, const tdb *db)
{
    tdb_field field;

    /* NOTE we could be much more permissive with what can be joined:
    we could support "full outer join" and replace all missing fields
    with NULLs automatically.
    */
    if (cons->num_ofields != db->num_fields - 1)
        return TDB_ERR_APPEND_FIELDS_MISMATCH;

    for (field = 0; field < cons->num_ofields; field++)
        if (strcmp(cons->ofield_names[field], tdb_get_field_name(db, field + 1)))
            return TDB_ERR_APPEND_FIELDS_MISMATCH;

    /* invalidate cached UUID ptr */
    cons->uuid_ptr = NULL;

    /* NOTE: When you add new options in tdb, remember to add them to
    the list below if they cause only a subset of events to be returned.
    */
    if (db->opt_event_filter ||
        db->opt_edge_encoded ||
        db->opt_trail_event_filters)
        /*
        Standard append: recreate lexicons through strings.
        We need to do this when only a subset of events is appended.
        */
        return tdb_cons_append_subset_lexicon(cons, db);
    else
        /*
        Optimized append: merge lexicons, remap items.
        We can do this when all events are appended.
        */
        return tdb_cons_append_full_lexicon(cons, db);
}

TDB_EXPORT tdb_error tdb_cons_finalize(tdb_cons *cons)
{
    struct tdb_file items_mmapped;
    uint64_t num_events = cons->events.next;
    int ret = 0;

    memset(&items_mmapped, 0, sizeof(struct tdb_file));

    /* finalize event items */
    if ((ret = arena_flush(&cons->items)))
        goto done;

    if (cons->items.fd && fclose(cons->items.fd)) {
        cons->items.fd = NULL;
        ret = TDB_ERR_IO_CLOSE;
        goto done;
    }
    cons->items.fd = NULL;

    if (cons->tempfile[0]){
        if (num_events && cons->num_ofields) {
            if (file_mmap(cons->tempfile, NULL, &items_mmapped, NULL)){
                ret = TDB_ERR_IO_READ;
                goto done;
            }
        }

        TDB_TIMER_DEF

        TDB_TIMER_START
        if ((ret = store_lexicons(cons)))
            goto done;
        TDB_TIMER_END("encoder/store_lexicons")

        TDB_TIMER_START
        if ((ret = store_uuids(cons)))
            goto done;
        TDB_TIMER_END("encoder/store_uuids")

        TDB_TIMER_START
        if ((ret = store_version(cons)))
            goto done;
        TDB_TIMER_END("encoder/store_version")

        TDB_TIMER_START
        if ((ret = tdb_encode(cons, (const tdb_item*)items_mmapped.data)))
            goto done;
        TDB_TIMER_END("encoder/encode")
    }
done:
    if (items_mmapped.ptr)
        munmap(items_mmapped.ptr, items_mmapped.mmap_size);

    if (cons->tempfile[0])
        unlink(cons->tempfile);

    if (!ret){
        #ifdef HAVE_ARCHIVE_H
        if (cons->output_format == TDB_OPT_CONS_OUTPUT_FORMAT_PACKAGE)
            ret = cons_package(cons);
        #endif
    }
    return ret;
}

TDB_EXPORT tdb_error tdb_cons_set_opt(tdb_cons *cons,
                                      tdb_opt_key key,
                                      tdb_opt_value value)
{
    switch (key){
        case TDB_OPT_CONS_OUTPUT_FORMAT:
            switch (value.value){
                #ifdef HAVE_ARCHIVE_H
                case TDB_OPT_CONS_OUTPUT_FORMAT_PACKAGE:
                #endif
                case TDB_OPT_CONS_OUTPUT_FORMAT_DIR:
                    cons->output_format = value.value;
                    return 0;
                default:
                    return TDB_ERR_INVALID_OPTION_VALUE;
            }
        case TDB_OPT_CONS_NO_BIGRAMS:
            cons->no_bigrams = !(!(value.value));
            return 0;
        default:
            return TDB_ERR_UNKNOWN_OPTION;
    }
}

TDB_EXPORT tdb_error tdb_cons_get_opt(tdb_cons *cons,
                                      tdb_opt_key key,
                                      tdb_opt_value *value)
{
    switch (key){
        case TDB_OPT_CONS_OUTPUT_FORMAT:
            value->value = cons->output_format;
            return 0;
        case TDB_OPT_CONS_NO_BIGRAMS:
            value->value = cons->no_bigrams;
            return 0;
        default:
            return TDB_ERR_UNKNOWN_OPTION;
    }
}

/*
helped functions used by tdb_cons_append_many
*/

struct uuid_node{
    uintptr_t uuid;
    __uint128_t key;
    size_t pos;
    const tdb *db;
    uint64_t trail_id;
    uint64_t num_trails;
    tdb_cursor *cursor;
};

/* pqueue callback functions */

static int cmp_pri(pqueue_pri_t a, pqueue_pri_t b)
{
    __uint128_t key_a, key_b;
    const void *ptr_a = (const void*)a;
    const void *ptr_b = (const void*)b;
    memcpy(&key_a, ptr_a, 16);
    memcpy(&key_b, ptr_b, 16);
    return key_a > key_b;
}

static pqueue_pri_t get_pri(void *a)
{
	return (pqueue_pri_t)((struct uuid_node*)a)->uuid;
}

static void set_pri(void *a, pqueue_pri_t other_pri)
{
	((struct uuid_node*)a)->uuid = (uintptr_t)other_pri;
}

static size_t get_pos(void *a)
{
	return ((struct uuid_node*)a)->pos;
}

static void set_pos(void *a, size_t pos)
{
    ((struct uuid_node*)a)->pos = pos;
}

static inline void insert_node(pqueue_t *queue, struct uuid_node *node)
{
    const void *uuid = tdb_get_uuid(node->db, node->trail_id);
    node->uuid = (uintptr_t)uuid;
    memcpy(&node->key, uuid, 16);
    pqueue_insert(queue, node);
}

TDB_EXPORT tdb_error tdb_cons_append_many(tdb_cons *cons,
                                          const tdb **dbs,
                                          uint32_t num_dbs)
{
    /* priority queue */
    pqueue_t *queue = NULL;
    /* elements of the queue */
    struct uuid_node *trails = NULL;
    /* next element to be processed */
    struct uuid_node *node = NULL;

    tdb_cursor **cursors = NULL;
    tdb_multi_cursor *mcursor = NULL;

    const char **values = NULL;
    uint64_t *lengths = NULL;

    tdb_multi_event *events = NULL;

    uint64_t i, j, n;
    uint64_t num_fields = cons->num_ofields + 1;
    tdb_error ret = TDB_ERR_NOMEM;

    /* TODO remove the requirement that fields have to match */
    for (i = 0; i < num_dbs; i++){
        tdb_field field;
        if (num_fields != dbs[i]->num_fields)
            return TDB_ERR_APPEND_FIELDS_MISMATCH;

        for (field = 0; field < cons->num_ofields; field++)
            if (strcmp(cons->ofield_names[field],
                       tdb_get_field_name(dbs[i], field + 1))){
                return TDB_ERR_APPEND_FIELDS_MISMATCH;
            }
    }

    /* invalidate cached UUID ptr */
    cons->uuid_ptr = NULL;

    if (!(values = malloc(num_fields * sizeof(char*))))
        goto done;

    if (!(lengths = malloc(num_fields * sizeof(uint64_t))))
        goto done;

    if (!(trails = calloc(num_dbs, sizeof(struct uuid_node))))
        goto done;

    if (!(cursors = malloc(num_dbs * sizeof(tdb_cursor*))))
        goto done;

    if (!(events = malloc(CONS_APPEND_MANY_NUM_EVENTS
                          * sizeof(tdb_multi_event))))
        goto done;

    if (!(queue = pqueue_init(num_dbs,
                              cmp_pri,
                              get_pri,
                              set_pri,
                              get_pos,
                              set_pos)))
        goto done;

    for (i = 0, j = 0; i < num_dbs; i++){
        if ((trails[i].num_trails = tdb_num_trails(dbs[i]))){
            trails[i].db = dbs[i];
            trails[i].trail_id = 0;
            trails[i].cursor = cursors[j++] = tdb_cursor_new(dbs[i]);
            insert_node(queue, &trails[i]);
        }
    }

    if (!(mcursor = tdb_multi_cursor_new(cursors, j)))
        goto done;

    while ((node = (struct uuid_node*)pqueue_pop(queue))){
        const uint8_t *uuid = (const uint8_t*)node->uuid;
        __uint128_t key = node->key;

        if ((ret = tdb_get_trail(node->cursor, node->trail_id)))
            goto done;
        if (++node->trail_id < node->num_trails)
            insert_node(queue, node);

        while (1){
            node = (struct uuid_node*)pqueue_peek(queue);
            if (!(node && node->key == key))
                break;
            node = (struct uuid_node*)pqueue_pop(queue);

            if ((ret = tdb_get_trail(node->cursor, node->trail_id)))
                goto done;
            if (++node->trail_id < node->num_trails)
                insert_node(queue, node);
        }

        tdb_multi_cursor_reset(mcursor);

        while ((n = tdb_multi_cursor_next_batch(mcursor,
                                                events,
                                                CONS_APPEND_MANY_NUM_EVENTS))){
            for (i = 0; i < n; i++){
                if ((ret = append_event_str(cons,
                                            events[i].db,
                                            uuid,
                                            events[i].event,
                                            values,
                                            lengths,
                                            num_fields)))
                    goto done;
            }
        }
    }

    ret = 0;
done:
    if (queue)
        pqueue_free(queue);
    if (trails){
        for (i = 0; i < num_dbs; i++)
            tdb_cursor_free(cursors[i]);
        free(trails);
    }
    tdb_multi_cursor_free(mcursor);
    free(values);
    free(lengths);
    free(cursors);
    free(events);
    return ret;
}
