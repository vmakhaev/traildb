#define _DEFAULT_SOURCE /* getline() */

#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include "tdb_package.h"
#include "tdb_external.h"
#include "tdb_external_priv.h"

#define DEFAULT_HOST "192.168.1.30"
#define DEFAULT_PORT "9009"
#define DEFAULT_CONNECT_TIMEOUT 60000
#define DEFAULT_RETRY_TIMEOUT 0

/* assume that most package TOCs fit in this space */
#define INITIAL_HEAD_SIZE 65000
/* if the TOC is larger, how much larger we should try */
#define HEAD_SIZE_INCREMENT 1000000
/* we believe that no sane TOC can be larger than this */
#define MAX_HEAD_SIZE 10000000

void ext_warn(char *fmt, ...)
{
    va_list aptr;
    va_start(aptr, fmt);
    vfprintf(stderr, fmt, aptr);
    va_end(aptr);
}

void ext_die(char *fmt, ...)
{
    va_list aptr;
    va_start(aptr, fmt);
    vfprintf(stderr, fmt, aptr);
    va_end(aptr);
    abort();
}

static int is_invalid_header(const struct tdb_ext_packet *resp)
{
    FILE *f;
    tdb_error ret = TDB_ERR_IO_TRUNCATE;
    char *p = NULL;
    uint64_t offset;

    /* NOTE: if the request offset=0 the return offset must be 0 too */
    if (resp->offset)
        return TDB_ERR_EXT_SERVER_FAILURE;
    if (resp->size < TOC_FILE_OFFSET)
        return TDB_ERR_EXT_INVALID_HEADER;

    /*
    We need to read the whole TOC file. The file ends with a double
    newline. Once we find it, we know that we have got the full file.
    */
    TDB_OPEN(f, resp->path, "r");
    p = mmap(NULL, resp->size, PROT_READ, MAP_SHARED, fileno(f), 0);
    fclose(f);
    if (p == MAP_FAILED)
        return TDB_ERR_IO_READ;

    for (offset = TOC_FILE_OFFSET; offset < resp->size - 1; offset++){
        if (p[offset] == '\n' && p[offset + 1] == '\n'){
            ret = 0;
            break;
        }
    }
done:
    if (p)
        munmap(p, resp->size);
    return ret;
}

static tdb_error open_package_header(tdb *db, const char *root)
{
    struct tdb_ext_packet resp;
    tdb_error err;
    uint64_t head_size = INITIAL_HEAD_SIZE;

    /*
    We don't know the exact size of the package TOC, so we
    start by requesting a chunk of data based on an educated guess,
    INITIAL_HEAD_SIZE. If the full TOC isn't contained in this chunk,
    we keep requesting a larger chunk, incremented by HEAD_SIZE_INCREMENT,
    until we have found the full TOC.
    */
    while (1){
        if ((err = ext_comm_request(db, "READ", 0, head_size, &resp)))
            return err;

        head_size += HEAD_SIZE_INCREMENT;
        if (head_size > MAX_HEAD_SIZE)
            return TDB_ERR_EXT_INVALID_HEADER;

        err = is_invalid_header(&resp);
        if (err == TDB_ERR_IO_TRUNCATE)
            continue;
        else if (err)
            return err;
        else
            break;
    }
    /*
    Now we know that we have found a chunk of data that contains the full
    package header. We can proceed with opening it as usual.
    */
    return open_package(db, resp.path);
}

int is_external_path(const char *path)
{
    char *p = strstr(path, "://");
    return p && (p - path < 6);
}

void external_init(tdb *db)
{
    tdb_opt_value val;
    val.ptr = DEFAULT_HOST;
    tdb_set_opt(db, TDB_OPT_EXTERNAL_HOST, val);
    val.ptr = DEFAULT_PORT;
    tdb_set_opt(db, TDB_OPT_EXTERNAL_PORT, val);
    val.value = (uint64_t)DEFAULT_CONNECT_TIMEOUT;
    tdb_set_opt(db, TDB_OPT_EXTERNAL_CONNECT_TIMEOUT, val);
    val.value = (uint64_t)DEFAULT_RETRY_TIMEOUT;
    tdb_set_opt(db, TDB_OPT_EXTERNAL_RETRY_TIMEOUT, val);
}

tdb_error open_external(tdb *db, const char *root)
{
    tdb_error err;
    struct tdb_ext_packet resp;

    if (!(db->root = strdup(root)))
        return TDB_ERR_NOMEM;

    /* initialize page fault handler */
    if ((err = ext_fault_init(db)))
        return err;
    /* open connection to the external server */
    if ((err = ext_comm_connect(db)))
        return err;
    /*
    handshake with the external server. Possible replies:
    - TDB_ERR_EXT_UNSUPPORTED_PROTOCOL - scheme not supported by the server
    - TDB_ERR_EXT_NOT_FOUND - object was not found
    */
    if ((err = ext_comm_request(db, TDB_EXT_LATEST_VERSION, 0, 0, &resp)))
        return err;
    /* object found - fetch the package header and parse the TOC */
    if ((err = open_package_header(db, root)))
        return err;

    return 0;
}

void free_external(tdb *db)
{
    ext_fault_free(db);
    ext_comm_free(db);
    free_package(db);
#pragma GCC diagnostic push
    free((char*)db->root);
#pragma GCC diagnostic ignored "-Wcast-qual"
#pragma GCC diagnostic pop
}

FILE *external_fopen(const char *fname, const char *root, const tdb *db)
{
    struct tdb_ext_packet resp;
    uint64_t offset, size;
    FILE *f;

    if (package_toc_get(db, fname, &offset, &size))
        return NULL;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
    if (ext_comm_request((tdb*)db, "READ", offset, size, &resp))
        return NULL;
#pragma GCC diagnostic pop
    if (!(f = fopen(resp.path, "r")))
        return NULL;
    if (fseek(f, (off_t)resp.offset, SEEK_SET) == -1)
        return NULL;
    return f;
}

int external_fclose(FILE *f)
{
    return fclose(f);
}

int external_mmap(const char *fname,
                  const char *root,
                  struct tdb_file *dst,
                  const tdb *db)
{
    /*
    lookup the offset and the size of the region requested
    in the package header
    */
    if (package_toc_get(db, fname, &dst->src_offset, &dst->size))
        return -1;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
    return ext_fault_mmap((tdb*)db, dst);
#pragma GCC diagnostic pop
}

