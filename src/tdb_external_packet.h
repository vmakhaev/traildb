
#ifndef __TDB_EXTERNAL_PACKET_H__
#define __TDB_EXTERNAL_PACKET_H__

#include <stdint.h>

#define TDB_EXT_LATEST_VERSION "V000"

#define TDB_EXT_MAX_PATH_LEN 1024

#define TDB_EXT_REQUEST_HEAD_SIZE 28
struct tdb_ext_request{
    char type[4];
    uint64_t offset;
    uint64_t min_size;
    uint32_t root_len;
    uint32_t fname_len;

    char *root;
    char *fname;
} __attribute__((packed));

#define TDB_EXT_RESPONSE_HEAD_SIZE 24
struct tdb_ext_response{
    char type[4];
    uint64_t offset;
    uint64_t max_size;
    uint32_t path_len;

    char path[TDB_EXT_MAX_PATH_LEN + 1];
} __attribute__((packed));

#endif /* __TDB_EXTERNAL_PACKET_H__ */
