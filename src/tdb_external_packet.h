
#ifndef __TDB_EXTERNAL_PACKET_H__
#define __TDB_EXTERNAL_PACKET_H__

#include <stdint.h>

#define TDB_EXT_LATEST_VERSION "V000"

#define TDB_EXT_MAX_PATH_LEN 1024

#define TDB_EXT_PACKET_HEAD_SIZE 24
struct tdb_ext_packet{
    char type[4];
    uint64_t offset;
    uint64_t size;
    uint32_t path_len;

    char path[TDB_EXT_MAX_PATH_LEN + 1];
} __attribute__((packed));

#endif /* __TDB_EXTERNAL_PACKET_H__ */
