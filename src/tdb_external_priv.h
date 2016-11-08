
#ifndef __TDB_EXTERNAL_PRIV_H__
#define __TDB_EXTERNAL_PRIV_H__

#include <stdarg.h>
#include <stdint.h>

#include "traildb.h"
#include "tdb_package.h"
#include "tdb_external_packet.h"

/* general */

void ext_warn(char *fmt, ...);

void ext_die(char *fmt, ...);

/* comm */

tdb_error ext_comm_connect(tdb *db);

tdb_error ext_comm_request(tdb *db,
                           const char *type,
                           uint64_t offset,
                           uint64_t min_size,
                           const char *root,
                           const char *fname,
                           struct tdb_ext_response *resp);

tdb_error ext_comm_request_simple(tdb *db, const char *type);

void ext_comm_free(tdb *db);

/* pagefault */

tdb_error ext_fault_init(tdb *db);

int ext_fault_mmap(tdb *db, struct tdb_file *dst);

void ext_fault_free(tdb *db);

#endif /* __TDB_EXTERNAL_PRIV_H__ */
