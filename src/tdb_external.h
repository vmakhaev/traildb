
#ifndef __TDB_EXTENRAL_H__
#define __TDB_EXTERNAL_H__

tdb_error open_external(tdb *db, const char *root);

void free_external(tdb *db);

FILE *external_fopen(const char *fname, const char *root, const tdb *db);

int external_fclose(FILE *f);

int external_mmap(const char *fname,
                  const char *root,
                  struct tdb_file *dst,
                  const tdb *db);

#endif /* __TDB_EXTERNAL_H__ */
