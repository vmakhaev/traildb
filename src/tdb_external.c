#define _DEFAULT_SOURCE /* getline() */
#define _GNU_SOURCE

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include <linux/userfaultfd.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <asm/unistd.h>
#include <sys/ioctl.h>
#include <poll.h>
#include <errno.h>

#include "tdb_package.h"
#include "tdb_external.h"

#undef JUDYERROR
#define JUDYERROR(CallerFile, CallerLine, JudyFunc, JudyErrno, JudyErrID) \
{                                                                         \
   if ((JudyErrno) == JU_ERRNO_NOMEM)                                     \
       goto out_of_memory;                                                \
}

#include <Judy.h>

static void warn(char *fmt, ...)
{
    va_list aptr;
    va_start(aptr, fmt);
    vfprintf(stderr, fmt, aptr);
    va_end(aptr);
}

static void die(char *fmt, ...)
{
    va_list aptr;
    va_start(aptr, fmt);
    vfprintf(stderr, fmt, aptr);
    va_end(aptr);
    abort();
}

static void free_cache(struct tdb_file *region)
{
    if (region->cached_data)
        if (munmap((char*)region->cached_data, region->cached_size))
            1; /* FIXME - this just doesn't like package_mmap */
            //die("tdb_external: munmap(cached_data failed (errno %d)", errno);
}

static void populate_cache(tdb *db, struct tdb_file *region, uint64_t requested_page)
{
    struct tdb_file src_region;
    int ret;

    free_cache(region);
    if ((ret = package_mmap(region->fname, NULL, &src_region, db)))
        die("package_mmap failed %d\n", ret);

    region->cached_data = src_region.data;
    region->cached_first_page = 0;
    region->cached_size = src_region.size;

    fprintf(stderr, "populate cache for %s\n", region->fname);
}

static void handle_pagefault(tdb *db, uint64_t addr)
{
    struct tdb_file *region;
    struct uffdio_copy copy;
    const uint64_t PAGESIZE = (uint64_t)getpagesize();
    uint64_t requested_page, offs;
    Word_t region_start = addr;
    Word_t *ptr;

    JLL(ptr, db->external_regions, region_start);
    if (ptr)
        region = (struct tdb_file*)*ptr;
    else
        die("tdb_external: unknown external_region at %lx\n", addr);

    requested_page = (addr - region_start) / PAGESIZE;
    if (requested_page < region->cached_first_page ||
        (requested_page + 1) * PAGESIZE >
         region->cached_first_page * PAGESIZE + region->cached_size)
        populate_cache(db, region, requested_page);

    offs = (requested_page - region->cached_first_page) * PAGESIZE;
    if (region->cached_size - offs < PAGESIZE){
        memset(db->external_page_buffer, 0, PAGESIZE);
        memcpy(db->external_page_buffer,
               region->cached_data + offs,
               region->cached_size - offs);
        copy.src = (uint64_t)db->external_page_buffer;
    }else
        copy.src = (uint64_t)(region->cached_data + offs);

    copy.dst = region_start + requested_page * PAGESIZE;
    copy.len = PAGESIZE;
    copy.mode = 0;

    if (ioctl(db->external_uffd, UFFDIO_COPY, &copy) == -1)
        die("tdb_external: "
            "UFFDIO_COPY failed (errno %d): file %s, requested page %lu",
            errno, region->fname, requested_page);
    return;
out_of_memory:
    die("tdb_external: assert failed - JLL out of memory\n");
}

static void *pagefault_thread(void *arg)
{
    tdb *db = (tdb*)arg;
    struct pollfd pollfd[1];

    pollfd[0].fd = db->external_uffd;
    pollfd[0].events = POLLIN;

    while (1){
        struct uffd_msg msg;
        int pollres = poll(pollfd, 1, 10000);
        ssize_t len;

        switch (pollres) {
            case 0:
                continue;
            case 1:
                break;
            default:
                warn("tdb_external: unexpected poll result (%d)\n", pollres);
                continue;
        }
        if (pollfd[0].revents & POLLNVAL)
            break; /* closed */

        if (pollfd[0].revents & POLLERR){
            warn("tdb_external: unexpected POLLERR\n");
            continue;
        }
        if ((len = read(db->external_uffd, &msg, sizeof(msg))) == -1){
            if (errno == EAGAIN)
                continue;
            else{
                warn("tdb_external: read failed (%d)\n", errno);
                continue;
            }
        }
        if (len != sizeof(msg)) {
            warn("tdb_external: invalid message size (%d)\n", len);
            continue;
        }
        if (msg.event & UFFD_EVENT_PAGEFAULT)
            handle_pagefault(db, msg.arg.pagefault.address);
    }
    printf("EXIT\n");
    return NULL;
}

tdb_error open_external(tdb *db, const char *root)
{
    const uint64_t PAGESIZE = (uint64_t)getpagesize();
    struct uffdio_api uffdio_api;
    tdb_error err;

    if ((err = open_package(db, root)))
        return err;

    if (!(db->external_page_buffer = malloc(PAGESIZE)))
        return TDB_ERR_NOMEM;

    fprintf(stderr, "cp 0\n");
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wconversion"
    db->external_uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
#pragma GCC diagnostic pop
    if (db->external_uffd == -1)
        return TDB_ERR_IO_READ; /* FIXME */
    fprintf(stderr, "cp 1\n");
    uffdio_api.api = UFFD_API;
    uffdio_api.features = 0;
    if (ioctl(db->external_uffd, UFFDIO_API, &uffdio_api) == -1)
        return TDB_ERR_IO_READ; /* FIXME */
    fprintf(stderr, "cp 2\n");

    if (uffdio_api.api != UFFD_API)
        return TDB_ERR_IO_READ; /* FIXME */
    fprintf(stderr, "cp 3\n");

    if (pthread_create(&db->external_pagefault_thread,
                       NULL,
                       pagefault_thread,
                       db))
        return TDB_ERR_IO_READ; /* FIXME */
    fprintf(stderr, "cp 4\n");

    return 0;
}

void free_external(tdb *db)
{
    /*
    TODO check if this is necessary
    unregister all
    if (ioctl(uffd, UFFDIO_UNREGISTER, &uffdio_register.range)) {
        fprintf(stderr, "ioctl unregister failure\n");
        return 1;
    }
    */
    Word_t tmp = 0;
    Word_t *ptr;
    int ret;

    JLF(ptr, db->external_regions, tmp);
    while (ptr){
        struct uffdio_range range;
        struct tdb_file *region = (struct tdb_file*)*ptr;

        free_cache(region);
        free((char*)region->fname);

        range.start = (uint64_t)region->ptr;
        range.len = region->mmap_size;
        if (ioctl(db->external_uffd, UFFDIO_UNREGISTER, &range) == -1){
            perror("fuu\n");
            die("tdb_external: UFFDIO_UNREGISTER failed %d\n", errno);
        }
        JLN(ptr, db->external_regions, tmp);
    }

    free(db->external_page_buffer);
    if (db->external_uffd)
        close(db->external_uffd);
    if (db->external_pagefault_thread)
        if ((ret = pthread_join(db->external_pagefault_thread, NULL)))
            die("tdb_external: pthread_join failed (errno %d)\n", ret);
    free_package(db);
    JLFA(tmp, db->external_regions);
out_of_memory:
    return;
}

FILE *external_fopen(const char *fname, const char *root, const tdb *db)
{
    return package_fopen(fname, root, db);
}

int external_fclose(FILE *f)
{
    return package_fclose(f);
}

int external_mmap(const char *fname,
                  const char *root,
                  struct tdb_file *dst,
                  const tdb *db)
{
    struct uffdio_register uffdio_register;
    Word_t *ptr;
    uint64_t offset, shift;
    const uint64_t PAGESIZE = (uint64_t)getpagesize();

    if (package_toc_get(db, fname, &offset, &dst->size))
        return -1;

    if (!(dst->fname = strdup(fname)))
        return -1;

    dst->mmap_size = dst->size + (PAGESIZE - (dst->size & (PAGESIZE - 1)));
    dst->data = dst->ptr = mmap(NULL,
                                dst->mmap_size,
                                PROT_READ,
                                MAP_PRIVATE | MAP_ANONYMOUS,
                                -1,
                                0);

    if (dst->ptr == MAP_FAILED)
        return -1;

    /* register the pages in the region for userfault */
    uffdio_register.range.start = (unsigned long)dst->ptr;
    uffdio_register.range.len = dst->mmap_size;
    uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING;

    if (ioctl(db->external_uffd, UFFDIO_REGISTER, &uffdio_register) == -1)
        goto err;

    if ((uffdio_register.ioctls & UFFD_API_RANGE_IOCTLS) !=
            UFFD_API_RANGE_IOCTLS)
        goto err;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
    /* store range.start -> fname mapping */
    JLI(ptr, ((tdb*)db)->external_regions, (Word_t)dst->ptr);
    *ptr = (Word_t)dst;
#pragma GCC diagnostic pop
    return 0;

out_of_memory:
err:
    munmap(dst->ptr, dst->mmap_size);
    return -1;
}

