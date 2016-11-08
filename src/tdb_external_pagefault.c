
#define _DEFAULT_SOURCE
#define _GNU_SOURCE /* POLLRDHUP */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

#include <sys/mman.h>
#include <sys/stat.h>

#include <linux/userfaultfd.h>
#include <sys/syscall.h>
#include <asm/unistd.h>
#include <sys/ioctl.h>
#include <poll.h>

#include "tdb_external_priv.h"

#undef JUDYERROR
#define JUDYERROR(CallerFile, CallerLine, JudyFunc, JudyErrno, JudyErrID) \
{                                                                         \
   if ((JudyErrno) == JU_ERRNO_NOMEM)                                     \
       goto out_of_memory;                                                \
}

#include <Judy.h>

#define MAX_EXP_BACKOFF_POWER 9 /* wait at most 2^9 ~= 8mins between retries */

static uint32_t PAGESIZE;

static void free_cache(struct tdb_file *region)
{
    if (region->cached_ptr){
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
        int r;
        if ((r = munmap((char*)region->cached_ptr, region->cached_mmap_size)))
            ext_die("tdb_external: munmap(cached_data) failed: %s\n",
                    strerror(errno));
#pragma GCC diagnostic pop
        region->cached_ptr = NULL;
    }
}

static uint64_t now(void)
{
    struct timespec tstamp;
    if (clock_gettime(CLOCK_MONOTONIC_COARSE, &tstamp))
        ext_die("clock_gettime failed\n");
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"
    return tstamp.tv_sec * 1000LU + tstamp.tv_nsec / 1000000LU;
#pragma GCC diagnostic pop
}

/*
Interestingly this function must not fail. There's nothing clever we can do
if we can't handle a page fault. We could segfault or SIGBUS.
*/
static void request_external_page(tdb *db,
                                  uint64_t offset,
                                  struct tdb_ext_packet *resp)
{
    tdb_error err;
    uint64_t start = now();
    uint64_t num_retries = 0;

    while ((err = ext_comm_request(db, "READ", offset, PAGESIZE, resp))){
        if (db->external_retry_timeout > 0 &&
            now() - start > db->external_retry_timeout)
            ext_die("FATAL! "
                    "Requesting a page for %s at %lu timed out (error %s)!\n",
                    db->root,
                    offset,
                    tdb_error_str(err));

        /* exponential backoff */
        if (num_retries < MAX_EXP_BACKOFF_POWER)
            ++num_retries;
        sleep(1U << num_retries);
    }
}

static void populate_cache(tdb *db, struct tdb_file *region, uint64_t requested_page)
{
    struct tdb_ext_packet resp;
    uint64_t ext_offset = region->src_offset + requested_page * PAGESIZE;
    uint64_t shift;
    int fd;

    free_cache(region);
    request_external_page(db, ext_offset, &resp);

    if ((fd = open(resp.path, O_RDONLY)) == -1)
        ext_die("Could not open a block at %s (requested %s at %lu): %s\n",
                resp.path,
                db->root,
                ext_offset,
                strerror(errno));

    /*
    memory map the section of the block that contains the page requested
    and pages after that up to resp->max_size as a lookahead cache
    */
    shift = resp.offset & ((uint64_t)(PAGESIZE - 1));
    resp.offset -= shift;

    region->cached_mmap_size = resp.size + shift;
    region->cached_ptr = mmap(NULL,
                              region->cached_mmap_size,
                              PROT_READ,
                              MAP_SHARED,
                              fd,
                              (off_t)resp.offset);

    if (region->cached_ptr == MAP_FAILED)
        ext_die("Could not mmap a block at %s (offset %lu size %lu)\n",
                resp.path,
                resp.offset,
                region->cached_mmap_size);

    region->cached_data = &region->cached_ptr[shift];
    region->cached_first_page = requested_page;
    region->cached_size = resp.size;
    close(fd);
}

static void handle_pagefault(tdb *db, uint64_t addr)
{
    struct tdb_file *region = NULL;
    struct uffdio_copy copy;
    uint64_t requested_page, offs;
    Word_t region_start = addr;
    Word_t *ptr;

    JLL(ptr, db->external_regions, region_start);
    if (ptr)
        region = (struct tdb_file*)*ptr;
    else
        ext_die("tdb_external: unknown external_region at %lx\n", addr);

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
        ext_die("tdb_external: "
                "UFFDIO_COPY failed (errno %d): "
                "offset %lu, requested page %lu\n",
                errno, region->src_offset, requested_page);
    return;
out_of_memory:
    ext_die("tdb_external: assert failed - JLL out of memory\n");
}

static void *pagefault_thread(void *arg)
{
    tdb *db = (tdb*)arg;
    struct pollfd pollfd[1];

    pollfd[0].fd = db->external_uffd;
    pollfd[0].events = POLLIN | POLLRDHUP;

    while (1){
        struct uffd_msg msg;
        /*
        note that we need a short timeout since close() doesn't seem
        to wake up poll but we notice it at the timeout
        */
        int pollres = poll(pollfd, 1, 100);
        ssize_t len;
        switch (pollres) {
            case 0:
                continue;
            case 1:
                break;
            default:
                ext_warn("tdb_external: unexpected poll result (%d)\n",
                         pollres);
                continue;
        }
        if (pollfd[0].revents & POLLNVAL || pollfd[0].revents & POLLRDHUP){
            break; /* closed */
        }

        if (pollfd[0].revents & POLLERR){
            ext_warn("tdb_external: unexpected POLLERR\n");
            continue;
        }
        if ((len = read(db->external_uffd, &msg, sizeof(msg))) == -1){
            if (errno == EAGAIN)
                continue;
            else{
                ext_warn("tdb_external: read failed (%d)\n", errno);
                continue;
            }
        }
        if (len != sizeof(msg)) {
            ext_warn("tdb_external: invalid message size (%d)\n", len);
            continue;
        }
        if (msg.event & UFFD_EVENT_PAGEFAULT)
            handle_pagefault(db, msg.arg.pagefault.address);
    }
    return NULL;
}

int ext_fault_mmap(tdb *db, struct tdb_file *dst)
{
    struct uffdio_register uffdio_register;
    Word_t *ptr;
    uint64_t shift;

    /*
    mmap_size must be a multiple of PAGESIZE since UFFDIO_COPY can
    only copy full pages
    */
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
    /* store range.start -> region mapping */
    JLI(ptr, ((tdb*)db)->external_regions, (Word_t)dst->ptr);
    *ptr = (Word_t)dst;
#pragma GCC diagnostic pop
    return 0;

out_of_memory:
err:
    munmap(dst->ptr, dst->mmap_size);
    return -1;
}

tdb_error ext_fault_init(tdb *db)
{
    struct uffdio_api uffdio_api;
    tdb_error err;

    if (!PAGESIZE)
        PAGESIZE = (uint32_t)getpagesize();

    if (!(db->external_page_buffer = malloc(PAGESIZE)))
        return TDB_ERR_NOMEM;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wconversion"
    db->external_uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
#pragma GCC diagnostic pop
    if (db->external_uffd == -1)
        return TDB_ERR_EXT_FAILED;

    uffdio_api.api = UFFD_API;
    uffdio_api.features = 0;
    if (ioctl(db->external_uffd, UFFDIO_API, &uffdio_api) == -1)
        return TDB_ERR_EXT_FAILED;

    if (uffdio_api.api != UFFD_API)
        return TDB_ERR_EXT_FAILED;

    if (pthread_create(&db->external_pagefault_thread,
                       NULL,
                       pagefault_thread,
                       db))
        return TDB_ERR_EXT_FAILED;

    return 0;
}

void ext_fault_free(tdb *db)
{
    Word_t tmp = 0;
    Word_t *ptr;
    int ret;

    JLF(ptr, db->external_regions, tmp);
    while (ptr){
        struct uffdio_range range;
        struct tdb_file *region = (struct tdb_file*)*ptr;

        free_cache(region);

        range.start = (uint64_t)region->ptr;
        range.len = region->mmap_size;
        if (ioctl(db->external_uffd, UFFDIO_UNREGISTER, &range) == -1)
            ext_die("tdb_external: UFFDIO_UNREGISTER failed %d\n", errno);

        JLN(ptr, db->external_regions, tmp);
    }
    free(db->external_page_buffer);
    if (db->external_uffd)
        close(db->external_uffd);
    if (db->external_pagefault_thread)
        if ((ret = pthread_join(db->external_pagefault_thread, NULL)))
            ext_die("tdb_external: pthread_join failed (errno %d)\n", ret);

    JLFA(tmp, db->external_regions);
out_of_memory:
    return;
}
