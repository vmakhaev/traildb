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

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/tcp.h>

#include "tdb_package.h"
#include "tdb_external.h"
#include "tdb_external_packet.h"

#undef JUDYERROR
#define JUDYERROR(CallerFile, CallerLine, JudyFunc, JudyErrno, JudyErrID) \
{                                                                         \
   if ((JudyErrno) == JU_ERRNO_NOMEM)                                     \
       goto out_of_memory;                                                \
}

#include <Judy.h>

#define DEFAULT_HOST "localhost"
#define DEFAULT_PORT "9009"
#define DEFAULT_TIMEOUT 0

#define MESSAGE_TIMEOUT 10 /* seconds */

/* assume that most package TOCs fit in this space */
#define INITIAL_HEAD_SIZE 65000
/* if the TOC is larger, how much larger we should try */
#define HEAD_SIZE_INCREMENT 1000000
/* we believe that no sane TOC can be larger than this */
#define MAX_HEAD_SIZE 10000000

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
                warn("tdb_external: unexpected poll result (%d)\n", pollres);
                continue;
        }
        if (pollfd[0].revents & POLLNVAL || pollfd[0].revents & POLLRDHUP){
            break; /* closed */
        }

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
    return NULL;
}

static tdb_error try_connect(tdb *db)
{
    struct addrinfo hints, *res;
    int ret, sock;

    fd_set fds;
    struct timespec tv;

    memset(&hints, 0, sizeof(hints));
    /* force ipv4 for now */
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if ((ret = getaddrinfo(db->external_host,
                           db->external_port,
                           &hints,
                           &res))){
        warn("tdb_external: getaddrinfo failed (%s)\n", gai_strerror(ret));
        return TDB_ERR_EXT_CONNECT_FAILED;
    }
    if ((sock = socket(res->ai_family,
                       res->ai_socktype | SOCK_NONBLOCK,
                       res->ai_protocol)) == -1){
        warn("tdb_external: creating a socket failed (%s)\n", strerror(errno));
        return TDB_ERR_EXT_CONNECT_FAILED;
    }
    if ((ret = connect(sock, res->ai_addr, res->ai_addrlen)) &&
         errno != EINPROGRESS){
        warn("tdb_external: connect failed (%s)\n", strerror(errno));
        return TDB_ERR_EXT_CONNECT_FAILED;
    }
    ret = 1;
    if (setsockopt(sock, SOL_TCP, TCP_NODELAY, &ret, sizeof(ret))){
        warn("tdb_external: setting TCP_NODELAY failed (%s)\n",
             strerror(errno));
        return TDB_ERR_EXT_CONNECT_FAILED;
    }

    FD_ZERO(&fds);
    FD_SET(sock, &fds);

    if (db->external_timeout > 0){
        tv.tv_sec = db->external_timeout / 1000;
        tv.tv_nsec = (db->external_timeout % 1000) * 1000;
        ret = pselect(sock + 1, NULL, &fds, NULL, &tv, NULL);
    }else{
        while (1){
            tv.tv_sec = 10;
            tv.tv_nsec = 0;
            if ((ret = pselect(sock + 1, NULL, &fds, NULL, &tv, NULL)))
                break;
            else
                warn("tdb_external: still trying to connect to %s:%s\n",
                     db->external_host,
                     db->external_port);
        }
    }
    switch (ret){
        case -1:
            warn("tdb_external: select failed (%s)\n", strerror(errno));
            return TDB_ERR_EXT_CONNECT_FAILED;
        case 0:
            return TDB_ERR_EXT_CONNECT_TIMEOUT;
        case 1:
            db->external_conn = sock;
            return 0;
    }
}

static tdb_error receive_bytes(int fd, char *ptr, uint64_t size)
{
    uint64_t i = 0;
    fd_set fds;
    struct timespec tv;

    FD_ZERO(&fds);
    FD_SET(fd, &fds);

    while (i < size){
        ssize_t n;
        tv.tv_sec = MESSAGE_TIMEOUT;
        tv.tv_nsec = 0;

        if (pselect(fd + 1, &fds, NULL, NULL, &tv, NULL) != 1){
            shutdown(fd, SHUT_RDWR);
            close(fd);
            return TDB_ERR_EXT_INVALID_RESPONSE;
        }
        n = recv(fd, &ptr[i], size - i, 0);
        if (n < 1){
            shutdown(fd, SHUT_RDWR);
            close(fd);
            return TDB_ERR_EXT_INVALID_RESPONSE;
        }
        i += (uint64_t)n;
    }
    return 0;
}

static tdb_error receive_response(tdb *db, struct tdb_ext_response *resp)
{
    char *ptr = (char*)resp;
    tdb_error err;

    memset(resp->path, 0, sizeof(resp->path));

    if ((err = receive_bytes(db->external_conn,
                             ptr,
                             TDB_EXT_RESPONSE_HEAD_SIZE)))
        return err;

    if (memcmp(resp->type, "OKOK", 4)){
        shutdown(db->external_conn, SHUT_RDWR);
        close(db->external_conn);
        return TDB_ERR_EXT_SERVER_FAILURE;
    }
    return receive_bytes(db->external_conn,
                         &ptr[TDB_EXT_RESPONSE_HEAD_SIZE],
                         resp->path_len);
}

static tdb_error ext_request(tdb *db,
                             const char *type,
                             uint64_t offset,
                             uint64_t min_size,
                             const char *root,
                             const char *fname,
                             struct tdb_ext_response *resp)
{
    char buffer[TDB_EXT_MAX_PATH_LEN * 2 + TDB_EXT_REQUEST_HEAD_SIZE];
    struct tdb_ext_request req = {.offset = offset, .min_size = min_size};
    uint64_t size = 0;
    uint64_t i = 0;
    uint64_t num_reconn = 0;
    tdb_error err;

    memcpy(req.type, type, 4);
    req.root_len = (uint32_t)strlen(root);
    req.fname_len = (uint32_t)strlen(fname);

    if (!(req.root_len < TDB_EXT_MAX_PATH_LEN &&
          req.fname_len < TDB_EXT_MAX_PATH_LEN))
        return TDB_ERR_EXT_PATH_TOO_LONG;

    memcpy(buffer, &req, TDB_EXT_REQUEST_HEAD_SIZE);
    size += TDB_EXT_REQUEST_HEAD_SIZE;
    memcpy(&buffer[size], root, req.root_len);
    size += req.root_len;
    memcpy(&buffer[size], fname, req.fname_len);

    while (i < size){
        ssize_t n;
        fd_set fds;
        struct timespec tv;

        FD_ZERO(&fds);
        FD_SET(db->external_conn, &fds);

        tv.tv_sec = MESSAGE_TIMEOUT;
        tv.tv_nsec = 0;

        if (pselect(db->external_conn + 1, NULL, &fds, NULL, &tv, NULL) != 1){
            shutdown(db->external_conn, SHUT_RDWR);
            close(db->external_conn);
            if ((err = try_connect(db)))
                return err;
        }
        n = send(db->external_conn, &buffer[i], size - i, 0);
        if (n < 1){
            shutdown(db->external_conn, SHUT_RDWR);
            close(db->external_conn);
        }else
            i += (uint64_t)n;
    }
    return receive_response(db, resp);
}

static tdb_error ext_request_simple(tdb *db, const char *type)
{
    struct tdb_ext_response resp;
    return ext_request(db, type, 0, 0, "", "", &resp);
}

static int is_invalid_header(const struct tdb_ext_response *resp)
{
    FILE *f;
    tdb_error ret = TDB_ERR_IO_TRUNCATE;
    char *p = NULL;
    uint64_t offset;

    /* NOTE: if the request offset=0 the return offset must be 0 too */
    if (resp->offset)
        return TDB_ERR_EXT_SERVER_FAILURE;
    if (resp->max_size < TOC_FILE_OFFSET)
        return TDB_ERR_EXT_INVALID_HEADER;

    /*
    We need to read the whole TOC file. The file ends with a double
    newline. Once we find it, we know that we have got the full file.
    */
    TDB_OPEN(f, resp->path, "r");
    p = mmap(NULL, resp->max_size, PROT_READ, MAP_SHARED, fileno(f), 0);
    fclose(f);
    if (p == MAP_FAILED)
        return TDB_ERR_IO_READ;

    for (offset = TOC_FILE_OFFSET; offset < resp->max_size - 1; offset++){
        if (p[offset] == '\n' && p[offset + 1] == '\n'){
            ret = 0;
            break;
        }
    }
done:
    if (p)
        munmap(p, resp->max_size);
    return ret;
}

static tdb_error open_package_header(tdb *db, const char *root)
{
    struct tdb_ext_response resp;
    tdb_error err;
    uint64_t head_size = INITIAL_HEAD_SIZE;

    while (1){
        if ((err = ext_request(db, "READ", 0, head_size, root, "", &resp)))
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
    return open_package(db, resp.path);
}

void external_init(tdb *db)
{
    tdb_opt_value val;
    val.ptr = DEFAULT_HOST;
    tdb_set_opt(db, TDB_OPT_EXTERNAL_HOST, val);
    val.ptr = DEFAULT_PORT;
    tdb_set_opt(db, TDB_OPT_EXTERNAL_PORT, val);
    val.value = (uint64_t)DEFAULT_TIMEOUT;
    tdb_set_opt(db, TDB_OPT_EXTERNAL_TIMEOUT, val);
}

tdb_error open_external(tdb *db, const char *root)
{
    const uint64_t PAGESIZE = (uint64_t)getpagesize();
    struct uffdio_api uffdio_api;
    tdb_error err;

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

    /* handshake with the external server */
    if ((err = try_connect(db)))
        return err;
    if ((err = ext_request_simple(db, TDB_EXT_LATEST_VERSION)))
        return err;
    /* fetch the package header and parse the TOC */
    if ((err = open_package_header(db, root)))
        return err;

    if (pthread_create(&db->external_pagefault_thread,
                       NULL,
                       pagefault_thread,
                       db))
        return TDB_ERR_EXT_FAILED;

    return 0;
}

void free_external(tdb *db)
{
    Word_t tmp = 0;
    Word_t *ptr;
    int ret;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
    free((char*)db->external_host);
    free((char*)db->external_port);
#pragma GCC diagnostic pop

    if (db->external_conn){
        ext_request_simple(db, "EXIT");
        close(db->external_conn);
    }

    JLF(ptr, db->external_regions, tmp);
    while (ptr){
        struct uffdio_range range;
        struct tdb_file *region = (struct tdb_file*)*ptr;

        free_cache(region);
        free((char*)region->fname);

        range.start = (uint64_t)region->ptr;
        range.len = region->mmap_size;
        if (ioctl(db->external_uffd, UFFDIO_UNREGISTER, &range) == -1)
            die("tdb_external: UFFDIO_UNREGISTER failed %d\n", errno);

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

