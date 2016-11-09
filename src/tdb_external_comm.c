
#define _DEFAULT_SOURCE

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <sys/select.h>
#include <sys/time.h>
#include <time.h>

#include <errno.h>

#include "tdb_external_priv.h"

#define MESSAGE_TIMEOUT 10 /* seconds */

tdb_error ext_comm_connect(tdb *db)
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
        ext_warn("tdb_external: getaddrinfo failed (%s)\n", gai_strerror(ret));
        return TDB_ERR_EXT_CONNECT_FAILED;
    }
    if ((sock = socket(res->ai_family,
                       res->ai_socktype | SOCK_NONBLOCK,
                       res->ai_protocol)) == -1){
        ext_warn("tdb_external: creating a socket failed (%s)\n",
                 strerror(errno));
        return TDB_ERR_EXT_CONNECT_FAILED;
    }
    if ((ret = connect(sock, res->ai_addr, res->ai_addrlen)) &&
         errno != EINPROGRESS){
        ext_warn("tdb_external: connect failed (%s)\n",
                 strerror(errno));
        return TDB_ERR_EXT_CONNECT_FAILED;
    }
    ret = 1;
    if (setsockopt(sock, SOL_TCP, TCP_NODELAY, &ret, sizeof(ret))){
        ext_warn("tdb_external: setting TCP_NODELAY failed (%s)\n",
                 strerror(errno));
        return TDB_ERR_EXT_CONNECT_FAILED;
    }

    FD_ZERO(&fds);
    FD_SET(sock, &fds);

    if (db->external_connect_timeout > 0){
        long ms = (long)db->external_connect_timeout;
        tv.tv_sec = ms / 1000L;
        tv.tv_nsec = (ms % 1000L) * 1000L;
        ret = pselect(sock + 1, NULL, &fds, NULL, &tv, NULL);
    }else{
        while (1){
            tv.tv_sec = 10;
            tv.tv_nsec = 0;
            if ((ret = pselect(sock + 1, NULL, &fds, NULL, &tv, NULL)))
                break;
            else
                ext_warn("tdb_external: still trying to connect to %s:%s\n",
                         db->external_host,
                         db->external_port);
        }
    }
    switch (ret){
        case -1:
            ext_warn("tdb_external: select failed (%s)\n", strerror(errno));
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

static tdb_error receive_response(tdb *db, struct tdb_ext_packet *resp)
{
    char *ptr = (char*)resp;
    tdb_error err;

    memset(resp->path, 0, sizeof(resp->path));

    if ((err = receive_bytes(db->external_conn,
                             ptr,
                             TDB_EXT_PACKET_HEAD_SIZE)))
        return err;

    if (memcmp(resp->type, "OKOK", 4)){
        shutdown(db->external_conn, SHUT_RDWR);
        close(db->external_conn);
        if (!memcmp(resp->type, "PROT", 4))
            return TDB_ERR_EXT_UNSUPPORTED_PROTOCOL;
        else if (!memcmp(resp->type, "MISS", 4))
            return TDB_ERR_EXT_NOT_FOUND;
        else
            return TDB_ERR_EXT_SERVER_FAILURE;
    }
    return receive_bytes(db->external_conn,
                         &ptr[TDB_EXT_PACKET_HEAD_SIZE],
                         resp->path_len);
}

tdb_error ext_comm_request(tdb *db,
                           const char *type,
                           uint64_t offset,
                           uint64_t min_size,
                           struct tdb_ext_packet *resp)
{
    struct tdb_ext_packet req = {.offset = offset, .size = min_size};
    const char *buffer = (const char*)&req;
    uint64_t size, num_reconn = 0;
    uint64_t i = 0;
    tdb_error err;

    memcpy(req.type, type, 4);
    req.path_len = (uint32_t)strlen(db->root);

    if (req.path_len >= TDB_EXT_MAX_PATH_LEN)
        return TDB_ERR_EXT_PATH_TOO_LONG;

    memcpy(req.path, db->root, req.path_len);
    size = req.path_len + TDB_EXT_PACKET_HEAD_SIZE;

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
            if ((err = ext_comm_connect(db)))
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

void ext_comm_free(tdb *db)
{
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
    free((char*)db->external_host);
    free((char*)db->external_port);
#pragma GCC diagnostic pop

    if (db->external_conn){
        struct tdb_ext_packet resp;
        ext_comm_request(db, "EXIT", 0, 0, &resp);
        close(db->external_conn);
    }
}
