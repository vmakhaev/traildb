
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <sys/select.h>
#include <sys/time.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <netinet/tcp.h>

#include <tdb_external_packet.h>

#define MAX_CONN 5
#define MAX_EPOLL_EVENTS 64

#define MESSAGE_TIMEOUT 50

#define DEBUG_MSG(fmt, ...) {\
    if (verbose)\
        fprintf(stderr, fmt, ##__VA_ARGS__);\
    }

#define PEER_MSG(fmt, ...) {\
    if (verbose){\
        int _port;\
        const char *_ip = get_addr(fd, &_port);\
        fprintf(stderr, "[%s:%d] ", _ip, _port);\
        fprintf(stderr, fmt, ##__VA_ARGS__);\
    }\
}

static void die(char *fmt, ...)
{
    va_list aptr;
    va_start(aptr, fmt);
    vfprintf(stderr, fmt, aptr);
    va_end(aptr);
    exit(1);
}

static int new_server_socket(int port)
{
    int on = 1;
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;

    if (sock < 0)
        die("Could not create a server socket\n");

    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)))
       die("Could not set SO_REUSEADDR\n");

    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (bind(sock, (struct sockaddr*)&addr, sizeof(struct sockaddr_in)) < 0)
        die("Binding to port %d failed\n", port);

    if (listen(sock, MAX_CONN))
        die("Listen failed\n");

    printf("Waiting for incoming connections at port %d\n", port);

    return sock;
}

static const char *get_addr(int fd, int *port)
{
    static char buffer[1024];
    struct sockaddr_storage addr;
    struct sockaddr_in *in = (struct sockaddr_in*)&addr;
    socklen_t addr_len = sizeof(struct sockaddr_storage);

    if (getpeername(fd, (struct sockaddr*)&addr, &addr_len))
        die("Getpeername failed\n");
    if (!inet_ntop(AF_INET, &in->sin_addr, buffer, sizeof(buffer)))
        die("Formatting peer address failed\n");

    *port = ntohs(in->sin_port);
    return buffer;
}

static void add_to_epoll(int efd, int fd)
{
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.u64 = 0LL;
    ev.data.fd = fd;

    if (epoll_ctl(efd, EPOLL_CTL_ADD, fd, &ev) < 0)
        die("Could not add a socket to epoll\n");
}

static uint64_t now()
{
    struct timespec tstamp;
    if (clock_gettime(CLOCK_MONOTONIC_COARSE, &tstamp))
        die("clock_gettime failed\n");
    return tstamp.tv_sec * 1000LLU + tstamp.tv_nsec / 1000000LLU;
}

static void wait_socket(int fd, int is_write)
{
    fd_set fds;
    struct timespec tv;
    int ret;

    FD_ZERO(&fds);
    FD_SET(fd, &fds);

    tv.tv_sec = 0;
    tv.tv_nsec = 10000000; /* 10ms */
    if (is_write)
        ret = pselect(fd + 1, NULL, &fds, NULL, &tv, NULL);
    else
        ret = pselect(fd + 1, &fds, NULL, NULL, &tv, NULL);
    if (ret  == -1)
        die("Waiting on socket failed\n");
}

static int receive_bytes(int fd, char *buf, uint32_t num_bytes)
{
    uint64_t start = now();
    int n, i = 0;

    while (i < num_bytes){
        if (now() - start > MESSAGE_TIMEOUT)
            return -2;
        if ((n = recv(fd, &buf[i], num_bytes - i, MSG_DONTWAIT)) < 1){
            if (n == -1 && errno == EAGAIN){
                wait_socket(fd, 0);
                continue;
            }else
                return -1;
        }else
            i += n;
    }
    return 0;
}

static int send_bytes(int fd, const char *buf, uint32_t num_bytes)
{
    uint64_t start = now();
    int n, i = 0;
    printf("SEND %u bytes\n", num_bytes);
    while (i < num_bytes){
        if (now() - start > MESSAGE_TIMEOUT)
            return -2;
        if ((n = send(fd, &buf[i], num_bytes - i, MSG_DONTWAIT)) < 1){
            if (n == -1 && errno == EAGAIN){
                wait_socket(fd, 1);
                continue;
            }else
                return -1;
        }else
            i += n;
    }
    return 0;
}

static int receive_request(int fd, struct tdb_ext_request *req)
{
    static char root[TDB_EXT_MAX_PATH_LEN];
    static char fname[TDB_EXT_MAX_PATH_LEN];
    int ret;

    if ((ret = receive_bytes(fd, (char*)req, TDB_EXT_REQUEST_HEAD_SIZE)))
        return ret;

    if (!(req->root_len < TDB_EXT_MAX_PATH_LEN &&
          req->fname_len < TDB_EXT_MAX_PATH_LEN))
        return -3;

    if ((ret = receive_bytes(fd, root, req->root_len)))
        return ret;
    req->root = root;

    if ((ret = receive_bytes(fd, fname, req->fname_len)))
        return ret;
    req->fname = fname;

    return 0;
}

static int send_response(int fd,
                         uint64_t offset,
                         uint64_t max_size,
                         const char *path)
{
    struct tdb_ext_response resp;
    memcpy(resp.type, "OKOK", 4);
    resp.offset = offset;
    resp.max_size = max_size;
    resp.path_len = strlen(path);
    memcpy(resp.path, path, resp.path_len);
    return send_bytes(fd,
                      (const char*)&resp,
                      TDB_EXT_RESPONSE_HEAD_SIZE + resp.path_len);
}

static int handle_request(int fd, const struct tdb_ext_request *req)
{
    printf("Got message %.4s root %.*s fname %.*s\n",
           req->type,
           req->root_len,
           req->root,
           req->fname_len,
           req->fname);
    if (!memcmp(req->type, "V000", 4)){
        send_response(fd, 0, 0, "");
        return 0;
    }else if (!memcmp(req->type, "READ", 4))
        return 0;
    else if (!memcmp(req->type, "EXIT", 4))
        return 1;
    else
        return -1;
    return 0;
}

static void server(int port, int verbose)
{
    struct epoll_event epoll_events[MAX_EPOLL_EVENTS];
    int server_sock = new_server_socket(port);
    int efd = epoll_create(1);
    int i, nfds;

    if (efd < 0)
        die("Could not create an epoll handle\n");

    add_to_epoll(efd, server_sock);

    while ((nfds = epoll_wait(efd, epoll_events, MAX_EPOLL_EVENTS, -1)) != -1){
        for (i = 0; i < nfds; i++){
            uint32_t ev = epoll_events[i].events;
            int fd = epoll_events[i].data.fd;

            /* closed connection */
            if ((ev & EPOLLERR) || (ev & EPOLLHUP) || (ev & EPOLLRDHUP)){
                PEER_MSG("Connection closed unexpectedly\n");
                close(fd);

            /* new connection */
            }else if ((ev & EPOLLIN) && fd == server_sock){
                struct sockaddr_in addr;
                int one = 1;
                socklen_t len = sizeof(struct sockaddr_in);
                if ((fd = accept(fd, (struct sockaddr*)&addr, &len)) < 0)
                    die("Accepting a new connection failed\n");
                PEER_MSG("New connection\n");

                if (setsockopt(fd, SOL_TCP, TCP_NODELAY, &one, sizeof(one)))
                    die("Setsockopt TCP_NODELAY failed\n");
                add_to_epoll(efd, fd);

            /* new message */
            }else if (ev & EPOLLIN){
                struct tdb_ext_request req;
                int ret = receive_request(fd, &req);
                if (ret){
                    if (ret == -1){
                        PEER_MSG("Truncated message\n");
                    }else if (ret == -2){
                        PEER_MSG("Message timeout\n");
                    }else{
                        PEER_MSG("Oversized message\n");
                    }
                    close(fd);
                }else{
                    int ret = handle_request(fd, &req);
                    if (ret){
                        if (ret == 1){
                            PEER_MSG("Closed connection\n");
                        }else{
                            PEER_MSG("Sent an unknown request, type '%.4s'\n",
                                     req.type);
                        }
                        close(fd);
                    }
                }
            /* something strange */
            }else
                die("Unknown epoll event: %u\n", ev);
        }
    }
    die("epoll_wait failed\n");
}

int main(int argc, char **argv)
{
    if (argc > 1)
        server(atoi(argv[1]), argc > 2 ? 1: 0);
    else
        die("Usage: external_server <port> [verbose]\n");
    return 0;
}
