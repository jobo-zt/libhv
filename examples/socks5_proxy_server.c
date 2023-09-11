/*
 * socks5 proxy server
 *
 * @build:          make examples
 *
 * @proxy_server    bin/socks5_proxy_server 1080
 *                  bin/socks5_proxy_server 1080 username password
 *
 * @proxy_client    curl -v http://www.example.com/ --proxy socks5://127.0.0.1:1080
 *                  curl -v http://www.example.com/ --proxy socks5://username:password@127.0.0.1:1080
 *
 */

#include "hv.h"
#include "hloop.h"

static char proxy_host[64] = "0.0.0.0";
static int  proxy_port = 1080;

static const char* auth_username = NULL;
static const char* auth_password = NULL;

#define SOCKS5_VERSION      ((uint8_t)5)

#define SOCKS5_AUTH_VERSION ((uint8_t)1)
#define SOCKS5_AUTH_SUCCESS ((uint8_t)0)
#define SOCKS5_AUTH_FAILURE ((uint8_t)1)

typedef enum {
    NoAuth          = 0,
    GssApiAuth      = 1,
    UserPassAuth    = 2,
} socks5_auth_method;

typedef enum {
    ConnectCommand  = 1,
    BindCommand     = 2,
    AssociateCommand= 3,
} socks5_command;

typedef enum {
    IPv4Addr    = 1,
    FqdnAddr    = 3,
    IPv6Addr    = 4,
} socks5_addr_type;

typedef enum {
    SuccessReply        = 0,
    ServerFailure       = 1,
    RuleFailure         = 2,
    NetworkUnreachable  = 3,
    HostUnreachable     = 4,
    ConnectRefused      = 5,
    TtlExpired          = 6,
    CommandNotSupported = 7,
    AddrTypeNotSupported= 8,
} socks5_reply_code;

typedef enum {
    s_begin,
    s_auth_methods_count,
    s_auth_methods,
    s_auth_username_len,
    s_auth_username,
    s_auth_password_len,
    s_auth_password,
    s_request,
    s_dst_addr_type,
    s_dst_addr_len,
    s_dst_addr,
    s_dst_port,
    s_upstream,
    s_end,
} socks5_state_e;

typedef struct {
    hio_t*              io;
    socks5_state_e      state;
    socks5_addr_type    addr_type;
    sockaddr_u          addr;
} socks5_conn_t;

// Add httpd
// =================================================== add httpd head by user start ======================================================
#define HTTP_KEEPALIVE_TIMEOUT 60000 // ms
#define HTTP_MAX_URL_LENGTH 256
#define HTTP_MAX_HEAD_LENGTH 1024

#define HTML_TAG_BEGIN "<html><body><center><h1>"
#define HTML_TAG_END "</h1></center></body></html>"

// status_message
#define HTTP_OK "OK"
#define NOT_FOUND "Not Found"
#define HELLO_WORLD "Hello, World"
#define NOT_IMPLEMENTED "Not Implemented"

// Content-Type
#define TEXT_PLAIN "text/plain"
#define TEXT_HTML "text/html"

typedef enum {
    s_begin_ex = s_end + 1,
    s_first_line,
    s_request_line = s_first_line,
    s_status_line = s_first_line,
    s_head,
    s_head_end,
    s_body,
    s_end_ex
} http_state_e;

typedef struct {
    // first line
    int major_version;
    int minor_version;
    union {
        // request line
        struct {
            char method[32];
            char path[HTTP_MAX_URL_LENGTH];
        };
        // status line
        struct {
            int status_code;
            char status_message[64];
        };
    };
    // headers
    char host[64];
    int content_length;
    char content_type[64];
    unsigned keepalive : 1;
    // char        head[HTTP_MAX_HEAD_LENGTH];
    // int         head_len;
    // body
    char* body;
    int body_len; // body_len = content_length
} http_msg_t;

typedef struct {
    hio_t* io;
    http_state_e state;
    http_msg_t request;
    http_msg_t response;
} http_conn_t;

static char s_date[32] = {0};
// =================================================== add httpd head by user end ======================================================
/*
 * workflow:
 * hloop_new -> hloop_create_tcp_server -> hloop_run
 * on_accept -> HV_ALLOC(socks5_conn_t) -> hio_readbytes(s_auth_methods_count:2) ->
 * on_recv -> hio_readbytes(s_auth_methods) ->
 * on_recv -> hio_write(auth_method) -> hio_readbytes(s_auth_username_len:2) ->
 * on_recv -> hio_readbytes(s_auth_username) ->
 * on_recv -> hio_readbytes(s_auth_password_len:1) ->
 * on_recv -> hio_readbytes(s_auth_password) -> hio_write(auth_result) ->
 * on_recv -> hio_readbytes(s_request:3) ->
 * on_recv -> hio_readbytes(addr_type:1) ->
 * on_recv -> hio_readbytes(addr_len:1) ->
 * on_recv -> hio_readbytes(addr) ->
 * on_recv -> hio_readbytes(port:2) ->
 * on_recv -> hio_setup_tcp_upstream(io, addr, port) ->
 * on_close -> hio_close_upstream -> HV_FREE(socks5_conn_t)
 *
 */

// define
// process http
static void on_recv_http(hio_t* io, void* buf, int readbytes);
static void on_close_http(hio_t* io);

static void on_upstream_connect(hio_t* upstream_io) {
    // printf("on_upstream_connect connfd=%d\n", hio_fd(upstream_io));
    socks5_conn_t* conn = (socks5_conn_t*)hevent_userdata(upstream_io);
    sockaddr_u* localaddr = (sockaddr_u*)hio_localaddr(upstream_io);
    uint8_t resp[32] = { SOCKS5_VERSION, SuccessReply, 0, IPv4Addr, 127,0,0,1, 0,80, 0 };
    int resp_len = 3;
    if (localaddr->sa.sa_family == AF_INET) {
        resp[resp_len++] = IPv4Addr;
        memcpy(resp + resp_len, &localaddr->sin.sin_addr, 4); resp_len += 4;
        memcpy(resp + resp_len, &localaddr->sin.sin_port, 2); resp_len += 2;
    } else if (localaddr->sa.sa_family == AF_INET6) {
        resp[resp_len++] = IPv6Addr;
        memcpy(resp + resp_len, &localaddr->sin6.sin6_addr, 16); resp_len += 16;
        memcpy(resp + resp_len, &localaddr->sin6.sin6_port, 2);  resp_len += 2;
    }
    hio_write(conn->io, resp, resp_len);
    hio_setcb_read(upstream_io, hio_write_upstream);
    hio_setcb_read(conn->io, hio_write_upstream);
    hio_read(conn->io);
    hio_read(upstream_io);
}

static void on_close(hio_t* io) {
    // printf("on_close fd=%d error=%d\n", hio_fd(io), hio_error(io));
    socks5_conn_t* conn = (socks5_conn_t*)hevent_userdata(io);
    if (conn) {
        hevent_set_userdata(io, NULL);
        HV_FREE(conn);
    }
    hio_close_upstream(io);
}

static void on_recv(hio_t* io, void* buf, int readbytes) {
    socks5_conn_t* conn = (socks5_conn_t*)hevent_userdata(io);
    const uint8_t* bytes = (uint8_t*)buf;

    switch(conn->state) {
    case s_begin:
        // printf("s_begin\n");
        conn->state = s_auth_methods_count;
    case s_auth_methods_count:
        // printf("s_auth_methods_count\n");
        {
            assert(readbytes == 2);
            uint8_t version = bytes[0];
            uint8_t methods_count = bytes[1];
            if (version != SOCKS5_VERSION || methods_count == 0) {

                // Release socks5 conn
                if (conn) {
                    hevent_set_userdata(io, NULL);
                    HV_FREE(conn);     
				}

				// http process
                http_conn_t* hHttpConn = NULL;
                HV_ALLOC_SIZEOF(hHttpConn);
                hHttpConn->io = io;
                hevent_set_userdata(io, hHttpConn);
                hio_setcb_read(io, on_recv_http);
                hio_setcb_close(io, on_close_http);

                hHttpConn->state = s_begin_ex;
				hio_readline(io);
                break;
            }
            conn->state = s_auth_methods;
            hio_readbytes(io, methods_count);
        }
        break;
    case s_auth_methods:
        // printf("s_auth_methods\n");
        {
            // TODO: check auth methos
            uint8_t auth_method = NoAuth;
            if (auth_username && auth_password) {
                auth_method = UserPassAuth;
            } else {
                // TODO: Implement more auth methods
            }
            // send auth mothod
            uint8_t resp[2] = { SOCKS5_VERSION, NoAuth };
            resp[1] = auth_method;
            hio_write(io, resp, 2);
            if (auth_method == NoAuth) {
                conn->state = s_request;
                hio_readbytes(io, 3);
            } else if (auth_method == UserPassAuth) {
                conn->state = s_auth_username_len;
                hio_readbytes(io, 2);
            }
        }
        break;
    case s_auth_username_len:
        // printf("s_auth_username_len\n");
        {
            assert(readbytes == 2);
            uint8_t auth_version = bytes[0];
            uint8_t username_len = bytes[1];
            if (auth_version != SOCKS5_AUTH_VERSION || username_len == 0) {
                fprintf(stderr, "Unsupported auth version: %d\n", (int)auth_version);
                hio_close(io);
                return;
            }
            conn->state = s_auth_username;
            hio_readbytes(io, username_len);
        }
        break;
    case s_auth_username:
        // printf("s_auth_username\n");
        {
            char* username = (char*)bytes;
            //printf("username=%.*s\n", readbytes, username);
            if (readbytes != strlen(auth_username) ||
                strncmp(username, auth_username, readbytes) != 0) {
                fprintf(stderr, "User authentication failed! username=%.*s\n", readbytes, username);
                uint8_t resp[2] = { SOCKS5_AUTH_VERSION, SOCKS5_AUTH_FAILURE };
                hio_write(io, resp, 2);
                hio_close(io);
                return;
            }
            conn->state = s_auth_password_len;
            hio_readbytes(io, 1);
        }
        break;
    case s_auth_password_len:
        // printf("s_auth_password_len\n");
        {
            assert(readbytes == 1);
            uint8_t password_len = bytes[0];
            if (password_len == 0) {
                fprintf(stderr, "Miss password\n");
                uint8_t resp[2] = { SOCKS5_AUTH_VERSION, SOCKS5_AUTH_FAILURE };
                hio_write(io, resp, 2);
                hio_close(io);
                return;
            }
            conn->state = s_auth_password;
            hio_readbytes(io, password_len);
        }
        break;
    case s_auth_password:
        // printf("s_auth_password\n");
        {
            char* password = (char*)bytes;
            //printf("password=%.*s\n", readbytes, password);
            uint8_t resp[2] = { SOCKS5_AUTH_VERSION, SOCKS5_AUTH_SUCCESS };
            if (readbytes != strlen(auth_password) ||
                strncmp(password, auth_password, readbytes) != 0) {
                fprintf(stderr, "User authentication failed! input password=%.*s\n", readbytes, password);
                resp[1] = SOCKS5_AUTH_FAILURE;
                hio_write(io, resp, 2);
                hio_close(io);
                return;
            }
            hio_write(io, resp, 2);
            conn->state = s_request;
            hio_readbytes(io, 3);
        }
        break;
    case s_request:
        // printf("s_request\n");
        {
            assert(readbytes == 3);
            uint8_t version = bytes[0];
            uint8_t cmd = bytes[1];
            if (version != SOCKS5_VERSION || cmd != ConnectCommand) {
                // TODO: Implement other commands
                fprintf(stderr, "Unsupported command: %d\n", (int)cmd);
                hio_close(io);
                return;
            }
            conn->state = s_dst_addr_type;
            hio_readbytes(io, 1);
        }
        break;
    case s_dst_addr_type:
        // printf("s_dst_addr_type\n");
        {
            assert(readbytes == 1);
            conn->addr_type = (socks5_addr_type)bytes[0];
            if (conn->addr_type == IPv4Addr) {
                conn->state = s_dst_addr;
                hio_readbytes(io, 4);
            } else if (conn->addr_type == FqdnAddr) {
                conn->state = s_dst_addr_len;
                hio_readbytes(io, 1);
            } else if (conn->addr_type == IPv6Addr) {
                conn->state = s_dst_addr;
                hio_readbytes(io, 16);
            } else {
                fprintf(stderr, "Unsupported addr type: %d\n", (int)conn->addr_type);
                hio_close(io);
                return;
            }
        }
        break;
    case s_dst_addr_len:
        // printf("s_dst_addr_len\n");
        {
            uint8_t addr_len = bytes[0];
            if (addr_len == 0) {
                fprintf(stderr, "Miss domain!\n");
                hio_close(io);
                return;
            }
            conn->state = s_dst_addr;
            hio_readbytes(io, addr_len);
        }
        break;
    case s_dst_addr:
        // printf("s_dst_addr\n");
        {
            if (conn->addr_type == IPv4Addr) {
                assert(readbytes == 4);
                conn->addr.sa.sa_family = AF_INET;
                memcpy(&conn->addr.sin.sin_addr, bytes, 4);
            } else if (conn->addr_type == IPv6Addr) {
                assert(readbytes == 16);
                conn->addr.sa.sa_family = AF_INET6;
                memcpy(&conn->addr.sin6.sin6_addr, bytes, 16);
            } else {
                char* host = NULL;
                STACK_OR_HEAP_ALLOC(host, readbytes + 1, 256);
                memcpy(host, bytes, readbytes);
                host[readbytes] = '\0';
                // TODO: async DNS
                int ret = ResolveAddr(host, &conn->addr);
                STACK_OR_HEAP_FREE(host);
                if (ret != 0) {
                    fprintf(stderr, "Resolve %.*s failed!\n", readbytes, (char*)bytes);
                    hio_close(io);
                    return;
                }
            }
            conn->state = s_dst_port;
            hio_readbytes(io, 2);
        }
        break;
    case s_dst_port:
        // printf("s_dst_port\n");
        {
            assert(readbytes == 2);
            uint16_t port = ((uint16_t)bytes[0]) << 8 | bytes[1];
            // printf("port=%d\n", port);
            sockaddr_set_port(&conn->addr, port);
            hloop_t* loop = hevent_loop(io);
            // hio_t* upstream_io = hio_setup_tcp_upstream(io, conn->host, conn->port, 0);
            // hio_t* upstream_io = hio_create_socket(loop, conn->host, conn->port, HIO_TYPE_TCP, HIO_CLIENT_SIDE);
            int sockfd = socket(conn->addr.sa.sa_family, SOCK_STREAM, 0);
            if (sockfd < 0) {
                perror("socket");
                hio_close(io);
                return;
            }
            hio_t* upstream_io = hio_get(loop, sockfd);
            assert(upstream_io != NULL);
            hio_set_peeraddr(upstream_io, &conn->addr.sa, sockaddr_len(&conn->addr));

            hevent_set_userdata(upstream_io, conn);
            // io <=> upstream_io
            hio_setup_upstream(io, upstream_io);
            hio_setcb_connect(upstream_io, on_upstream_connect);
            hio_setcb_close(upstream_io, hio_close_upstream);
            conn->state = s_upstream;
            // printf("connect to ");
            // SOCKADDR_PRINT(hio_peeraddr(upstream_io));
            hio_connect(upstream_io);
        }
        break;
    case s_upstream:
        hio_write_upstream(io, buf, readbytes);
        break;
    case s_end:
        break;
    default:
        if ((conn->state > s_end) && (conn->state <= s_end_ex)) {
            on_recv_http(io, buf, readbytes); 
        }
			
        break;
    }
}

static void on_accept(hio_t* io) {
    /*
    printf("on_accept connfd=%d\n", hio_fd(io));
    char localaddrstr[SOCKADDR_STRLEN] = {0};
    char peeraddrstr[SOCKADDR_STRLEN] = {0};
    printf("accept connfd=%d [%s] <= [%s]\n", hio_fd(io),
            SOCKADDR_STR(hio_localaddr(io), localaddrstr),
            SOCKADDR_STR(hio_peeraddr(io), peeraddrstr));
    */

    hio_setcb_read(io, on_recv);
    hio_setcb_close(io, on_close);

    socks5_conn_t* conn = NULL;
    HV_ALLOC_SIZEOF(conn);
    conn->io = io;
    hevent_set_userdata(io, conn);
    // start read
    conn->state = s_auth_methods_count;
    hio_readbytes(io, 2);
}

int main(int argc, char** argv) {
    if (argc < 2) {
        printf("Usage: %s proxy_port [username] [password]\n", argv[0]);
        return -10;
    }
    proxy_port = atoi(argv[1]);
    if (argc > 3) {
        auth_username = argv[2];
        auth_password = argv[3];
    }

    hloop_t* loop = hloop_new(0);
    hio_t* listenio = hloop_create_tcp_server(loop, proxy_host, proxy_port, on_accept);
    if (listenio == NULL) {
        return -20;
    }
    printf("socks5 proxy server listening on %s:%d, listenfd=%d\n", proxy_host, proxy_port, hio_fd(listenio));
    hloop_run(loop);
    hloop_free(&loop);
    return 0;
}

// Add httpd
// =================================================== add httpd body by user start ======================================================
static int http_response_dump(http_msg_t* msg, char* buf, int len) {
    int offset = 0;
    // status line
    offset += snprintf(buf + offset, len - offset, "HTTP/%d.%d %d %s\r\n", msg->major_version, msg->minor_version, msg->status_code, msg->status_message);
    // headers
    offset += snprintf(buf + offset, len - offset, "Server: libhv/%s\r\n", hv_version());
    offset += snprintf(buf + offset, len - offset, "Connection: %s\r\n", msg->keepalive ? "keep-alive" : "close");
    if (msg->content_length > 0) {
        offset += snprintf(buf + offset, len - offset, "Content-Length: %d\r\n", msg->content_length);
    }
    if (*msg->content_type) {
        offset += snprintf(buf + offset, len - offset, "Content-Type: %s\r\n", msg->content_type);
    }
    if (*s_date) {
        offset += snprintf(buf + offset, len - offset, "Date: %s\r\n", s_date);
    }
    // TODO: Add your headers
    offset += snprintf(buf + offset, len - offset, "\r\n");
    // body
    if (msg->body && msg->content_length > 0) {
        memcpy(buf + offset, msg->body, msg->content_length);
        offset += msg->content_length;
    }
    return offset;
}

static int http_reply(http_conn_t* conn, int status_code, const char* status_message, const char* content_type, const char* body, int body_len) {
    http_msg_t* req = &conn->request;
    http_msg_t* resp = &conn->response;
    resp->major_version = req->major_version;
    resp->minor_version = req->minor_version;
    resp->status_code = status_code;
    if (status_message) strncpy(resp->status_message, status_message, sizeof(req->status_message) - 1);
    if (content_type) strncpy(resp->content_type, content_type, sizeof(req->content_type) - 1);
    resp->keepalive = req->keepalive;
    if (body) {
        if (body_len <= 0) body_len = strlen(body);
        resp->content_length = body_len;
        resp->body = (char*)body;
    }
    char* buf = NULL;
    STACK_OR_HEAP_ALLOC(buf, HTTP_MAX_HEAD_LENGTH + resp->content_length, HTTP_MAX_HEAD_LENGTH + 1024);
    int msglen = http_response_dump(resp, buf, HTTP_MAX_HEAD_LENGTH + resp->content_length);
    int nwrite = hio_write(conn->io, buf, msglen);
    STACK_OR_HEAP_FREE(buf);
    return nwrite < 0 ? nwrite : msglen;
}

static int http_serve_file(http_conn_t* conn) {
    http_msg_t* req = &conn->request;
    http_msg_t* resp = &conn->response;
    // GET / HTTP/1.1\r\n
    const char* filepath = req->path + 1;
    // homepage
    if (*filepath == '\0') {
        filepath = "index.html";
    }
    FILE* fp = fopen(filepath, "rb");
    if (!fp)  {
        //http_reply(conn, 404, NOT_FOUND, TEXT_HTML, HTML_TAG_BEGIN NOT_FOUND HTML_TAG_END, 0);
        http_reply(conn, 200, HELLO_WORLD, TEXT_HTML, HTML_TAG_BEGIN HELLO_WORLD HTML_TAG_END, 0);
        return 404;
    }
    char buf[4096] = {0};
    // send head
    size_t filesize = hv_filesize(filepath);
    resp->content_length = filesize;
    const char* suffix = hv_suffixname(filepath);
    const char* content_type = NULL;
    if (strcmp(suffix, "html") == 0) {
        content_type = TEXT_HTML;
    }
    else {
        // TODO: set content_type by suffix
    }
    int nwrite = http_reply(conn, 200, "OK", content_type, NULL, 0);
    if (nwrite < 0) return nwrite; // disconnected
    // send file
    int nread = 0;
    while (1) {
        nread = fread(buf, 1, sizeof(buf), fp);
        if (nread <= 0) break;
        nwrite = hio_write(conn->io, buf, nread);
        if (nwrite < 0) return nwrite; // disconnected
        if (nwrite == 0) {
            // send too fast or peer recv too slow
            // WARN: too large file should control sending rate, just delay a while in the demo!
            hv_delay(10);
        }
    }
    fclose(fp);
    return 200;
}

static bool parse_http_request_line(http_conn_t* conn, char* buf, int len) {
    // GET / HTTP/1.1
    http_msg_t* req = &conn->request;
    sscanf(buf, "%s %s HTTP/%d.%d", req->method, req->path, &req->major_version, &req->minor_version);
    sprintf(&req->path[HTTP_MAX_URL_LENGTH - 1], "%s", "\0");

	//fix last get 2 bytes so here fix
    if (strcmp(req->method, "T") == 0) sprintf(req->method, "%s", "GET");
    if (strcmp(req->method, "ST") == 0) sprintf(req->method, "%s", "POST");
    if (strcmp(req->method, "") == 0) sprintf(req->method, "%s", "GET");

    if (req->major_version != 1) return false;
    if (req->minor_version == 1) req->keepalive = 1;
    // printf("%s %s HTTP/%d.%d\r\n", req->method, req->path, req->major_version, req->minor_version);
    return true;
}

static bool parse_http_head(http_conn_t* conn, char* buf, int len) {
    http_msg_t* req = &conn->request;
    // Content-Type: text/html
    const char* key = buf;
    const char* val = buf;
    char* delim = strchr(buf, ':');
    if (!delim) return false;
    *delim = '\0';
    val = delim + 1;
    // trim space
    while (*val == ' ') ++val;
    // printf("%s: %s\r\n", key, val);
    if (stricmp(key, "Content-Length") == 0) {
        req->content_length = atoi(val);
    }
    else if (stricmp(key, "Content-Type") == 0) {
        strncpy(req->content_type, val, sizeof(req->content_type) - 1);
    }
    else if (stricmp(key, "Connection") == 0) {
        if (stricmp(val, "close") == 0) {
            req->keepalive = 0;
        }
    }
    else {
        // TODO: save other head
    }
    return true;
}

static int on_request(http_conn_t* conn) {
    http_msg_t* req = &conn->request;
    // TODO: router
    if (strcmp(req->method, "GET") == 0) {
        // GET /ping HTTP/1.1\r\n
        if (strcmp(req->path, "/ping") == 0) {
            http_reply(conn, 200, "OK", TEXT_PLAIN, "pong", 4);
            return 200;
        }
        else {
            // TODO: Add handler for your path
        }
        return http_serve_file(conn);
    }
    else if (strcmp(req->method, "POST") == 0) {
        // POST /echo HTTP/1.1\r\n
        if (strcmp(req->path, "/echo") == 0) {
            http_reply(conn, 200, "OK", req->content_type, req->body, req->content_length);
            return 200;
        }
        else {
            // TODO: Add handler for your path
        }
    }
    else {
        // TODO: handle other method
    }
    //http_reply(conn, 501, NOT_IMPLEMENTED, TEXT_HTML, HTML_TAG_BEGIN NOT_IMPLEMENTED HTML_TAG_END, 0);
    http_serve_file(conn);
    return 501;
}

static void on_close_http(hio_t* io) {
    // printf("on_close fd=%d error=%d\n", hio_fd(io), hio_error(io));
    http_conn_t* conn = (http_conn_t*)hevent_userdata(io);
    if (conn) {
        hevent_set_userdata(io, NULL);
        HV_FREE(conn);
    }
    hio_close_upstream(io);
}

static void on_recv_http(hio_t* io, void* buf, int readbytes) {
    char* str = (char*)buf;
    // printf("on_recv fd=%d readbytes=%d\n", hio_fd(io), readbytes);
    // printf("%.*s", readbytes, str);
    http_conn_t* conn = (http_conn_t*)hevent_userdata(io);
    http_msg_t* req = &conn->request;
    switch (conn->state) {
    case s_begin_ex:
        // printf("s_begin_ex");
        conn->state = s_first_line;
    case s_first_line:
        // printf("s_first_line\n");
        if (readbytes < 2) {
            fprintf(stderr, "Not match \r\n!");
            hio_close(io);
            return;
        }

		if (readbytes > 2) {
			str[readbytes - 2] = '\0';
			if (parse_http_request_line(conn, str, readbytes - 2) == false) {
				fprintf(stderr, "Failed to parse http request line:\n%s\n", str);
				hio_close(io);
				return;
			}
		}

		// start read head
        conn->state = s_head;
        hio_readline(io);
        break;
    case s_head:
        // printf("s_head\n");
        if (readbytes < 2) {
            fprintf(stderr, "Not match \r\n!");
            hio_close(io);
            return;
        }
        if (readbytes == 2 && str[0] == '\r' && str[1] == '\n') {
            conn->state = s_head_end;
        }
        else {

            str[readbytes - 2] = '\0';
            if (parse_http_head(conn, str, readbytes - 2) == false) {
                fprintf(stderr, "Failed to parse http head:\n%s\n", str);
                hio_close(io);
                return;
            }

            hio_readline(io);
            break;
        }
    case s_head_end:
        // printf("s_head_end\n");
        if (req->content_length == 0) {
            conn->state = s_end_ex;
            goto s_end_ex;
        }
        else {
            // start read body
            conn->state = s_body;
            // WARN: too large content_length should read multiple times!
            hio_readbytes(io, req->content_length);
            break;
        }
    case s_body:
        // printf("s_body\n");
        req->body = str;
        req->body_len += readbytes;
        if (req->body_len == req->content_length) {
            conn->state = s_end_ex;
        }
        else {
            // WARN: too large content_length should be handled by streaming!
            break;
        }
    case s_end_ex:
s_end_ex:
        // printf("s_end\n");
        // received complete request
        on_request(conn);
        if (hio_is_closed(io)) return;
        if (req->keepalive) {
            // Connection: keep-alive\r\n
            // reset and receive next request
            memset(&conn->request, 0, sizeof(http_msg_t));
            memset(&conn->response, 0, sizeof(http_msg_t));
            conn->state = s_first_line;
            hio_readline(io);
        }
        else {
            // Connection: close\r\n
            hio_close(io);
        }
        break;
    default: break;
    }
}
// =================================================== add httpd body by user end ======================================================