#include <stdio.h>
#include <ctype.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <limits.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>

#include "threadpool.h"

struct arguments {
    int port;
    int pool_size;
    int max_requests;
    const char * filter;
};

struct filter {
    char ** hosts;
    size_t num_hosts;

    in_addr_t * ips;
    size_t num_ips;
};

typedef struct dispatch_st {
    int sd;
    struct sockaddr_in inaddr;
    const struct filter * filt;
} dispatch_t;

//Send an error reply over a socket
static void err_reply(const int sd, const int code, const char * hdr, const char * msg){

    const size_t cont_len = snprintf(NULL, 0,
                                     "<HTML><HEAD><TITLE>%d %s</TITLE></HEAD><BODY><H4>%d %s</H4>%s.</BODY></HTML>",
                                     code, hdr, code, hdr, msg);

    dprintf(sd, "HTTP/1.0 %d %s\r\n", code, hdr);
    dprintf(sd, "Content-Type: text/html\r\n");
    dprintf(sd, "Content-Length: %lu\r\n", cont_len);
    dprintf(sd, "Connection: closed\r\n\r\n");
    dprintf(sd, "<HTML><HEAD><TITLE>%d %s</TITLE></HEAD><BODY><H4>%d %s</H4>%s.</BODY></HTML>",
            code, hdr, code, hdr, msg);
}

//Read HTTP reqeust
static int read_headers(const int sd, char * buf, const size_t buf_size){
    size_t i = 0;

    while(recv(sd, &buf[i], 1, 0) > 0){

        if(++i >= buf_size){  //if buffer is full
            break;
        }

        //if we have the request end
        if((i >=4) && (strncmp(&buf[i - 4], "\r\n\r\n", 4) == 0)){
            break;
        }
    }

    buf[i-1] = '\0';

    return i;
}

//Extract host
static int is_legal(const int sd, const char * buf, const size_t buf_len, char hname[NI_MAXHOST], char pname[PATH_MAX]){
    char * end, *save_ptr;
    size_t len = strchr(buf, '\r') - buf;

    char * first = (char*) malloc(sizeof(char) *(len+1));
    strncpy(first, buf, len);
    first[len] = '\0';


    char * method = strtok_r(first, " ",&save_ptr);
    char * uri    = strtok_r(NULL, " ", &save_ptr);
    char * proto  = strtok_r(NULL, " ", &save_ptr);

    if((method == NULL) || (uri == NULL) || (proto == NULL)){
        free(first);
        err_reply(sd, 400, "Bad Request", "Bad Request");
        return -1;
    }

    //must be a GET request
    if(strcmp(method, "GET") != 0){
        free(first);
        err_reply(sd, 501, "Not Implemented", "Method is not supported");
        return -1;
    }

    //check if HTTP version is 1.0/1.1
    if( (strcmp(proto, "HTTP/1.0") != 0) &&
        (strcmp(proto, "HTTP/1.1") != 0) ){
        free(first);
        err_reply(sd, 400, "Bad Request", "Bad Request");
        return -1;
    }

    if(uri[0] == '/'){  //GET /index.php HTTP/1.0
        strncpy(pname, uri, PATH_MAX);

        //get host from header line
        char * hosthdr = strstr(buf, "Host: ");
        if(hosthdr == NULL){
            free(first);
            err_reply(sd, 400, "Bad Request", "Bad Request");
            return -1;
        }

        end = strchr(hosthdr, '\r');
        if(end == NULL){
            free(first);
            err_reply(sd, 400, "Bad Request", "Bad Request");
            return -1;
        }
        end[0] = '\0';

        strncpy(hname, &hosthdr[6], NI_MAXHOST);

    }else{  //GET http://www.site.com:80/index.html HTTP/1.0
        char * end;

        if(strncmp(uri, "http://", 7) == 0){
            uri += 7;
        }

        end = strchr(uri, '/'); //find end of hostname
        if(end){
            strncpy(pname, end, PATH_MAX);

            end[0] = '\0';
            end = strchr(uri, ':');
            if(end){
                end[0] = '\0';
            }
        }
        strncpy(hname, uri, NI_MAXHOST);
    }

    free(first);
    return 0;
}

//Check if we can get IP for that hostname
static int is_resolveable(const char * hname){
    int s;
    struct addrinfo hints, *result;

    /* Obtain address(es) matching host/port. */
    memset(&hints, 0, sizeof(hints));

    hints.ai_family = AF_INET;        /* Allow IPv4 */
    hints.ai_socktype = SOCK_STREAM;  /* TCP */
    hints.ai_flags = 0;
    hints.ai_protocol = 0;          /* Any protocol */

    s = getaddrinfo(hname, "80", &hints, &result);
    if (s != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
        freeaddrinfo(result);           /* No longer needed */
        return -1;
    }
    freeaddrinfo(result);           /* No longer needed */

    return 0;
}

static int is_filtered_host(const char * hname, const struct filter * filt){
    size_t i;
    //check each hostname in filter
    for(i=0; i < filt->num_hosts; i++){
        if(strcmp(hname, filt->hosts[i]) == 0){
            return 1;
        }
    }
    return 0;
}

static int is_filtered_ip(const char * hname, const struct filter * filt){
    int s;
    struct addrinfo hints, *result, *rp;

    /* Obtain address(es) matching host/port. */
    memset(&hints, 0, sizeof(hints));

    hints.ai_family = AF_INET;        /* Allow IPv4 */
    hints.ai_socktype = SOCK_STREAM;  /* TCP */
    hints.ai_flags = 0;
    hints.ai_protocol = 0;          /* Any protocol */

    s = getaddrinfo(hname, "80", &hints, &result);
    if (s != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
        return -1;
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        if(rp->ai_family == AF_INET){
            size_t i;

            //that is the server IP address
            struct sockaddr_in inaddr = *(struct sockaddr_in*) rp->ai_addr;
            const in_addr_t ip_addr = inaddr.sin_addr.s_addr;

            //check each ip network in filter
            for(i=0; i < filt->num_ips; i++){
                const in_addr_t mask = filt->ips[i];

                if((ip_addr & mask) == mask){
                    return 1;
                }
            }
        }
    }
    freeaddrinfo(result);           /* No longer needed */

    return 0; //not filtered
}

//Check if a host/ip is filtered
static int is_filtered(const char * hname, const struct filter * filt){


    if(!isdigit(hname[0])){  //if its not a digit
        if(is_filtered_host(hname, filt) == 1){
            return 1;
        }
    }

    //we always check if ip, is in the filtered networks
    return is_filtered_ip(hname, filt);
}

static int creat_cache_file(const char * hname, const char * pname){
    char fpath[PATH_MAX];

    if(strcmp(pname, "/") == 0){  //don't cache indexp pages
        //create the path
        snprintf(fpath, PATH_MAX, "%s/index.html", hname);
    }else{
        snprintf(fpath, PATH_MAX, "%s%s", hname, pname);
    }

    //create the path to file
    char * delim = strchr(fpath, '/');
    while(delim){ //if we have a directory
        //replace / with null, to end string temporarily
        delim[0] = '\0';

        if(mkdir(fpath, 0770) == -1){
            if(errno != EEXIST){
                perror("mkdir");
                break;
            }
        }
        //restore delimiter
        delim[0] = '/';

        //move to next delimiter
        delim = strchr(delim + 1, '/');
    }

    //create the file
    int fd = open(fpath, O_CREAT | O_RDWR, 0764);
    if(fd == -1){
        perror("open");
    }

    return fd;
}

//Open a file from cache, based on hostname and URL path
static int open_cache_file(const char * hname, const char * pname){
    char fpath[PATH_MAX];

    if(strcmp(pname, "/") == 0){  //don't cache indexp pages
        //create the path
        snprintf(fpath, PATH_MAX, "%s/index.html", hname);
    }else{
        snprintf(fpath, PATH_MAX, "%s%s", hname, pname);
    }

    return open(fpath, O_RDONLY);
}

static int connect_to(const char * hname){
    struct addrinfo hints, *result, *rp;
    int s, sd = -1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;        /* Allow IPv4 */
    hints.ai_socktype = SOCK_STREAM; /* Datagram socket */

    s = getaddrinfo(hname, "80", &hints, &result);
    if (s != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
        return -1;
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        sd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sd == -1){
            continue;
        }

        if (connect(sd, rp->ai_addr, rp->ai_addrlen) != -1)
            break;                  /* Success */

        close(sd);
    }
    freeaddrinfo(result);           /* No longer needed */

    return sd;
}

static int writen(const int fd, const char * buf, const int len){
    int i=0;
    while(i < len){
        int n = write(fd, &buf[i], len - i);
        if(n <= 0){
            perror("write");
            return -1;
        }
        i += n;
    }
    return len;
}

static int send_cache_file(const int sd, const int fd){
    char buf[100];
    int rv = 0, buf_len;

    while((buf_len = read(fd, buf, sizeof(buf))) > 0){
        if(writen(sd, buf, buf_len) != buf_len){
            rv = -1;
            break;
        }
        rv += buf_len;
    }
    close(fd);
    return rv;
}

static int save_cache_file(const int sd, const char * hname, const char * pname){
    char buf[100];
    int err=0, buf_len;

    int fd = creat_cache_file(hname, pname);
    if(fd == -1){
        return -1;
    }

    //send file and cache at the same time
    while((buf_len = read(sd, buf, sizeof(buf))) > 0){

        if(writen(fd, buf, buf_len) != buf_len){
            err = -1;
            break;
        }
    }

    if(err == -1){
        close(fd);  //close cache file
        fd = -1;
    }

    return fd;
}

static int cache_file(const int sd, const char *hname, const char * pname, char * hdr, int hdr_len, const int hdr_size){
    const int serv_sd = connect_to(hname);
    if(serv_sd == -1){
        err_reply(sd, 404, "Not Found", "File not found");
        return -1;
    }

    //re-send client request
    //if(writen(serv_sd, hdr, hdr_len) != hdr_len){
    //  err_reply(sd, 500, "Some server side error", "Some server side error");
    //  return -1;
    //}
    dprintf(serv_sd, "GET %s HTTP/1.0\r\n", pname);
    dprintf(serv_sd, "Host: %s\r\n\r\n", hname);

    //receive server reply headers
    hdr_len = read_headers(serv_sd, hdr, hdr_size);
    if(hdr_len <= 0){
        err_reply(sd, 500, "Some server side error", "Some server side error");
        return -1;
    }

    //re-send server reply to client
    if(writen(sd, hdr, hdr_len) != hdr_len){
        err_reply(sd, 500, "Some server side error", "Some server side error");
        return -1;
    }

    const int fd = save_cache_file(serv_sd, hname, pname);
    if(fd > 0){
        //return to beginning of file
        lseek(fd, 0L, SEEK_SET);
    }

    shutdown(serv_sd, SHUT_RDWR);
    close(serv_sd);

    return fd;
}

static int send_hdr_file(const int sd, const int fd){
    struct stat st;

    if(fstat(fd, &st) == -1){
        perror("fstat");
        err_reply(sd, 500, "Some server side error", "Some server side error");
        return -1;
    }

    //send header to client
    dprintf(sd, "HTTP/1.0 200 OK\r\n");
    dprintf(sd, "Content-Length: %lu\r\n", st.st_size);
    dprintf(sd, "Content-Type: text/html\r\nConnection: Closed\r\n\r\n");

    return st.st_size;
}

int proxy_handler(void * arg){

    dispatch_t * data = (dispatch_t *) arg;
    const int sd = data->sd;
    const struct filter * filt = data->filt;
    free(data);

    char hname[NI_MAXHOST], pname[PATH_MAX];

    const size_t buf_size = 4*1024;
    char * buf = malloc(sizeof(char)*buf_size);
    if(buf == NULL){
        perror("malloc");

        err_reply(sd, 500, "Some server side error", "Some server side error");

        shutdown(sd, SHUT_RDWR);
        close(sd);
        return -1;
    }

    //process client connection
    while(1){

        //read the request
        size_t buf_len = read_headers(sd, buf, buf_size);
        if(buf_len < 0){
            err_reply(sd, 400, "Bad Request", "Bad Request");
            break;
        }

        //check if we have a GET request with path and HTTP protocol
        if((is_legal(sd, buf, buf_len, hname, pname) < 0) ){
            break;
        }

        if(is_resolveable(hname) < 0){
            err_reply(sd, 404, "Not Found", "File not found");
            break;
        }

        if(is_filtered(hname, filt) < 0){
            err_reply(sd, 403, "Forbidden", "Access denied");
            break;
        }

        //request is valid, print it
        printf("HTTP request =\n%s\nLEN = %lu\n", buf, buf_len);

        size_t response_bytes = 0;

        int fd = open_cache_file(hname, pname);
        if(fd != -1){
            response_bytes = send_hdr_file(sd, fd);
            printf("File is given from local filesystem\n");
        }else{
            fd = cache_file(sd, hname, pname, buf, buf_len, buf_size);
            if(fd > 0){
                printf("File is given from origin filesystem\n");
            }
        }

        if(fd > 0){
            response_bytes = send_cache_file(sd, fd);
            printf("Total response bytes: %lu\n", response_bytes);
        }

        //serve only one request per connection
        break;
    }
    free(buf);

    //close the connection after reply is sent
    shutdown(sd, SHUT_RDWR);
    close(sd);

    return 0;
}

static int check_arguments(struct arguments * arg, const int argc, char * argv[]){

    if(argc != 5){
        fprintf(stderr, "Usage: proxyServer <port> <pool-size> <max-number-of-request> <filter>\n");
        return -1;
    }

    arg->port         = atoi(argv[1]);
    arg->pool_size    = atoi(argv[2]);
    arg->max_requests = atoi(argv[3]);
    arg->filter       =      argv[4];

    //check if number arguments are valid
    if( (arg->port < 0)      || (arg->port > 65535) ||
        (arg->pool_size < 0) || (arg->pool_size > MAXT_IN_POOL) ||
        (arg->max_requests < 0)){
        fprintf(stderr, "Error: Invalid arguments\n");
    }

    //check file exists and is readable
    if(access(arg->filter, R_OK) == -1){
        perror(arg->filter);
        return -1;
    }

    return 0;
}

static int creat_socket(const int port){
    struct sockaddr_in inaddr;
    const int opt = 1;

    const int sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock < 0){
        perror("socket");
        return -1;
    }

    if(setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(int)) != 0){
        perror("setsockopt");
        return -1;
    }

    bzero(&inaddr, sizeof(struct sockaddr_in));
    inaddr.sin_family	= AF_INET;
    inaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    inaddr.sin_port	= htons(port);

    if( bind(sock, (struct sockaddr *) &inaddr, sizeof(struct sockaddr_in)) < 0 ){
        perror("bind");
        return -1;
    }

    if(listen(sock, 10) < 0){
        perror("listen");
        return -1;
    }

    return sock;
}

static int accept_socket(const int sock, struct sockaddr_in *inaddr){
    char ip[INET_ADDRSTRLEN];
    size_t len = sizeof(struct sockaddr_in);

    const int sd = accept(sock, (struct sockaddr *) inaddr, (socklen_t *) &len);
    if(sd < 0){
        perror("accept");
        return -1;
    }

    inet_ntop(AF_INET, &inaddr->sin_addr, ip, INET_ADDRSTRLEN);
    printf("Peer %s connected on port %d\n", ip, ntohs(inaddr->sin_port));

    return sd;
}

static int load_filter(const char * filename, struct filter * filt){
    char buf[NI_MAXHOST];
    size_t hosts_size = 0;
    size_t ips_size = 0;

    FILE * fp = fopen(filename, "r");
    if(fp == NULL){
        perror("fopen");
        return -1;
    }

    filt->hosts = NULL;
    filt->ips = NULL;
    filt->num_hosts = filt->num_ips = 0;

    while(fgets(buf, sizeof(buf), fp) != NULL){

        size_t len = strlen(buf);
        if(buf[len-1] == '\n'){
            buf[--len] = '\0';  //remove newline
        }

        if(buf[len-1] == '\r'){
            buf[--len] = '\0';  //remove newline
        }

        if(isdigit(buf[0])){
            if(filt->num_ips >= ips_size){
                ips_size += 10;
                filt->ips = realloc(filt->ips, sizeof(char*)*ips_size);
            }
            const char * s_ip  = strtok(buf, "/");
            const char * s_net = strtok(NULL, "/");
            int ip = (int) inet_addr(s_ip);
            const int net = 32 - atoi(s_net);

            //drop the unused bits from ip
            ip = (ip >> net) << net;

            filt->ips[filt->num_ips++] = (in_addr_t) ip;

        }else{
            if(filt->num_hosts >= hosts_size){
                hosts_size += 10;
                filt->hosts = realloc(filt->hosts, sizeof(char*)*hosts_size);
            }
            filt->hosts[filt->num_hosts++] = strdup(buf);
        }
    }
    fclose(fp);

    return 0;
}

static void free_filters(struct filter * filt){
    int i;
    for(i=0; i < filt->num_hosts; i++){
        free(filt->hosts[i]);
    }
    free(filt->hosts);
    free(filt->ips);
}

static void sig_handler(int sig){
    return;
}

int main(const int argc, char * argv[]){
    struct arguments arg;
    threadpool * tp;
    struct filter filt;
    unsigned int nreq = 0;  //number of requests
    struct sigaction sa;

    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    sa.sa_handler = sig_handler;
    if( (sigaction(SIGTERM, &sa, NULL) == -1) ||
        (sigaction(SIGINT, &sa, NULL) == -1) ){
        perror("sigaction");
    }

    if(check_arguments(&arg, argc, argv) < 0){
        return EXIT_FAILURE;
    }

    if(load_filter(arg.filter, &filt) == -1){
        return EXIT_FAILURE;
    }

    tp = create_threadpool(arg.pool_size);
    if(tp == NULL){
        return EXIT_FAILURE;
    }

    const int sock = creat_socket(arg.port);
    if(sock == -1){
        return EXIT_FAILURE;
    }

    while(nreq++ < arg.max_requests){
        //wait for a connection
        struct sockaddr_in inaddr;
        const int sd = accept_socket(sock, &inaddr);
        if(sd == -1){
            break;
        }

        //dispatch to thread
        dispatch_t * data = (dispatch_t*) malloc(sizeof(dispatch_t));
        if(data == NULL){
            perror("malloc");
            break;
        }
        data->sd = sd;
        data->filt = &filt;
        data->inaddr = inaddr;

        dispatch(tp, proxy_handler, data);
    }

    shutdown(sock, SHUT_RDWR);
    close(sock);

    destroy_threadpool(tp);

    free_filters(&filt);
    return EXIT_SUCCESS;
}