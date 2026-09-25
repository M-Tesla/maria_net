#include <curl/curl.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <time.h>
#include <sys/timerfd.h>
#include <unistd.h>

size_t mn_write_cb(char *ptr, size_t size, size_t nmemb, void *userdata);
int mn_on_socket(void *user, void *easy, int sock, int what, void *socketp);
int mn_on_timer(void *user, long timeout_ms);

struct MnMulti {
    CURLM *multi;
    void *user;
};

static int socket_cb(CURL *easy, curl_socket_t s, int what, void *userp, void *socketp) {
    struct MnMulti *m = userp;
    (void)socketp;
    return mn_on_socket(m->user, easy, (int)s, what, NULL);
}

static int timer_cb(CURLM *multi, long timeout_ms, void *userp) {
    (void)multi;
    struct MnMulti *m = userp;
    return mn_on_timer(m->user, timeout_ms);
}

int mn_global_init(void) {
    return curl_global_init(CURL_GLOBAL_ALL);
}

struct MnMulti *mn_multi_new(void *user, long max_total) {
    struct MnMulti *m = calloc(1, sizeof *m);
    if (!m) return NULL;
    m->multi = curl_multi_init();
    if (!m->multi) {
        free(m);
        return NULL;
    }
    m->user = user;
    curl_multi_setopt(m->multi, CURLMOPT_SOCKETFUNCTION, socket_cb);
    curl_multi_setopt(m->multi, CURLMOPT_SOCKETDATA, m);
    curl_multi_setopt(m->multi, CURLMOPT_TIMERFUNCTION, timer_cb);
    curl_multi_setopt(m->multi, CURLMOPT_TIMERDATA, m);
    curl_multi_setopt(m->multi, CURLMOPT_MAX_TOTAL_CONNECTIONS, max_total);
    return m;
}

void mn_multi_destroy(struct MnMulti *m) {
    if (!m) return;
    curl_multi_cleanup(m->multi);
    free(m);
}

int mn_multi_add(struct MnMulti *m, CURL *easy) {
    return (int)curl_multi_add_handle(m->multi, easy);
}

int mn_multi_remove(struct MnMulti *m, CURL *easy) {
    return (int)curl_multi_remove_handle(m->multi, easy);
}

int mn_socket_action(struct MnMulti *m, int sock, int ev, int *running) {
    return (int)curl_multi_socket_action(m->multi, sock, ev, running);
}

int mn_next_done(struct MnMulti *m, CURL **easy, int *result) {
    for (;;) {
        int left = 0;
        CURLMsg *msg = curl_multi_info_read(m->multi, &left);
        if (!msg) return 0;
        if (msg->msg == CURLMSG_DONE) {
            *easy = msg->easy_handle;
            *result = (int)msg->data.result;
            return 1;
        }
    }
}

CURL *mn_easy_new(void) { return curl_easy_init(); }

void mn_easy_free(CURL *easy) { curl_easy_cleanup(easy); }

int mn_easy_setup(
    CURL *easy,
    const char *url,
    const char *method,
    const void *body,
    long body_len,
    int send_body,
    struct curl_slist *headers,
    struct curl_slist *resolve,
    long timeout_ms,
    long connect_timeout_ms,
    long max_body,
    char *errbuf,
    void *write_user) {
    curl_easy_setopt(easy, CURLOPT_URL, url);
    curl_easy_setopt(easy, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(easy, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(easy, CURLOPT_MAXREDIRS, 0L);
    curl_easy_setopt(easy, CURLOPT_PROXY, "");
    curl_easy_setopt(easy, CURLOPT_NOPROXY, "*");
    curl_easy_setopt(easy, CURLOPT_ALTSVC_CTRL, 0L);
    curl_easy_setopt(easy, CURLOPT_PROTOCOLS_STR, "http,https");
    curl_easy_setopt(easy, CURLOPT_REDIR_PROTOCOLS_STR, "http,https");
    curl_easy_setopt(easy, CURLOPT_TIMEOUT_MS, timeout_ms);
    curl_easy_setopt(easy, CURLOPT_CONNECTTIMEOUT_MS, connect_timeout_ms);
    curl_easy_setopt(easy, CURLOPT_USERAGENT, "maria-net/0.1");
    curl_easy_setopt(easy, CURLOPT_ERRORBUFFER, errbuf);
    curl_easy_setopt(easy, CURLOPT_WRITEFUNCTION, mn_write_cb);
    curl_easy_setopt(easy, CURLOPT_WRITEDATA, write_user);
    curl_easy_setopt(easy, CURLOPT_HTTPHEADER, headers);
    if (resolve) curl_easy_setopt(easy, CURLOPT_RESOLVE, resolve);
    curl_easy_setopt(easy, CURLOPT_MAXFILESIZE_LARGE, (curl_off_t)max_body);
    if (send_body) {
        curl_easy_setopt(easy, CURLOPT_POSTFIELDS, body);
        curl_easy_setopt(easy, CURLOPT_POSTFIELDSIZE, body_len);
        curl_easy_setopt(easy, CURLOPT_CUSTOMREQUEST, method);
    } else if (strcmp(method, "GET") == 0) {
        curl_easy_setopt(easy, CURLOPT_HTTPGET, 1L);
    } else {
        curl_easy_setopt(easy, CURLOPT_CUSTOMREQUEST, method);
        curl_easy_setopt(easy, CURLOPT_HTTPGET, 1L);
    }
    return 0;
}

long mn_status(CURL *easy) {
    long code = 0;
    curl_easy_getinfo(easy, CURLINFO_RESPONSE_CODE, &code);
    return code;
}

long mn_time_ms(CURL *easy) {
    curl_off_t us = 0;
    curl_easy_getinfo(easy, CURLINFO_TOTAL_TIME_T, &us);
    return (long)(us / 1000);
}

const char *mn_errstr(int code) {
    return curl_easy_strerror((CURLcode)code);
}

struct curl_slist *mn_slist_append(struct curl_slist *list, const char *line) {
    return curl_slist_append(list, line);
}

void mn_slist_free(struct curl_slist *list) { curl_slist_free_all(list); }

int mn_poll_in(void) { return CURL_POLL_IN; }
int mn_poll_out(void) { return CURL_POLL_OUT; }
int mn_poll_inout(void) { return CURL_POLL_INOUT; }
int mn_poll_remove(void) { return CURL_POLL_REMOVE; }
int mn_socket_timeout(void) { return CURL_SOCKET_TIMEOUT; }

int mn_epoll_create(void) { return epoll_create1(EPOLL_CLOEXEC); }

int mn_epoll_set(int ep, int fd, int add, int want_in, int want_out) {
    struct epoll_event ev;
    memset(&ev, 0, sizeof ev);
    ev.data.fd = fd;
    ev.events = EPOLLERR | EPOLLHUP;
    if (want_in) ev.events |= EPOLLIN;
    if (want_out) ev.events |= EPOLLOUT;
    int op = add ? EPOLL_CTL_ADD : EPOLL_CTL_MOD;
    if (epoll_ctl(ep, op, fd, &ev) != 0) {
        if (!add && errno == ENOENT) return epoll_ctl(ep, EPOLL_CTL_ADD, fd, &ev) == 0 ? 0 : -1;
        return -1;
    }
    return 0;
}

int mn_epoll_del(int ep, int fd) {
    struct epoll_event ev;
    memset(&ev, 0, sizeof ev);
    if (epoll_ctl(ep, EPOLL_CTL_DEL, fd, &ev) != 0 && errno != ENOENT && errno != EBADF) return -1;
    return 0;
}

struct MnReady {
    int fd;
    int is_timer;
    int in_ev;
    int out_ev;
    int err_ev;
};

int mn_epoll_wait(int ep, int timerfd, struct MnReady *out, int max, int timeout_ms) {
    struct epoll_event evs[32];
    if (max > 32) max = 32;
    int n = epoll_wait(ep, evs, max, timeout_ms);
    if (n < 0) {
        if (errno == EINTR) return 0;
        return -1;
    }
    for (int i = 0; i < n; i++) {
        int fd = evs[i].data.fd;
        out[i].fd = fd;
        out[i].is_timer = fd == timerfd;
        out[i].in_ev = (evs[i].events & (EPOLLIN | EPOLLERR | EPOLLHUP)) ? CURL_CSELECT_IN : 0;
        out[i].out_ev = (evs[i].events & (EPOLLOUT | EPOLLERR | EPOLLHUP)) ? CURL_CSELECT_OUT : 0;
        out[i].err_ev = (evs[i].events & (EPOLLERR | EPOLLHUP)) ? 1 : 0;
        if (fd == timerfd) {
            uint64_t expirations = 0;
            ssize_t rd = read(timerfd, &expirations, sizeof expirations);
            (void)rd;
        }
    }
    return n;
}

int mn_timerfd_create(void) {
    return timerfd_create(1, TFD_NONBLOCK | TFD_CLOEXEC);
}

int mn_timerfd_arm(int fd, long timeout_ms) {
    struct itimerspec ts;
    memset(&ts, 0, sizeof ts);
    if (timeout_ms == 0) {
        ts.it_value.tv_nsec = 1000000L;
    } else if (timeout_ms > 0) {
        ts.it_value.tv_sec = timeout_ms / 1000;
        ts.it_value.tv_nsec = (timeout_ms % 1000) * 1000000L;
    }
    return timerfd_settime(fd, 0, &ts, NULL);
}
