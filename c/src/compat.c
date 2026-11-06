/* SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 Marc Gandar
 *
 * compat.c -- implementation POSIX / Winsock de compat.h */
#include "compat.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
  #include <windows.h>
  #include <iphlpapi.h>
  #include <stdlib.h>
  #define Q_SEND_FLAGS 0
#else
  #include <dirent.h>
  #include <stdlib.h>
  #include <sys/stat.h>
  #include <errno.h>
  #include <fcntl.h>
  #include <netdb.h>
  #include <unistd.h>
  #include <arpa/inet.h>
  #include <netinet/in.h>
  #include <sys/select.h>
  #include <sys/socket.h>
  #define Q_SEND_FLAGS MSG_NOSIGNAL   /* pas de SIGPIPE si le pair a ferme */
#endif

int q_net_init(void)
{
#ifdef _WIN32
    WSADATA w;
    return WSAStartup(MAKEWORD(2, 2), &w) == 0 ? 0 : -1;
#else
    return 0;
#endif
}

void q_net_cleanup(void)
{
#ifdef _WIN32
    WSACleanup();
#endif
}

void q_close(qsock_t s)
{
    if (s == QSOCK_INVALID) return;
#ifdef _WIN32
    closesocket(s);
#else
    close(s);
#endif
}

static int set_nonblock(qsock_t s, int on)
{
#ifdef _WIN32
    u_long m = on ? 1 : 0;
    return ioctlsocket(s, FIONBIO, &m) == 0 ? 0 : -1;
#else
    int f = fcntl(s, F_GETFL, 0);
    if (f < 0) return -1;
    f = on ? (f | O_NONBLOCK) : (f & ~O_NONBLOCK);
    return fcntl(s, F_SETFL, f) == 0 ? 0 : -1;
#endif
}

static int connect_in_progress(void)
{
#ifdef _WIN32
    return WSAGetLastError() == WSAEWOULDBLOCK;
#else
    return errno == EINPROGRESS;
#endif
}

/* >0 pret ; 0 timeout ; <0 erreur */
static int wait_sock(qsock_t s, int for_write, int timeout_ms)
{
    fd_set rw, ex;
    struct timeval tv;
    int nfds, r;
#ifndef _WIN32
    if (s < 0 || s >= FD_SETSIZE) return -1;   /* select() ne gere pas au-dela */
    nfds = s + 1;
#else
    nfds = 0;                                   /* ignore par Winsock */
#endif
    if (timeout_ms < 0) timeout_ms = 0;
    FD_ZERO(&rw); FD_ZERO(&ex);
    FD_SET(s, &rw); FD_SET(s, &ex);
    tv.tv_sec  = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    r = select(nfds, for_write ? NULL : &rw, for_write ? &rw : NULL, &ex, &tv);
    if (r > 0 && FD_ISSET(s, &ex) && !FD_ISSET(s, &rw)) return -1;
    return r;
}

qsock_t q_tcp_connect(const char *host, int port, int timeout_ms)
{
    char ps[16];
    struct addrinfo hints, *res = NULL, *ai;
    qsock_t s = QSOCK_INVALID;

    if (port <= 0 || port > 65535) return QSOCK_INVALID;
    snprintf(ps, sizeof ps, "%d", port);
    memset(&hints, 0, sizeof hints);
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, ps, &hints, &res) != 0) return QSOCK_INVALID;

    for (ai = res; ai; ai = ai->ai_next) {
        int ok = 0;
        s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s == QSOCK_INVALID) continue;
        if (set_nonblock(s, 1) == 0) {
            if (connect(s, ai->ai_addr, (socklen_t)ai->ai_addrlen) == 0) {
                ok = 1;
            } else if (connect_in_progress() && wait_sock(s, 1, timeout_ms) > 0) {
                int err = 0;
                socklen_t el = sizeof err;
                if (getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&err, &el) == 0 && err == 0)
                    ok = 1;
            }
        }
        if (ok && set_nonblock(s, 0) == 0) break;
        q_close(s);
        s = QSOCK_INVALID;
    }
    freeaddrinfo(res);
    return s;
}

qsock_t q_tcp_listen(const char *host, int port, int backlog)
{
    char ps[16];
    struct addrinfo hints, *res = NULL;
    qsock_t s;

    if (port <= 0 || port > 65535) return QSOCK_INVALID;
    snprintf(ps, sizeof ps, "%d", port);
    memset(&hints, 0, sizeof hints);
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags    = AI_PASSIVE;
    if (getaddrinfo(host, ps, &hints, &res) != 0) return QSOCK_INVALID;

    s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (s != QSOCK_INVALID) {
#ifdef _WIN32
        /* EXCLUSIVEADDRUSE : empeche un autre processus de detourner le port
         * (SO_REUSEADDR sous Windows le permettrait). */
        BOOL one = TRUE;
        setsockopt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (const char *)&one, sizeof one);
#else
        int one = 1;
        setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
#endif
        if (bind(s, res->ai_addr, (socklen_t)res->ai_addrlen) != 0 || listen(s, backlog) != 0) {
            q_close(s);
            s = QSOCK_INVALID;
        }
    }
    freeaddrinfo(res);
    return s;
}

qsock_t q_tcp_accept(qsock_t srv, int *peer_port)
{
    struct sockaddr_storage ss;
    socklen_t sl = sizeof ss;
    qsock_t c = accept(srv, (struct sockaddr *)&ss, &sl);

    if (peer_port) *peer_port = 0;
    if (c == QSOCK_INVALID) return c;
    if (peer_port) {
        if (ss.ss_family == AF_INET)
            *peer_port = ntohs(((struct sockaddr_in *)&ss)->sin_port);
        else if (ss.ss_family == AF_INET6)
            *peer_port = ntohs(((struct sockaddr_in6 *)&ss)->sin6_port);
    }
    return c;
}

int q_send_all(qsock_t s, const void *buf, size_t len)
{
    const char *p = (const char *)buf;
    while (len > 0) {
        int chunk = len > 65536 ? 65536 : (int)len;
        int n = (int)send(s, p, chunk, Q_SEND_FLAGS);
        if (n <= 0) return -1;
        p   += n;
        len -= (size_t)n;
    }
    return 0;
}

int q_recv_timeout(qsock_t s, void *buf, size_t cap, int timeout_ms)
{
    int w, n, chunk;
    if (cap == 0) return -1;
    w = wait_sock(s, 0, timeout_ms);
    if (w == 0) return Q_TIMEOUT;
    if (w < 0)  return -1;
    chunk = cap > 65536 ? 65536 : (int)cap;
    n = (int)recv(s, (char *)buf, chunk, 0);
    return n < 0 ? -1 : n;
}

void q_sleep_ms(int ms)
{
    if (ms <= 0) return;
#ifdef _WIN32
    Sleep((DWORD)ms);
#else
    {
        struct timespec ts;
        ts.tv_sec  = ms / 1000;
        ts.tv_nsec = (long)(ms % 1000) * 1000000L;
        while (nanosleep(&ts, &ts) != 0 && errno == EINTR) { }
    }
#endif
}

long long q_now_ms(void)
{
#ifdef _WIN32
    return (long long)GetTickCount64();
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
#endif
}

int q_utc_iso_ms(char *out, size_t cap)
{
    int n;
#ifdef _WIN32
    SYSTEMTIME t;
    GetSystemTime(&t);
    n = snprintf(out, cap, "%04u-%02u-%02uT%02u:%02u:%02u.%03u",
                 t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond, t.wMilliseconds);
#else
    struct timespec ts;
    struct tm tm;
    clock_gettime(CLOCK_REALTIME, &ts);
    if (!gmtime_r(&ts.tv_sec, &tm)) return -1;
    n = snprintf(out, cap, "%04d-%02d-%02dT%02d:%02d:%02d.%03ld",
                 tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                 tm.tm_hour, tm.tm_min, tm.tm_sec, ts.tv_nsec / 1000000L);
#endif
    return (n > 0 && (size_t)n < cap) ? 0 : -1;
}

#ifndef _WIN32
/* inode de la socket TCP (local port lp, distant port rp) dans /proc/net/tcp[6] */
static unsigned long proc_inode(const char *file, int lp, int rp)
{
    FILE *f = fopen(file, "r");
    char line[512];
    unsigned long found = 0;
    if (!f) return 0;
    if (!fgets(line, sizeof line, f)) { fclose(f); return 0; }   /* en-tete */
    while (fgets(line, sizeof line, f)) {
        char la[64], ra[64];
        unsigned int l, r;
        unsigned long ino;
        if (sscanf(line, " %*d: %63[0-9A-Fa-f]:%x %63[0-9A-Fa-f]:%x %*x %*x:%*x %*x:%*x %*x %*u %*u %lu",
                   la, &l, ra, &r, &ino) == 5 && (int)l == lp && (int)r == rp && ino != 0) {
            found = ino;
            break;
        }
    }
    fclose(f);
    return found;
}
#endif

long q_peer_pid(int peer_port, int server_port)
{
#ifdef _WIN32
    ULONG sz = 0;
    PMIB_TCPTABLE_OWNER_PID t = NULL;
    long pid = -1;
    DWORD i;
    if (GetExtendedTcpTable(NULL, &sz, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != ERROR_INSUFFICIENT_BUFFER)
        return -1;
    t = (PMIB_TCPTABLE_OWNER_PID)malloc(sz);
    if (!t) return -1;
    if (GetExtendedTcpTable(t, &sz, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
        for (i = 0; i < t->dwNumEntries; i++) {
            if (ntohs((u_short)t->table[i].dwLocalPort) == peer_port &&
                ntohs((u_short)t->table[i].dwRemotePort) == server_port) {
                pid = (long)t->table[i].dwOwningPid;
                break;
            }
        }
    }
    free(t);
    return pid;
#else
    char want[64], path[600], link[64];
    unsigned long ino;
    DIR *proc;
    struct dirent *e;
    long pid = -1;

    ino = proc_inode("/proc/net/tcp", peer_port, server_port);
    if (!ino) ino = proc_inode("/proc/net/tcp6", peer_port, server_port);
    if (!ino) return -1;
    snprintf(want, sizeof want, "socket:[%lu]", ino);

    proc = opendir("/proc");
    if (!proc) return -1;
    while (pid < 0 && (e = readdir(proc)) != NULL) {
        DIR *fd;
        struct dirent *g;
        const char *p = e->d_name;
        while (*p >= '0' && *p <= '9') p++;
        if (*p || e->d_name[0] == '\0') continue;           /* que les PID */
        snprintf(path, sizeof path, "/proc/%s/fd", e->d_name);
        fd = opendir(path);
        if (!fd) continue;                                  /* autre utilisateur */
        while ((g = readdir(fd)) != NULL) {
            ssize_t n;
            if (g->d_name[0] == '.') continue;
            snprintf(path, sizeof path, "/proc/%s/fd/%s", e->d_name, g->d_name);
            n = readlink(path, link, sizeof link - 1);
            if (n <= 0) continue;
            link[n] = '\0';
            if (strcmp(link, want) == 0) { pid = strtol(e->d_name, NULL, 10); break; }
        }
        closedir(fd);
    }
    closedir(proc);
    return pid;
#endif
}

FILE *q_log_open(const char *path)
{
#ifdef _WIN32
    return fopen(path, "a");
#else
    mode_t old = umask(077);
    FILE *f = fopen(path, "a");
    umask(old);
    return f;
#endif
}

int q_local_stamp(char *out, size_t cap)
{
    int n;
#ifdef _WIN32
    SYSTEMTIME t;
    GetLocalTime(&t);
    n = snprintf(out, cap, "%04u-%02u-%02u %02u:%02u:%02u",
                 t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond);
#else
    time_t now = time(NULL);
    struct tm tm;
    if (!localtime_r(&now, &tm)) return -1;
    n = (int)strftime(out, cap, "%Y-%m-%d %H:%M:%S", &tm);
#endif
    return (n > 0 && (size_t)n < cap) ? 0 : -1;
}

int q_sock_timeouts(qsock_t s, int timeout_ms)
{
#ifdef _WIN32
    DWORD t = (DWORD)timeout_ms;
    if (setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&t, sizeof t) != 0) return -1;
    return setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char *)&t, sizeof t) == 0 ? 0 : -1;
#else
    struct timeval tv;
    tv.tv_sec  = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    if (setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv) != 0) return -1;
    return setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv) == 0 ? 0 : -1;
#endif
}

int q_wait_read(qsock_t s, int timeout_ms)
{
    return wait_sock(s, 0, timeout_ms);
}

typedef struct { q_thread_fn fn; void *arg; } thr_t;

#ifdef _WIN32
static DWORD WINAPI thr_main(LPVOID p)
{
    thr_t t = *(thr_t *)p;
    free(p);
    t.fn(t.arg);
    return 0;
}

int q_thread_start(q_thread_fn fn, void *arg)
{
    HANDLE h;
    thr_t *t = (thr_t *)malloc(sizeof *t);
    if (!t) return -1;
    t->fn = fn; t->arg = arg;
    h = CreateThread(NULL, 256 * 1024, thr_main, t, 0, NULL);
    if (!h) { free(t); return -1; }
    CloseHandle(h);                                 /* detache */
    return 0;
}

void q_mutex_init(q_mutex *m)   { InitializeCriticalSection(m); }
void q_mutex_lock(q_mutex *m)   { EnterCriticalSection(m); }
void q_mutex_unlock(q_mutex *m) { LeaveCriticalSection(m); }

long long q_unix_time(void)
{
    FILETIME ft;
    unsigned long long v;
    GetSystemTimeAsFileTime(&ft);
    v = ((unsigned long long)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    return (long long)(v / 10000000ULL - 11644473600ULL);
}
#else
static void *thr_main(void *p)
{
    thr_t t = *(thr_t *)p;
    free(p);
    t.fn(t.arg);
    return NULL;
}

int q_thread_start(q_thread_fn fn, void *arg)
{
    pthread_t th;
    pthread_attr_t at;
    int rc;
    thr_t *t = (thr_t *)malloc(sizeof *t);
    if (!t) return -1;
    t->fn = fn; t->arg = arg;
    pthread_attr_init(&at);
    pthread_attr_setdetachstate(&at, PTHREAD_CREATE_DETACHED);
    rc = pthread_create(&th, &at, thr_main, t);
    pthread_attr_destroy(&at);
    if (rc != 0) { free(t); return -1; }
    return 0;
}

void q_mutex_init(q_mutex *m)   { pthread_mutex_init(m, NULL); }
void q_mutex_lock(q_mutex *m)   { pthread_mutex_lock(m); }
void q_mutex_unlock(q_mutex *m) { pthread_mutex_unlock(m); }

long long q_unix_time(void)
{
    return (long long)time(NULL);
}
#endif
