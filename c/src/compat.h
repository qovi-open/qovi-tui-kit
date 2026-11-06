/* SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 Marc Gandar
 *
 * compat.h -- SEULE couche dependante de l'OS (sockets, temps, processus).
 * Linux/POSIX et Windows (Winsock) exposent ici la meme API ; le reste du
 * code ne contient aucun #ifdef. */
#ifndef QOVI_COMPAT_H
#define QOVI_COMPAT_H

#include <stddef.h>
#include <stdio.h>

#ifdef _WIN32
  #ifndef WIN32_LEAN_AND_MEAN
  #define WIN32_LEAN_AND_MEAN
  #endif
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <windows.h>
  typedef SOCKET qsock_t;
  #define QSOCK_INVALID INVALID_SOCKET
#else
  typedef int qsock_t;
  #define QSOCK_INVALID (-1)
#endif

#define Q_TIMEOUT (-2)   /* code retour de q_recv_timeout */

int     q_net_init(void);                 /* 0 = ok */
void    q_net_cleanup(void);

qsock_t q_tcp_connect(const char *host, int port, int timeout_ms);
qsock_t q_tcp_listen(const char *host, int port, int backlog);
qsock_t q_tcp_accept(qsock_t srv, int *peer_port);
int     q_send_all(qsock_t s, const void *buf, size_t len);   /* 0 = ok */
/* >0 : octets lus ; 0 : connexion fermee ; -1 : erreur ; Q_TIMEOUT */
int     q_recv_timeout(qsock_t s, void *buf, size_t cap, int timeout_ms);
void    q_close(qsock_t s);

void      q_sleep_ms(int ms);
long long q_now_ms(void);                          /* horloge monotone */
int       q_utc_iso_ms(char *out, size_t cap);     /* 2026-10-06T08:20:00.123 */
int       q_local_stamp(char *out, size_t cap);    /* 2026-10-06 10:20:00 (local) */

/* PID du processus client connecte au service : on cherche la socket dont
 * le port local est peer_port et le port distant server_port.
 * Linux : /proc (meme utilisateur) ; Windows : GetExtendedTcpTable.
 * -1 si introuvable. */
long      q_peer_pid(int peer_port, int server_port);

/* Delais d'envoi et de reception d'une socket BLOQUANTE (TLS). 0 = ok */
int       q_sock_timeouts(qsock_t s, int timeout_ms);

/* Attend des donnees a lire. >0 pret ; 0 delai ; <0 erreur */
int       q_wait_read(qsock_t s, int timeout_ms);

/* Fils d'execution detaches et verrou (le service traite plusieurs demandes) */
typedef void (*q_thread_fn)(void *arg);
int       q_thread_start(q_thread_fn fn, void *arg);    /* 0 = ok */
#ifdef _WIN32
  typedef CRITICAL_SECTION q_mutex;
#else
  #include <pthread.h>
  typedef pthread_mutex_t q_mutex;
#endif
void      q_mutex_init(q_mutex *m);
void      q_mutex_lock(q_mutex *m);
void      q_mutex_unlock(q_mutex *m);

/* Heure UTC en secondes (horloge murale, pour signer les requetes) */
long long q_unix_time(void);

/* Ouvre un journal en ajout. Linux : cree en 0600 (il contient des emails). */
FILE     *q_log_open(const char *path);

#endif
