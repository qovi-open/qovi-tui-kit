/* SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 Marc Gandar
 *
 * qovi_tls.c -- client TLS verifie (OpenSSL) */
#include "qovi_tls.h"
#include "compat.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#ifdef _WIN32
  #include <wincrypt.h>
#else
  #include <signal.h>
#endif

#define IO_TIMEOUT_MS 15000     /* plafond d'une ecriture ou d'un enregistrement */

struct q_tls { SSL *ssl; qsock_t s; };

static SSL_CTX *g_ctx = NULL;

static void set_err(char *e, size_t cap, const char *s)
{
    if (cap) snprintf(e, cap, "%s", s);
}

#ifdef _WIN32
/* Recopie les racines du magasin Windows dans OpenSSL */
static int load_windows_roots(X509_STORE *st)
{
    HCERTSTORE hs = CertOpenSystemStoreA(0, "ROOT");
    PCCERT_CONTEXT c = NULL;
    int n = 0;
    if (!hs) return 0;
    while ((c = CertEnumCertificatesInStore(hs, c)) != NULL) {
        const unsigned char *p = c->pbCertEncoded;
        X509 *x = d2i_X509(NULL, &p, (long)c->cbCertEncoded);
        if (x) {
            if (X509_STORE_add_cert(st, x) == 1) n++;
            X509_free(x);
        }
    }
    CertCloseStore(hs, 0);
    ERR_clear_error();                /* doublons eventuels : sans importance */
    return n;
}
#endif

int q_tls_init(const char *ca_file)
{
#ifndef _WIN32
    signal(SIGPIPE, SIG_IGN);         /* OpenSSL ecrit sans MSG_NOSIGNAL */
#endif
    g_ctx = SSL_CTX_new(TLS_client_method());
    if (!g_ctx) return -1;
    SSL_CTX_set_min_proto_version(g_ctx, TLS1_2_VERSION);
    SSL_CTX_set_verify(g_ctx, SSL_VERIFY_PEER, NULL);
    if (ca_file && *ca_file) {
        if (SSL_CTX_load_verify_locations(g_ctx, ca_file, NULL) != 1) goto fail;
    } else {
#ifdef _WIN32
        if (load_windows_roots(SSL_CTX_get_cert_store(g_ctx)) == 0) goto fail;
#else
        if (SSL_CTX_set_default_verify_paths(g_ctx) != 1) goto fail;
#endif
    }
    return 0;
fail:
    SSL_CTX_free(g_ctx);
    g_ctx = NULL;
    return -1;
}

void q_tls_cleanup(void)
{
    SSL_CTX_free(g_ctx);
    g_ctx = NULL;
}

q_tls *q_tls_connect(const char *host, int port, int timeout_ms, char *err, size_t cap)
{
    q_tls *t;
    long vr;

    set_err(err, cap, "");
    if (!g_ctx) { set_err(err, cap, "TLS non initialise"); return NULL; }
    t = (q_tls *)calloc(1, sizeof *t);
    if (!t) { set_err(err, cap, "memoire"); return NULL; }
    t->s = q_tcp_connect(host, port, timeout_ms);
    if (t->s == QSOCK_INVALID) { set_err(err, cap, "connexion impossible"); free(t); return NULL; }
    q_sock_timeouts(t->s, timeout_ms > 0 ? timeout_ms : IO_TIMEOUT_MS);

    t->ssl = SSL_new(g_ctx);
    if (!t->ssl || SSL_set_fd(t->ssl, (int)t->s) != 1 ||
        SSL_set_tlsext_host_name(t->ssl, host) != 1 ||      /* SNI */
        SSL_set1_host(t->ssl, host) != 1) {                 /* nom d'hote verifie */
        set_err(err, cap, "TLS : preparation impossible");
        goto fail;
    }
    if (SSL_connect(t->ssl) != 1) {
        vr = SSL_get_verify_result(t->ssl);
        if (vr != X509_V_OK)
            snprintf(err, cap, "TLS : certificat refuse (%s)", X509_verify_cert_error_string(vr));
        else
            set_err(err, cap, "TLS : poignee de main impossible");
        goto fail;
    }
    if (SSL_get_verify_result(t->ssl) != X509_V_OK) {       /* ceinture et bretelles */
        set_err(err, cap, "TLS : certificat refuse");
        goto fail;
    }
    q_sock_timeouts(t->s, IO_TIMEOUT_MS);
    ERR_clear_error();
    return t;

fail:
    ERR_clear_error();
    if (t->ssl) SSL_free(t->ssl);
    q_close(t->s);
    free(t);
    return NULL;
}

int q_tls_send(q_tls *t, const void *buf, size_t n)
{
    const char *p = (const char *)buf;
    while (n > 0) {
        int chunk = n > 16384 ? 16384 : (int)n;   /* une trame CH4 tient en un enregistrement */
        int w = SSL_write(t->ssl, p, chunk);
        if (w <= 0) { ERR_clear_error(); return -1; }
        p += w;
        n -= (size_t)w;
    }
    return 0;
}

int q_tls_recv(q_tls *t, void *buf, size_t cap, int timeout_ms)
{
    int r, e;
    if (cap == 0) return -1;
    if (SSL_pending(t->ssl) <= 0) {
        int w = q_wait_read(t->s, timeout_ms);
        if (w == 0) return Q_TIMEOUT;
        if (w < 0) return -1;
    }
    r = SSL_read(t->ssl, buf, cap > 16384 ? 16384 : (int)cap);
    if (r > 0) return r;
    e = SSL_get_error(t->ssl, r);
    ERR_clear_error();
    if (e == SSL_ERROR_ZERO_RETURN) return 0;
    if (e == SSL_ERROR_WANT_READ) return Q_TIMEOUT;      /* enregistrement incomplet */
    if (e == SSL_ERROR_SYSCALL && r == 0) return 0;      /* fermeture brutale */
    return -1;
}

const char *q_tls_version(q_tls *t)
{
    return (t && t->ssl) ? SSL_get_version(t->ssl) : "?";
}

void q_tls_close(q_tls *t)
{
    if (!t) return;
    if (t->ssl) {
        SSL_shutdown(t->ssl);
        SSL_free(t->ssl);
    }
    ERR_clear_error();
    q_close(t->s);
    free(t);
}
