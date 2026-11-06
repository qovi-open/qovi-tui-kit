/* SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 Marc Gandar
 *
 * qovi_ch4.c -- cycle CH4 en TLS + G1 (port de python/qovi_ch4.py) */
#include "qovi_ch4.h"
#include "compat.h"
#include "qovi_codec.h"
#include "qovi_crypto.h"
#include "qovi_json.h"
#include "qovi_tls.h"
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define G_MAX (8 * 1024)        /* taille max de l'objet g recopie */

/* Trace de diagnostic (QOVI_TUI_DEBUG=1) sur la sortie d'erreur : tailles,
 * types de trames, resultat du dechiffrement, code Tip.r. JAMAIS de cle, de
 * jeton ni de contenu dechiffre. */
static int dbg_on(void)
{
    const char *e = getenv("QOVI_TUI_DEBUG");
    return e && e[0] == '1';
}

static void dbg(const char *fmt, ...)
{
    va_list ap;
    if (!dbg_on()) return;
    va_start(ap, fmt);
    fprintf(stderr, "[ch4] ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
}

/* (04.11) objet g renvoye par Qovi apres un Go, recopie tel quel dans
 * SiT_3_End : taille, octets non ASCII, UTF-8 valide ou non, et les octets
 * (en hexa) autour du 1er non ASCII -- seulement la RAISON y est concernee,
 * pour diagnostiquer les accents. */
static void dbg_g(const char *g, size_t n)
{
    size_t i, first = n, na = 0, a, b;
    char hx[3 * 32 + 1];
    size_t k = 0;
    if (!dbg_on()) return;
    for (i = 0; i < n; i++) if ((unsigned char)g[i] >= 0x80) { if (first == n) first = i; na++; }
    dbg("objet g recu : %u octets, %u non ASCII, UTF-8 %s", (unsigned)n, (unsigned)na,
        q_utf8_valid(g, n) ? "valide" : "INVALIDE");
    if (first == n) return;
    a = first > 8 ? first - 8 : 0;
    b = first + 16 < n ? first + 16 : n;
    for (i = a; i < b && k + 3 < sizeof hx; i++) k += (size_t)snprintf(hx + k, sizeof hx - k, "%02x ", (unsigned char)g[i]);
    dbg("   octets autour du 1er non ASCII (position %u) : %s", (unsigned)first, hx);
}

/* debut d'une trame NON dechiffrable, en caracteres imprimables seulement */
static void dbg_peek(const char *p, size_t n)
{
    char s[61];
    size_t i, k = 0;
    if (!dbg_on()) return;
    for (i = 0; i < n && k < 60; i++)
        s[k++] = (p[i] >= 0x20 && p[i] < 0x7F) ? p[i] : '.';
    s[k] = '\0';
    dbg("   debut de la trame refusee : \"%s\"%s", s, n > 60 ? "..." : "");
}

typedef struct {
    const unsigned char *key;
    const char     *aad_r;
    q_ch4_status_cb cb;
    void           *ud;
    q_ch4_verdict   v;
    int             done;
    char           *text;
    size_t          textcap;
    char          **g_out;
} ctx_t;

const char *q_ch4_verdict_name(q_ch4_verdict v)
{
    switch (v) {
    case Q_CH4_GO:      return "GO";
    case Q_CH4_KO:      return "KO";
    case Q_CH4_TIMEOUT: return "TIMEOUT";
    default:            return "ERR";
    }
}

static void set_text(char *t, size_t cap, const char *s)
{
    if (cap) snprintf(t, cap, "%s", s);
}

/* [longueur 4 octets big-endian][payload] en UNE seule ecriture TLS, comme le
 * Python : un serveur qui lit l'en-tete et le contenu dans le meme morceau ne
 * doit pas recevoir deux enregistrements TLS separes. */
static int send_frame(q_tls *t, const char *payload, size_t n)
{
    unsigned char *b;
    int rc;
    if (n > Q_CH4_MAX_MSG) return -1;
    b = (unsigned char *)malloc(4 + n);
    if (!b) return -1;
    b[0] = (unsigned char)(n >> 24);
    b[1] = (unsigned char)(n >> 16);
    b[2] = (unsigned char)(n >> 8);
    b[3] = (unsigned char)n;
    memcpy(b + 4, payload, n);
    rc = q_tls_send(t, b, 4 + n);
    free(b);
    return rc;
}

/* G1({"g":{},"c":{"i":<i>}}) -- separateurs compacts comme le Python */
static char *seal_click(const unsigned char *key, const char *aad_q, int i)
{
    char m[48];
    snprintf(m, sizeof m, "{\"g\":{},\"c\":{\"i\":%d}}", i);
    return q_g1_seal(key, aad_q, m, NULL);
}

static void handle_frame(ctx_t *c, const char *payload, size_t n)
{
    char *clr = q_g1_open(c->key, c->aad_r, payload, n);
    long r;
    char s[512];

    if (!clr) {                               /* fausse, modifiee ou pas pour nous */
        dbg("trame de %u octets : G1 REFUSEE (ignoree)", (unsigned)n);
        dbg_peek(payload, n);
        return;
    }
    if (q_json_get_int(clr, "Tip.r", &r) != 0) {           /* pas de Tip : ignoree */
        dbg("trame de %u octets : G1 ok, sans Tip.r (ignoree)", (unsigned)n);
        goto out;
    }
    dbg("trame de %u octets : G1 ok, Tip.r=%ld", (unsigned)n, r);
    if (q_json_get_str(clr, "Tip.s", s, sizeof s) != 0) s[0] = '\0';

    if (r == Q_RES_OK || r == Q_RES_OG) {
        if (c->cb) c->cb((int)r, s[0] ? s : "demande envoyee au mobile, vote en attente", c->ud);
    } else if (r == Q_RES_GO) {
        c->v = Q_CH4_GO;
        c->done = 1;
        set_text(c->text, c->textcap, s[0] ? s : "accepte");
        if (c->g_out && !*c->g_out) {
            const char *g;
            size_t gl;
            if (q_json_find(clr, "g", &g, &gl) == 0 && gl <= G_MAX && *g == '{') {
                dbg_g(g, gl);
                *c->g_out = (char *)malloc(gl + 1);
                if (*c->g_out) { memcpy(*c->g_out, g, gl); (*c->g_out)[gl] = '\0'; }
            } else {
                *c->g_out = (char *)malloc(3);
                if (*c->g_out) memcpy(*c->g_out, "{}", 3);
            }
        }
    } else if (r == Q_RES_KO) {
        c->v = Q_CH4_KO;
        c->done = 1;
        set_text(c->text, c->textcap, s[0] ? s : "refuse");
    }
out:
    q_secure_zero(clr, strlen(clr));
    free(clr);
}

q_ch4_verdict q_ch4_authenticate(const char *host, int port, const char *nap,
                                 int timeout_s, q_ch4_status_cb cb, void *ud,
                                 char *text, size_t textcap, char **g_out)
{
    ctx_t c;
    unsigned char key[32];
    char kid[33], aad_q[40], aad_r[40], err[160];
    unsigned char *buf = NULL;
    const size_t cap = 4 + Q_CH4_MAX_MSG;
    long long deadline;
    int clicked = 0, retried = 0;

    memset(&c, 0, sizeof c);
    c.cb = cb; c.ud = ud;
    c.text = text; c.textcap = textcap; c.g_out = g_out;
    c.v = Q_CH4_ERR;
    if (g_out) *g_out = NULL;
    set_text(text, textcap, "");

    if (!q_uuid_valid(nap) || q_ch4_derive(nap, kid, key) != 0) {
        set_text(text, textcap, "jeton invalide");
        return Q_CH4_ERR;
    }
    snprintf(aad_q, sizeof aad_q, "ch4q|%s", kid);
    snprintf(aad_r, sizeof aad_r, "ch4r|%s", kid);
    c.key = key;
    c.aad_r = aad_r;
    buf = (unsigned char *)malloc(cap);
    if (!buf) { set_text(text, textcap, "memoire"); goto end; }
    deadline = q_now_ms() + (long long)timeout_s * 1000;

    while (!c.done && q_now_ms() < deadline) {
        q_tls *t;
        char *enc, *first;
        size_t bl = 0;

        t = q_tls_connect(host, port, 10000, err, sizeof err);
        if (!t) {
            dbg("connexion TLS a %s:%d impossible : %s", host, port, err);
            snprintf(text, textcap, "connexion CH4 impossible (%s)", err);
            c.v = Q_CH4_ERR;
            goto end;
        }
        dbg("connexion TLS a %s:%d ok (%s)%s", host, port, q_tls_version(t), retried ? ", reprise" : "");
        /* ouverture : kid (PUBLIC) + G1(i:1) -- le jeton ne circule jamais */
        enc = seal_click(key, aad_q, 1);
        first = enc ? (char *)malloc(32 + strlen(enc) + 1) : NULL;
        if (first) {
            memcpy(first, kid, 32);
            memcpy(first + 32, enc, strlen(enc) + 1);
        }
        free(enc);
        if (!first || send_frame(t, first, strlen(first)) != 0) {
            free(first);
            q_tls_close(t);
            goto lost;
        }
        dbg("envoye : ouverture i:1 (%u octets + en-tete)", (unsigned)strlen(first));
        free(first);

        if (!clicked) {                       /* le clic (i:2) : UNE seule fois */
            /* 500 ms comme la reference bin/test_ch4_g1.dart : un clic arrive
             * trop tot apres l'ouverture peut etre perdu par le serveur (TLP) */
            q_sleep_ms(500);
            enc = seal_click(key, aad_q, 2);
            if (!enc || send_frame(t, enc, strlen(enc)) != 0) { free(enc); q_tls_close(t); goto lost; }
            dbg("envoye : clic i:2 (%u octets + en-tete)", (unsigned)strlen(enc));
            free(enc);
            clicked = 1;
        }

        while (!c.done) {
            long long left = deadline - q_now_ms();
            int n;
            size_t off = 0;
            if (left <= 0) break;
            n = q_tls_recv(t, buf + bl, cap - bl, left > 2000 ? 2000 : (int)left);
            if (n == Q_TIMEOUT) continue;
            if (n <= 0) { dbg(n == 0 ? "fermeture par le serveur" : "erreur de lecture TLS"); break; }
            dbg("recu %d octets", n);
            bl += (size_t)n;
            while (!c.done && bl - off >= 4) {
                uint32_t ln = ((uint32_t)buf[off] << 24) | ((uint32_t)buf[off + 1] << 16) |
                              ((uint32_t)buf[off + 2] << 8) | buf[off + 3];
                if (ln > Q_CH4_MAX_MSG) { dbg("longueur annoncee %u : trame geante, coupure", (unsigned)ln); bl = 0; off = 0; n = -1; break; }
                if (bl - off < 4 + (size_t)ln) break;
                handle_frame(&c, (const char *)buf + off + 4, ln);
                off += 4 + (size_t)ln;
            }
            if (n < 0) break;
            if (off) { memmove(buf, buf + off, bl - off); bl -= off; }
        }
        q_tls_close(t);
lost:
        if (c.done || q_now_ms() >= deadline) break;
        if (retried) break;
        retried = 1;                          /* une seule reprise, avec i:1 seul */
        q_sleep_ms(1000);
    }

    if (!c.done) {
        if (q_now_ms() >= deadline) { c.v = Q_CH4_TIMEOUT; set_text(text, textcap, "aucun vote dans le delai"); }
        else { c.v = Q_CH4_ERR; set_text(text, textcap, "connexion CH4 perdue"); }
    }

end:
    q_secure_zero(key, sizeof key);
    if (buf) { q_secure_zero(buf, cap); free(buf); }
    return c.v;
}
