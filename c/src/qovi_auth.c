/* SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 Marc Gandar
 *
 * qovi_auth.c -- coeur de TuI (port de authenticate() de python/_tuip.py) */
#include "qovi_auth.h"
#include "compat.h"
#include "qovi_ch4.h"
#include "qovi_codec.h"
#include "qovi_json.h"
#include "qovi_rest.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define REST_TIMEOUT_MS 15000

const char *q_auth_res_name(q_auth_res r)
{
    switch (r) {
    case Q_AUTH_GO:      return "go";
    case Q_AUTH_KO:      return "ko";
    case Q_AUTH_TIMEOUT: return "timeout";
    default:             return "error";
    }
}

static int is_ctrl(unsigned char c) { return c < 0x20 || c == 0x7F; }
static int is_alpha(char c) { return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'); }
static int is_dom(char c) { return is_alpha(c) || (c >= '0' && c <= '9') || c == '.' || c == '-'; }

/* ^[^@\s"<>|]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,63}$  (comme _tuip.py) */
int q_auth_edr_ok(const char *edr)
{
    const char *at, *dot, *p;
    size_t ll, dl, tl;

    if (!edr || strlen(edr) > Q_EDR_MAX || !q_utf8_valid(edr, strlen(edr))) return 0;
    at = strchr(edr, '@');
    if (!at || strchr(at + 1, '@')) return 0;
    ll = (size_t)(at - edr);
    if (ll < 1 || ll > 64) return 0;
    for (p = edr; p < at; p++) {
        unsigned char c = (unsigned char)*p;
        if (is_ctrl(c) || c == ' ' || c == '"' || c == '<' || c == '>' || c == '|') return 0;
    }
    for (p = at + 1; *p; p++) if (!is_dom(*p)) return 0;
    dot = strrchr(at + 1, '.');
    if (!dot) return 0;
    dl = (size_t)(dot - (at + 1));
    tl = strlen(dot + 1);
    if (dl < 1 || dl > 253 || tl < 2 || tl > 63) return 0;
    for (p = dot + 1; *p; p++) if (!is_alpha(*p)) return 0;
    return 1;
}

int q_auth_subj_ok(const char *subj)
{
    size_t n, i;
    if (!subj) return 1;
    n = strlen(subj);
    if (n > Q_SUBJ_MAX || !q_utf8_valid(subj, n)) return 0;
    for (i = 0; i < n; i++) if (is_ctrl((unsigned char)subj[i])) return 0;
    return 1;
}

int q_auth_subj_ml_ok(const char *subj)
{
    size_t n, i;
    int lines = 1;
    if (!subj) return 1;
    n = strlen(subj);
    if (n > Q_SUBJ_MAX || !q_utf8_valid(subj, n)) return 0;
    for (i = 0; i < n; i++) {
        unsigned char ch = (unsigned char)subj[i];
        if (ch == '\r') { if (subj[i + 1] != '\n') return 0; continue; }
        if (ch == '\n') { if (++lines > Q_SUBJ_LINES) return 0; continue; }
        if (is_ctrl(ch)) return 0;
    }
    return 1;
}

/* comparaison insensible a la casse ASCII (comme .lower() sur une adresse) */
static int ascii_ieq(const char *a, const char *b)
{
    for (; *a && *b; a++, b++) {
        char x = (*a >= 'A' && *a <= 'Z') ? (char)(*a + 32) : *a;
        char y = (*b >= 'A' && *b <= 'Z') ? (char)(*b + 32) : *b;
        if (x != y) return 0;
    }
    return *a == *b;
}

/* "https://qovi.ch/RST" -> "qovi.ch" */
static int host_of(const char *url, char *out, size_t cap)
{
    char path[256];
    int port;
    return q_url_split(url, out, cap, &port, path, sizeof path);
}

/* texte sur une ligne, caracteres de controle neutralises */
static q_auth_res done(char *text, size_t cap, q_auth_res r, const char *t)
{
    size_t i;
    if (!cap) return r;
    snprintf(text, cap, "%s", t ? t : "");
    for (i = 0; text[i]; i++)
        if (is_ctrl((unsigned char)text[i])) text[i] = ' ';
    return r;
}

typedef struct { q_auth_event_cb cb; void *ud; int last; } wait_t;

static void on_ch4(int r, const char *s, void *ud)
{
    wait_t *w = (wait_t *)ud;
    if (w->cb && r != w->last) w->cb("wait", s, w->ud);    /* sans repetition */
    w->last = r;
}

q_auth_res q_authenticate(const q_conf *c, const char *edr, const char *subj,
                          q_auth_event_cb cb, void *ud, char *text, size_t cap)
{
    char nap[40], msg[300], host[256], edr_ok[Q_EDR_MAX + 2], gotxt[300], e[340];
    char *g = NULL;
    long long t0 = q_now_ms(), left;
    q_ch4_verdict v;
    q_rest_rc rc;
    wait_t w;
    int vote_s;

    if (!q_auth_edr_ok(edr)) return done(text, cap, Q_AUTH_KO, "adresse invalide");
    if (!q_auth_subj_ml_ok(subj)) return done(text, cap, Q_AUTH_KO, "raison invalide");
    if (!subj) subj = "";
    if (host_of(c->api_url, host, sizeof host) != 0) return done(text, cap, Q_AUTH_ERR, "api_url invalide");

    /* 1. SiT_1_Edr -> jeton */
    rc = q_rest_sit_1_edr(c, edr, subj, nap, sizeof nap, msg, sizeof msg, REST_TIMEOUT_MS);
    if (rc == Q_R_KO) return done(text, cap, Q_AUTH_KO, msg);
    if (rc == Q_R_REFUSED || rc == Q_R_NET) {      /* rappelle le serveur interroge */
        char e1[300];
        snprintf(e1, sizeof e1, "%s (serveur %s%s)", q_rest_rc_text(rc), c->api_url,
                 strncmp(c->api_url, "https://qovi.ch/", 16) == 0 ? ", production" : "");
        return done(text, cap, Q_AUTH_ERR, e1);
    }
    if (rc != Q_R_OK) return done(text, cap, Q_AUTH_ERR, q_rest_rc_text(rc));
    if (cb) cb("sent", "", ud);

    /* 2. CH4 -> vote mobile, dans le budget (marge gardee pour l'etape 3) */
    left = Q_AUTH_BUDGET_MS - (q_now_ms() - t0) - REST_TIMEOUT_MS;
    vote_s = (int)(left / 1000);
    if (vote_s > c->vote_timeout) vote_s = c->vote_timeout;
    if (vote_s < 5) vote_s = 5;
    w.cb = cb; w.ud = ud; w.last = 0;
    v = q_ch4_authenticate(host, c->ch4_port, nap, vote_s, on_ch4, &w, msg, sizeof msg, &g);
    if (v != Q_CH4_GO) {
        free(g);
        q_secure_zero(nap, sizeof nap);
        if (v == Q_CH4_KO)      return done(text, cap, Q_AUTH_KO, msg);
        if (v == Q_CH4_TIMEOUT) return done(text, cap, Q_AUTH_TIMEOUT, msg);
        return done(text, cap, Q_AUTH_ERR, msg);
    }
    snprintf(gotxt, sizeof gotxt, "%s", msg);

    /* 3. SiT_3_End -> SEULE preuve qui compte */
    left = Q_AUTH_BUDGET_MS - (q_now_ms() - t0);
    if (left > REST_TIMEOUT_MS) left = REST_TIMEOUT_MS;
    if (left < 1000) left = 1000;
    rc = q_rest_sit_3_end(c, g, nap, edr, edr_ok, sizeof edr_ok, (int)left);
    free(g);
    q_secure_zero(nap, sizeof nap);
    if (rc == Q_R_OK && ascii_ieq(edr_ok, edr)) return done(text, cap, Q_AUTH_GO, gotxt);
    if (rc == Q_R_OK || rc == Q_R_KO) return done(text, cap, Q_AUTH_KO, "fin de login refusee");
    snprintf(e, sizeof e, "confirmation impossible (%s)", q_rest_rc_text(rc));
    return done(text, cap, Q_AUTH_ERR, e);
}
