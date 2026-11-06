/* SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 Marc Gandar
 *
 * qovi_conf.c -- lecture stricte de qovi-tui.conf */
#include "qovi_conf.h"
#include "qovi_codec.h"
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
  #include <sys/stat.h>
#endif

#define LINE_MAX_LEN 600

static char *trim(char *s)
{
    char *e;
    while (*s && isspace((unsigned char)*s)) s++;
    e = s + strlen(s);
    while (e > s && isspace((unsigned char)e[-1])) *--e = '\0';
    return s;
}

static int copy_val(char *dst, size_t cap, const char *v)
{
    size_t n = strlen(v);
    if (n >= cap) return -1;
    memcpy(dst, v, n + 1);
    return 0;
}

static int parse_int(const char *v, int lo, int hi, int *out)
{
    char *end;
    long x;
    errno = 0;
    x = strtol(v, &end, 10);
    if (errno != 0 || end == v || *end != '\0' || x < lo || x > hi) return -1;
    *out = (int)x;
    return 0;
}

/* 64 hexa ; recopie en minuscules (forme signee par le serveur) */
static int norm_hex64(char *s)
{
    size_t i;
    for (i = 0; s[i]; i++) {
        if (!isxdigit((unsigned char)s[i])) return -1;
        s[i] = (char)tolower((unsigned char)s[i]);
    }
    return i == 64 ? 0 : -1;
}

int q_conf_load(const char *path, q_conf *c, char *err, size_t errcap)
{
    FILE *f;
    char line[LINE_MAX_LEN];
    const char *env;
    int lineno = 0, rc = -1;

    memset(c, 0, sizeof *c);
    snprintf(c->api_url, sizeof c->api_url, "https://qovi.ch/RST");
    c->ch4_port = 6404;
    c->port = 7777;
    c->vote_timeout = 120;
    if (errcap) err[0] = '\0';
    if (!path || !*path) path = Q_DEFAULT_CONF;

    f = fopen(path, "r");
    if (!f && errno != ENOENT) {
        snprintf(err, errcap, "%s illisible (droits ?)", path);
        return -1;
    }
    while (f && fgets(line, sizeof line, f)) {
        char *s, *eq, *k, *v;
        int bad = 0;
        lineno++;
        if (!strchr(line, '\n') && !feof(f)) {
            snprintf(err, errcap, "%s ligne %d trop longue", path, lineno);
            goto out;
        }
        s = trim(line);
        if (*s == '\0' || *s == '#') continue;
        eq = strchr(s, '=');
        if (!eq) { snprintf(err, errcap, "%s ligne %d : '=' manquant", path, lineno); goto out; }
        *eq = '\0';
        k = trim(s);
        v = trim(eq + 1);

        if      (!strcmp(k, "prv_us"))   bad = copy_val(c->prv_us, sizeof c->prv_us, v);
        else if (!strcmp(k, "api_url"))  bad = copy_val(c->api_url, sizeof c->api_url, v);
        else if (!strcmp(k, "ch4_port")) bad = parse_int(v, 1, 65535, &c->ch4_port);
        else if (!strcmp(k, "port"))     bad = parse_int(v, 1, 65535, &c->port);
        else if (!strcmp(k, "timeout"))  bad = parse_int(v, 10, 600, &c->vote_timeout);
        else if (!strcmp(k, "log_file")) bad = copy_val(c->log_file, sizeof c->log_file, v);
        else if (!strcmp(k, "ca_file"))  bad = copy_val(c->ca_file, sizeof c->ca_file, v);
        else {
            /* une faute de frappe ne doit pas passer silencieusement */
            snprintf(err, errcap, "%s ligne %d : cle inconnue '%.40s'", path, lineno, k);
            goto out;
        }
        if (bad) { snprintf(err, errcap, "%s ligne %d : valeur invalide pour %s", path, lineno, k); goto out; }
    }

    env = getenv("QOVI_PRV_US");
    if (env && *env && copy_val(c->prv_us, sizeof c->prv_us, env) != 0) {
        snprintf(err, errcap, "QOVI_PRV_US invalide");
        goto out;
    }
    env = getenv("QOVI_API_URL");
    if (env && *env && copy_val(c->api_url, sizeof c->api_url, env) != 0) {
        snprintf(err, errcap, "QOVI_API_URL trop longue");
        goto out;
    }
    if (c->vote_timeout > 130) c->vote_timeout = 130;          /* plafond, comme le Python */

    if (strncmp(c->api_url, "https://", 8) != 0) {
        snprintf(err, errcap, "api_url doit commencer par https://");
        goto out;
    }
    if (c->prv_us[0] == '\0' || !strncmp(c->prv_us, "COLLEZ", 6)) {
        snprintf(err, errcap, "cle privee du site non renseignee (prv_us dans %s, ou QOVI_PRV_US)", path);
        goto out;
    }
    if (norm_hex64(c->prv_us) != 0) {
        snprintf(err, errcap, "prv_us doit faire 64 caracteres hexadecimaux");
        goto out;
    }
    rc = 0;

out:
    q_secure_zero(line, sizeof line);   /* la ligne a pu contenir la cle privee */
    if (f) fclose(f);
    if (rc != 0) q_conf_wipe(c);
    return rc;
}

void q_conf_wipe(q_conf *c)
{
    q_secure_zero(c->prv_us, sizeof c->prv_us);
}

int q_conf_too_open(const char *path, char *msg, size_t cap)
{
#ifdef _WIN32
    (void)path;
    if (cap) msg[0] = '\0';
    return 0;
#else
    struct stat st;
    if (cap) msg[0] = '\0';
    if (!path || stat(path, &st) != 0) return 0;
    if (st.st_mode & 077) {
        snprintf(msg, cap, "%s est lisible par d'autres utilisateurs : faites  chmod 600 %s", path, path);
        return 1;
    }
    return 0;
#endif
}
