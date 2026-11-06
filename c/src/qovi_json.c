/* SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 Marc Gandar */
/* qovi_json.c -- mini JSON borne (validation, recherche par chemin, echappement) */
#include "qovi_json.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_DEPTH 32

static int is_digit(char c) { return c >= '0' && c <= '9'; }
static int is_hex(char c)
{
    return is_digit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

static const char *ws(const char *p)
{
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    return p;
}

/* p sur '"' ; renvoie l'adresse APRES le guillemet fermant, ou NULL */
static const char *skip_string(const char *p)
{
    p++;
    while (*p) {
        unsigned char c = (unsigned char)*p;
        if (c == '"') return p + 1;
        if (c < 0x20) return NULL;                  /* controle brut interdit */
        if (c == '\\') {
            p++;
            switch (*p) {
            case '"': case '\\': case '/': case 'b': case 'f':
            case 'n': case 'r': case 't':
                p++;
                break;
            case 'u':
                if (!is_hex(p[1]) || !is_hex(p[2]) || !is_hex(p[3]) || !is_hex(p[4]))
                    return NULL;
                p += 5;
                break;
            default:
                return NULL;
            }
            continue;
        }
        p++;
    }
    return NULL;
}

static const char *skip_number(const char *p)
{
    if (*p == '-') p++;
    if (*p == '0') p++;
    else if (*p >= '1' && *p <= '9') { while (is_digit(*p)) p++; }
    else return NULL;
    if (*p == '.') {
        p++;
        if (!is_digit(*p)) return NULL;
        while (is_digit(*p)) p++;
    }
    if (*p == 'e' || *p == 'E') {
        p++;
        if (*p == '+' || *p == '-') p++;
        if (!is_digit(*p)) return NULL;
        while (is_digit(*p)) p++;
    }
    return p;
}

static const char *skip_value(const char *p, int depth)
{
    if (depth > MAX_DEPTH) return NULL;            /* pas d'epuisement de pile */
    p = ws(p);
    switch (*p) {
    case '"':
        return skip_string(p);
    case '{':
        p = ws(p + 1);
        if (*p == '}') return p + 1;
        for (;;) {
            if (*p != '"') return NULL;
            p = skip_string(p);
            if (!p) return NULL;
            p = ws(p);
            if (*p != ':') return NULL;
            p = skip_value(p + 1, depth + 1);
            if (!p) return NULL;
            p = ws(p);
            if (*p == ',') { p = ws(p + 1); continue; }
            if (*p == '}') return p + 1;
            return NULL;
        }
    case '[':
        p = ws(p + 1);
        if (*p == ']') return p + 1;
        for (;;) {
            p = skip_value(p, depth + 1);
            if (!p) return NULL;
            p = ws(p);
            if (*p == ',') { p++; continue; }
            if (*p == ']') return p + 1;
            return NULL;
        }
    case 't': return strncmp(p, "true", 4) == 0 ? p + 4 : NULL;
    case 'f': return strncmp(p, "false", 5) == 0 ? p + 5 : NULL;
    case 'n': return strncmp(p, "null", 4) == 0 ? p + 4 : NULL;
    default:
        if (*p == '-' || is_digit(*p)) return skip_number(p);
        return NULL;
    }
}

int q_json_valid(const char *json)
{
    const char *p;
    if (!json) return 0;
    p = skip_value(json, 0);
    if (!p) return 0;
    return *ws(p) == '\0';
}

int q_json_find(const char *json, const char *path, const char **val, size_t *len)
{
    const char *p, *seg = path, *end;

    if (!json || !path || !q_json_valid(json)) return -1;
    p = ws(json);
    while (*seg) {
        const char *dot = strchr(seg, '.');
        size_t sl = dot ? (size_t)(dot - seg) : strlen(seg);
        if (*p != '{') return -1;
        p = ws(p + 1);
        if (*p == '}') return -1;
        for (;;) {
            const char *ks = p + 1, *ke = skip_string(p);
            size_t kl;
            if (!ke) return -1;
            kl = (size_t)(ke - 1 - ks);
            p = ws(ws(ke) + 1);                      /* passe ':' */
            /* premiere occurrence de la cle (cles echappees : jamais egales) */
            if (kl == sl && memcmp(ks, seg, sl) == 0) break;
            p = skip_value(p, 0);
            if (!p) return -1;
            p = ws(p);
            if (*p != ',') return -1;
            p = ws(p + 1);
        }
        seg = dot ? dot + 1 : seg + sl;
    }
    end = skip_value(p, 0);
    if (!end) return -1;
    *val = p;
    *len = (size_t)(end - p);
    return 0;
}

static int put_utf8(unsigned long cp, char *out, size_t cap, size_t *o)
{
    unsigned char b[4];
    size_t n, i;
    if (cp < 0x80)         { b[0] = (unsigned char)cp; n = 1; }
    else if (cp < 0x800)   { b[0] = (unsigned char)(0xC0 | (cp >> 6));
                             b[1] = (unsigned char)(0x80 | (cp & 0x3F)); n = 2; }
    else if (cp < 0x10000) { b[0] = (unsigned char)(0xE0 | (cp >> 12));
                             b[1] = (unsigned char)(0x80 | ((cp >> 6) & 0x3F));
                             b[2] = (unsigned char)(0x80 | (cp & 0x3F)); n = 3; }
    else                   { b[0] = (unsigned char)(0xF0 | (cp >> 18));
                             b[1] = (unsigned char)(0x80 | ((cp >> 12) & 0x3F));
                             b[2] = (unsigned char)(0x80 | ((cp >> 6) & 0x3F));
                             b[3] = (unsigned char)(0x80 | (cp & 0x3F)); n = 4; }
    if (*o + n >= cap) return -1;
    for (i = 0; i < n; i++) out[(*o)++] = (char)b[i];
    return 0;
}

static unsigned long hex4(const char *p)
{
    char t[5];
    memcpy(t, p, 4);
    t[4] = '\0';
    return strtoul(t, NULL, 16);
}

int q_json_get_str(const char *json, const char *path, char *out, size_t cap)
{
    const char *v, *p, *end;
    size_t len, o = 0;

    if (cap == 0 || q_json_find(json, path, &v, &len) != 0 || *v != '"') return -1;
    end = v + len - 1;                               /* guillemet fermant */
    for (p = v + 1; p < end; ) {
        if (*p != '\\') {
            if (o + 1 >= cap) return -1;
            out[o++] = *p++;
            continue;
        }
        p++;
        switch (*p) {
        case '"': case '\\': case '/':
            if (o + 1 >= cap) return -1;
            out[o++] = *p; p++; break;
        case 'b': if (o + 1 >= cap) return -1; out[o++] = '\b'; p++; break;
        case 'f': if (o + 1 >= cap) return -1; out[o++] = '\f'; p++; break;
        case 'n': if (o + 1 >= cap) return -1; out[o++] = '\n'; p++; break;
        case 'r': if (o + 1 >= cap) return -1; out[o++] = '\r'; p++; break;
        case 't': if (o + 1 >= cap) return -1; out[o++] = '\t'; p++; break;
        case 'u': {
            unsigned long cp = hex4(p + 1);
            p += 5;
            if (cp >= 0xD800 && cp <= 0xDBFF) {        /* paire de substitution */
                unsigned long lo;
                if (p + 6 > end || p[0] != '\\' || p[1] != 'u') return -1;
                lo = hex4(p + 2);
                if (lo < 0xDC00 || lo > 0xDFFF) return -1;
                cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                p += 6;
            } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
                return -1;
            }
            if (cp == 0) return -1;                    /* NUL interdit */
            if (put_utf8(cp, out, cap, &o) != 0) return -1;
            break;
        }
        default:
            return -1;
        }
    }
    out[o] = '\0';
    return 0;
}

int q_json_get_int(const char *json, const char *path, long *out)
{
    const char *v;
    size_t len, i;
    char tmp[24];
    char *end;
    long x;

    if (q_json_find(json, path, &v, &len) != 0 || len == 0 || len >= sizeof tmp) return -1;
    for (i = 0; i < len; i++)
        if (!(is_digit(v[i]) || (i == 0 && v[i] == '-'))) return -1;
    memcpy(tmp, v, len);
    tmp[len] = '\0';
    errno = 0;
    x = strtol(tmp, &end, 10);
    if (errno != 0 || *end != '\0') return -1;
    *out = x;
    return 0;
}

int q_json_is_true(const char *json, const char *path)
{
    const char *v;
    size_t len;
    return q_json_find(json, path, &v, &len) == 0 && len == 4 && memcmp(v, "true", 4) == 0;
}

int q_utf8_valid(const char *s, size_t n)
{
    const unsigned char *p = (const unsigned char *)s;
    size_t i = 0;
    while (i < n) {
        unsigned char c = p[i];
        size_t k, need;
        unsigned long cp;
        if (c < 0x80) { i++; continue; }
        if (c >= 0xC2 && c <= 0xDF)      { need = 1; cp = c & 0x1F; }
        else if (c >= 0xE0 && c <= 0xEF) { need = 2; cp = c & 0x0F; }
        else if (c >= 0xF0 && c <= 0xF4) { need = 3; cp = c & 0x07; }
        else return 0;
        if (need >= n - i) return 0;                 /* sequence tronquee */
        for (k = 1; k <= need; k++) {
            if ((p[i + k] & 0xC0) != 0x80) return 0;
            cp = (cp << 6) | (p[i + k] & 0x3F);
        }
        if ((need == 2 && cp < 0x800) || (need == 3 && cp < 0x10000)) return 0;  /* surlongueur */
        if (cp >= 0xD800 && cp <= 0xDFFF) return 0;                              /* surrogate */
        if (cp > 0x10FFFF) return 0;
        i += need + 1;
    }
    return 1;
}

char *q_json_quote(const char *s)
{
    size_t n, i, o = 0;
    char *out;

    if (!s) return NULL;
    n = strlen(s);
    if (n > 1024 * 1024 || !q_utf8_valid(s, n)) return NULL;
    out = (char *)malloc(n * 6 + 3);
    if (!out) return NULL;
    out[o++] = '"';
    for (i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        switch (c) {
        case '"':  out[o++] = '\\'; out[o++] = '"';  break;
        case '\\': out[o++] = '\\'; out[o++] = '\\'; break;
        case '\b': out[o++] = '\\'; out[o++] = 'b';  break;
        case '\f': out[o++] = '\\'; out[o++] = 'f';  break;
        case '\n': out[o++] = '\\'; out[o++] = 'n';  break;
        case '\r': out[o++] = '\\'; out[o++] = 'r';  break;
        case '\t': out[o++] = '\\'; out[o++] = 't';  break;
        default:
            if (c < 0x20 || c == 0x7F) {
                snprintf(out + o, 7, "\\u%04x", c);
                o += 6;
            } else {
                out[o++] = (char)c;
            }
        }
    }
    out[o++] = '"';
    out[o] = '\0';
    return out;
}
