/* SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 Marc Gandar
 *
 * qovi_codec.c -- base64, hexadecimal, jeton de transaction (sans dependance) */
#include "qovi_codec.h"
#include <limits.h>
#include <string.h>

static const char B64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

size_t q_b64_encoded_len(size_t n)
{
    if (n > (SIZE_MAX / 4) * 3 - 3) return 0;     /* garde anti-debordement */
    return 4 * ((n + 2) / 3);
}

size_t q_b64_encode(const unsigned char *in, size_t n, char *out, size_t cap)
{
    size_t need = q_b64_encoded_len(n), i = 0, o = 0;
    uint32_t v;

    if (cap == 0 || (n > 0 && need == 0) || cap < need + 1) {
        if (cap) out[0] = '\0';
        return 0;
    }
    while (i + 2 < n) {
        v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8) | in[i + 2];
        out[o++] = B64[(v >> 18) & 63];
        out[o++] = B64[(v >> 12) & 63];
        out[o++] = B64[(v >> 6) & 63];
        out[o++] = B64[v & 63];
        i += 3;
    }
    if (i < n) {
        v = (uint32_t)in[i] << 16;
        if (i + 1 < n) v |= (uint32_t)in[i + 1] << 8;
        out[o++] = B64[(v >> 18) & 63];
        out[o++] = B64[(v >> 12) & 63];
        out[o++] = (i + 1 < n) ? B64[(v >> 6) & 63] : '=';
        out[o++] = '=';
    }
    out[o] = '\0';
    return o;
}

static int b64v(unsigned char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

long q_b64_decode(const char *in, size_t n, unsigned char *out, size_t cap)
{
    size_t pad = 0, outlen, i, o = 0;

    if (n % 4 != 0) return -1;
    if (n == 0) return 0;
    if (in[n - 1] == '=') {
        pad = 1;
        if (in[n - 2] == '=') pad = 2;
    }
    outlen = n / 4 * 3 - pad;
    if (outlen > cap || outlen > (size_t)LONG_MAX) return -1;

    for (i = 0; i < n; i += 4) {
        int last = (i + 4 == n), v[4], k;
        uint32_t t;
        size_t take;
        for (k = 0; k < 4; k++) {
            unsigned char ch = (unsigned char)in[i + k];
            if (last && ch == '=' && k >= 4 - (int)pad) {
                v[k] = 0;
            } else {
                v[k] = b64v(ch);
                if (v[k] < 0) return -1;
            }
        }
        t = ((uint32_t)v[0] << 18) | ((uint32_t)v[1] << 12) |
            ((uint32_t)v[2] << 6)  |  (uint32_t)v[3];
        take = last ? 3 - pad : 3;
        if (take >= 1) out[o++] = (unsigned char)(t >> 16);
        if (take >= 2) out[o++] = (unsigned char)(t >> 8);
        if (take >= 3) out[o++] = (unsigned char)t;
    }
    return (long)o;
}

static int hexv(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int q_key_from_uuid(const char *uuid, unsigned char key[16])
{
    size_t got = 0;
    int nib = 0;
    unsigned cur = 0;
    const char *p;

    if (!uuid) return -1;
    for (p = uuid; *p; p++) {
        int v;
        if (*p == '-') continue;
        v = hexv(*p);
        if (v < 0 || got >= 16) { q_secure_zero(key, 16); return -1; }
        cur = (cur << 4) | (unsigned)v;
        if (++nib == 2) {
            key[got++] = (unsigned char)cur;
            cur = 0;
            nib = 0;
        }
    }
    if (got != 16 || nib != 0) { q_secure_zero(key, 16); return -1; }
    return 0;
}

int q_hex_decode(const char *hex, unsigned char *out, size_t cap)
{
    size_t n, i;
    if (!hex) return -1;
    n = strlen(hex);
    if (n == 0 || n % 2 || n / 2 > cap) return -1;
    for (i = 0; i < n; i += 2) {
        int a = hexv(hex[i]), b = hexv(hex[i + 1]);
        if (a < 0 || b < 0) { q_secure_zero(out, i / 2); return -1; }
        out[i / 2] = (unsigned char)((a << 4) | b);
    }
    return (int)(n / 2);
}

void q_hex_encode(const unsigned char *in, size_t n, char *out)
{
    static const char HX[] = "0123456789abcdef";
    size_t i;
    for (i = 0; i < n; i++) {
        out[2 * i]     = HX[in[i] >> 4];
        out[2 * i + 1] = HX[in[i] & 15];
    }
    out[2 * n] = '\0';
}

int q_uuid_valid(const char *uuid)
{
    size_t i, h = 0;
    if (!uuid) return 0;
    for (i = 0; uuid[i]; i++) {
        if (i >= 36) return 0;
        if (uuid[i] == '-') continue;
        if (hexv(uuid[i]) < 0) return 0;
        h++;
    }
    return h == 32;
}

void q_secure_zero(void *p, size_t n)
{
    volatile unsigned char *v = (volatile unsigned char *)p;
    while (n--) *v++ = 0;
}
