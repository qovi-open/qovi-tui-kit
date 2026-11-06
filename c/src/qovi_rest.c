/* SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 Marc Gandar
 *
 * qovi_rest.c -- SiT_1_Edr / SiT_3_End signes (port de python/qovi_rest.py),
 * sur un HTTPS minimal (HTTP/1.1, Connection: close) au-dessus de qovi_tls. */
#include "qovi_rest.h"
#include "compat.h"
#include "qovi_codec.h"
#include "qovi_crypto.h"
#include "qovi_json.h"
#include "qovi_tls.h"
#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define REST_MAX_RESP (256 * 1024)          /* corps maximal accepte            */
#define REST_MAX_RAW  (REST_MAX_RESP + 16384) /* + en-tetes HTTP                 */
#define REST_MAX_REQ  (64 * 1024)           /* x_j maximal                      */

const char *q_rest_rc_text(q_rest_rc rc)
{
    switch (rc) {
    case Q_R_OK:      return "ok";
    case Q_R_KO:      return "refus";
    case Q_R_KEY:     return "cle du site absente ou mal formee";
    case Q_R_NET:     return "Qovi injoignable";
    case Q_R_REFUSED: return "cle du site refusee par Qovi";
    case Q_R_SIG:     return "reponse de Qovi falsifiee";
    default:          return "reponse de Qovi illisible";
    }
}

/* concatene des morceaux (NULL final) dans une chaine allouee */
static char *join(const char *first, ...)
{
    va_list ap;
    size_t n = 0;
    const char *p;
    char *out, *o;

    va_start(ap, first);
    for (p = first; p; p = va_arg(ap, const char *)) n += strlen(p);
    va_end(ap);
    out = (char *)malloc(n + 1);
    if (!out) return NULL;
    o = out;
    va_start(ap, first);
    for (p = first; p; p = va_arg(ap, const char *)) {
        size_t l = strlen(p);
        memcpy(o, p, l);
        o += l;
    }
    va_end(ap);
    *o = '\0';
    return out;
}

static void free_secret(char *s)
{
    if (s) { q_secure_zero(s, strlen(s)); free(s); }
}

/* ------------------------------------------------------------- signature */

static int prv_bytes(const char *prv_hex, unsigned char key[32])
{
    if (!prv_hex || strlen(prv_hex) != 64) return -1;
    return q_hex_decode(prv_hex, key, 32) == 32 ? 0 : -1;
}

int q_rest_sit_pub(const char *prv_hex, char k[65])
{
    char *m;
    int rc;
    if (!prv_hex || strlen(prv_hex) != 64) return -1;
    m = join("qovi-sit-pub-v1:", prv_hex, (const char *)NULL);
    if (!m) return -1;
    rc = q_sha256_hex(m, strlen(m), k);
    free_secret(m);
    return rc;
}

int q_rest_sign(const char *prv_hex, const char *proc, const char *k, long long t,
                const char *n, const char *p, char s[65])
{
    unsigned char key[32], mac[32];
    char ts[24], hp[65], *m;
    int rc = -1;

    if (prv_bytes(prv_hex, key) != 0) return -1;
    snprintf(ts, sizeof ts, "%lld", t);
    if (q_sha256_hex(p, strlen(p), hp) == 0 &&
        (m = join("qovi-sit-v1\n", proc, "\n", k, "\n", ts, "\n", n, "\n", hp, (const char *)NULL)) != NULL) {
        if (q_hmac_sha256(key, 32, m, strlen(m), mac) == 0) {
            q_hex_encode(mac, 32, s);
            rc = 0;
        }
        free(m);
    }
    q_secure_zero(key, sizeof key);
    return rc;
}

int q_rest_verify(const char *prv_hex, const char *proc, const char *n,
                  const char *p, const char *s)
{
    unsigned char key[32], mac[32];
    char hp[65], exp[65], low[65], *m;
    size_t i;
    int ok = 0;

    if (!s || strlen(s) != 64) return 0;
    for (i = 0; i < 64; i++) low[i] = (char)tolower((unsigned char)s[i]);
    low[64] = '\0';
    if (prv_bytes(prv_hex, key) != 0) return 0;
    if (q_sha256_hex(p, strlen(p), hp) == 0 &&
        (m = join("qovi-pub-v1\n", proc, "\n", n, "\n", hp, (const char *)NULL)) != NULL) {
        if (q_hmac_sha256(key, 32, m, strlen(m), mac) == 0) {
            q_hex_encode(mac, 32, exp);
            ok = q_ct_equal(exp, low, 64);
        }
        free(m);
    }
    q_secure_zero(key, sizeof key);
    return ok;
}

/* ------------------------------------------------------------------ HTTP */

int q_url_split(const char *url, char *host, size_t hcap, int *port, char *path, size_t pcap)
{
    const char *p, *h;
    size_t hl = 0, pl;

    if (!url || strncmp(url, "https://", 8) != 0) return -1;
    h = url + 8;
    while (h[hl] && h[hl] != '/' && h[hl] != ':') {
        char ch = h[hl];
        /* nom d'hote simple : aucun caractere qui casserait l'en-tete Host */
        if (!(isalnum((unsigned char)ch) || ch == '.' || ch == '-')) return -1;
        hl++;
    }
    if (hl == 0 || hl >= hcap) return -1;
    memcpy(host, h, hl);
    host[hl] = '\0';
    p = h + hl;
    *port = 443;
    if (*p == ':') {
        char *end;
        long v = strtol(p + 1, &end, 10);
        if (end == p + 1 || v < 1 || v > 65535) return -1;
        *port = (int)v;
        p = end;
    }
    if (*p && *p != '/') return -1;
    pl = strlen(p);
    while (pl > 0 && p[pl - 1] == '/') pl--;
    if (pl >= pcap) return -1;
    for (hl = 0; hl < pl; hl++)
        if ((unsigned char)p[hl] <= 0x20 || (unsigned char)p[hl] >= 0x7F) return -1;
    memcpy(path, p, pl);
    path[pl] = '\0';
    return 0;
}

static const char *find_hdr_end(const char *raw, size_t n)
{
    size_t i;
    for (i = 0; i + 3 < n; i++)
        if (raw[i] == '\r' && raw[i + 1] == '\n' && raw[i + 2] == '\r' && raw[i + 3] == '\n')
            return raw + i;
    return NULL;
}

static int hdr_is(const char *line, size_t ll, const char *name)
{
    size_t nl = strlen(name), i;
    if (ll <= nl || line[nl] != ':') return 0;
    for (i = 0; i < nl; i++)
        if (tolower((unsigned char)line[i]) != name[i]) return 0;
    return 1;
}

/* en-tetes : statut, longueur (-1 si absente), chunked. 0 = ok */
static int parse_head(const char *raw, const char *he, int *status, long *clen, int *chunked)
{
    const char *p = raw, *eol;
    *clen = -1;
    *chunked = 0;
    if (he - raw < 12 || strncmp(raw, "HTTP/1.", 7) != 0 || raw[8] != ' ') return -1;
    if (!isdigit((unsigned char)raw[9]) || !isdigit((unsigned char)raw[10]) || !isdigit((unsigned char)raw[11]))
        return -1;
    *status = (raw[9] - '0') * 100 + (raw[10] - '0') * 10 + (raw[11] - '0');
    for (;;) {
        size_t ll;
        eol = strstr(p, "\r\n");
        if (!eol || eol > he) break;
        ll = (size_t)(eol - p);
        if (hdr_is(p, ll, "content-length")) {
            const char *v = p + 15;
            long x = 0;
            while (*v == ' ' || *v == '\t') v++;
            if (!isdigit((unsigned char)*v)) return -1;
            while (isdigit((unsigned char)*v)) {
                if (x > REST_MAX_RAW) return -1;
                x = x * 10 + (*v - '0');
                v++;
            }
            *clen = x;
        } else if (hdr_is(p, ll, "transfer-encoding")) {
            size_t i;
            for (i = 18; i + 7 <= ll; i++)
                if (strncmp(p + i, "chunked", 7) == 0) *chunked = 1;
        }
        if (eol == he) break;
        p = eol + 2;
    }
    return 0;
}

/* Dechunke src[0..n) dans dst (dst <= src permis). Longueur, ou -1 si
 * incomplet ou invalide. */
static long dechunk(const char *src, size_t n, char *dst)
{
    size_t i = 0, o = 0;
    for (;;) {
        unsigned long sz = 0;
        int digits = 0;
        while (i < n && isxdigit((unsigned char)src[i])) {
            int v = isdigit((unsigned char)src[i]) ? src[i] - '0' : (tolower((unsigned char)src[i]) - 'a' + 10);
            if (sz > REST_MAX_RAW) return -1;
            sz = sz * 16 + (unsigned long)v;
            i++; digits++;
        }
        if (!digits) return -1;
        while (i < n && src[i] != '\r') i++;           /* extensions ignorees */
        if (i + 1 >= n || src[i + 1] != '\n') return -1;
        i += 2;
        if (sz == 0) return (long)o;
        if (i + sz + 2 > n) return -1;
        if (dst) memmove(dst + o, src + i, sz);
        o += sz;
        i += sz;
        if (src[i] != '\r' || src[i + 1] != '\n') return -1;
        i += 2;
    }
}

int q_http_parse(char *raw, size_t n, int *status, char **body, size_t *blen)
{
    const char *he = find_hdr_end(raw, n);
    long clen;
    int chunked;
    size_t off, avail;

    if (!he || parse_head(raw, he, status, &clen, &chunked) != 0) return -1;
    off = (size_t)(he - raw) + 4;
    avail = n - off;
    *body = raw + off;
    if (chunked) {
        long l = dechunk(raw + off, avail, raw + off);
        if (l < 0) return -1;
        *blen = (size_t)l;
    } else if (clen >= 0) {
        if ((size_t)clen > avail) return -1;
        *blen = (size_t)clen;
    } else {
        *blen = avail;                                  /* jusqu'a la fermeture */
    }
    return 0;
}

/* 1 si la reponse est complete (longueur ou dernier morceau atteints) */
static int http_complete(const char *raw, size_t n)
{
    const char *he = find_hdr_end(raw, n);
    long clen;
    int chunked, st;
    size_t off;
    if (!he || parse_head(raw, he, &st, &clen, &chunked) != 0) return 0;
    off = (size_t)(he - raw) + 4;
    if (chunked) return dechunk(raw + off, n - off, NULL) >= 0;
    if (clen >= 0) return n - off >= (size_t)clen;
    return 0;
}

/* (04.11) trace QOVI_TUI_DEBUG=1 : etapes de l'appel HTTPS (jamais le contenu) */
static void rdbg(const char *fmt, ...)
{
    const char *e = getenv("QOVI_TUI_DEBUG");
    va_list ap;
    if (!e || e[0] != '1') return;
    va_start(ap, fmt);
    fprintf(stderr, "[rest] ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
}

/* POST JSON ; *raw recoit la reponse brute (NUL final). Q_R_OK ou Q_R_NET */
static q_rest_rc https_post(const char *api_url, const char *proc, const char *body,
                            char **raw, size_t *rawlen, int timeout_ms)
{
    char host[256], path[256], hostport[300], cl[24];
    char *req = NULL, *buf = NULL, err[160];
    int port, r;
    size_t n = 0;
    long long deadline = q_now_ms() + timeout_ms;
    q_tls *t = NULL;
    q_rest_rc rc = Q_R_NET;

    *raw = NULL;
    *rawlen = 0;
    if (q_url_split(api_url, host, sizeof host, &port, path, sizeof path) != 0) return Q_R_NET;
    if (port == 443) snprintf(hostport, sizeof hostport, "%s", host);
    else             snprintf(hostport, sizeof hostport, "%s:%d", host, port);
    snprintf(cl, sizeof cl, "%u", (unsigned)strlen(body));
    req = join("POST ", path, "/", proc, " HTTP/1.1\r\nHost: ", hostport,
               "\r\nContent-Type: application/json\r\nContent-Length: ", cl,
               "\r\nUser-Agent: Qovi_Kit_TuI\r\nConnection: close\r\n\r\n", body, (const char *)NULL);
    buf = (char *)malloc(REST_MAX_RAW + 1);
    if (!req || !buf) goto end;

    t = q_tls_connect(host, port, timeout_ms < 10000 ? timeout_ms : 10000, err, sizeof err);
    if (!t) { rdbg("%s : connexion TLS a %s:%d impossible : %s", proc, host, port, err); goto end; }
    if (q_tls_send(t, req, strlen(req)) != 0) { rdbg("%s : envoi impossible", proc); goto end; }
    rdbg("%s : requete envoyee (%u octets de corps), attente %d ms au plus", proc, (unsigned)strlen(body), timeout_ms);
    for (;;) {
        long long left = deadline - q_now_ms();
        if (left <= 0) { rdbg("%s : DELAI DEPASSE apres %u octets recus", proc, (unsigned)n); goto end; }
        if (n >= REST_MAX_RAW) { rdbg("%s : reponse trop longue", proc); goto end; }
        r = q_tls_recv(t, buf + n, REST_MAX_RAW - n, (int)left);
        if (r == Q_TIMEOUT) continue;
        if (r < 0) { rdbg("%s : ERREUR de lecture TLS apres %u octets recus", proc, (unsigned)n); goto end; }
        if (r == 0) { rdbg("%s : fermeture par le serveur apres %u octets", proc, (unsigned)n); break; }
        n += (size_t)r;
        buf[n] = '\0';
        if (http_complete(buf, n)) break;
    }
    {   int st = 0; const char *sp = strchr(buf, ' ');
        if (sp) st = atoi(sp + 1);
        rdbg("%s : reponse HTTP %d, %u octets", proc, st, (unsigned)n); }
    buf[n] = '\0';
    *raw = buf;
    *rawlen = n;
    buf = NULL;
    rc = Q_R_OK;

end:
    q_tls_close(t);
    free(req);
    if (buf) { q_secure_zero(buf, n); free(buf); }
    return rc;
}

/* Appel signe complet : x_json -> d_json verifie (alloue). */
static q_rest_rc rest_call(const q_conf *c, const char *proc, const char *x_json,
                           char **d_json, int timeout_ms)
{
    char k[65], nonce_hex[33], s[65];
    unsigned char nb[16];
    char *p = NULL, *body = NULL, *raw = NULL, *rp = NULL, *rs = NULL, *rbody;
    unsigned char *dec = NULL;
    size_t xl, pl, rawlen = 0, blen = 0;
    long dl;
    int status = 0;
    long long t;
    q_rest_rc rc;
    char ts[24];
    const char *v;
    size_t vl;

    *d_json = NULL;
    if (!c->prv_us[0] || strlen(c->prv_us) != 64) return Q_R_KEY;
    xl = strlen(x_json);
    if (xl == 0 || xl > REST_MAX_REQ) return Q_R_BAD;

    pl = q_b64_encoded_len(xl);
    p = (char *)malloc(pl + 1);
    if (!p || q_b64_encode((const unsigned char *)x_json, xl, p, pl + 1) != pl) { rc = Q_R_BAD; goto end; }
    if (q_rest_sit_pub(c->prv_us, k) != 0) { rc = Q_R_KEY; goto end; }
    if (q_random(nb, sizeof nb) != 0) { rc = Q_R_BAD; goto end; }
    q_hex_encode(nb, sizeof nb, nonce_hex);
    t = q_unix_time();
    if (q_rest_sign(c->prv_us, proc, k, t, nonce_hex, p, s) != 0) { rc = Q_R_KEY; goto end; }
    snprintf(ts, sizeof ts, "%lld", t);
    /* k, n, s : hexa ; p : base64 -- aucun echappement necessaire */
    body = join("{\"v\":1,\"k\":\"", k, "\",\"t\":", ts, ",\"n\":\"", nonce_hex,
                "\",\"p\":\"", p, "\",\"s\":\"", s, "\"}", (const char *)NULL);
    if (!body) { rc = Q_R_BAD; goto end; }

    rc = https_post(c->api_url, proc, body, &raw, &rawlen, timeout_ms);
    if (rc != Q_R_OK) goto end;

    /* refus : le corps n'est pas signe -> REFUSED, comme le Python */
    rc = Q_R_REFUSED;
    if (q_http_parse(raw, rawlen, &status, &rbody, &blen) != 0) goto end;
    rbody[blen] = '\0';
    if (memchr(rbody, '\0', blen) || !q_json_valid(rbody)) goto end;
    if (q_json_find(rbody, "p", &v, &vl) != 0 || *v != '"') goto end;
    rp = (char *)malloc(vl + 1);
    rs = (char *)malloc(80);
    if (!rp || !rs) { rc = Q_R_BAD; goto end; }
    if (q_json_get_str(rbody, "p", rp, vl + 1) != 0 || q_json_get_str(rbody, "s", rs, 80) != 0) goto end;

    if (!q_rest_verify(c->prv_us, proc, nonce_hex, rp, rs)) { rc = Q_R_SIG; goto end; }

    rc = Q_R_BAD;
    dec = (unsigned char *)malloc(strlen(rp) + 1);
    if (!dec) goto end;
    dl = q_b64_decode(rp, strlen(rp), dec, strlen(rp));
    if (dl < 2 || memchr(dec, '\0', (size_t)dl)) goto end;
    dec[dl] = '\0';
    {
        const char *q = (const char *)dec;
        while (*q == ' ' || *q == '\t' || *q == '\r' || *q == '\n') q++;
        if (*q != '{' || !q_json_valid((const char *)dec)) goto end;
    }
    *d_json = (char *)dec;
    dec = NULL;
    rc = Q_R_OK;

end:
    if (raw) { q_secure_zero(raw, rawlen); free(raw); }
    free_secret(body);
    free_secret(p);
    free_secret(rp);
    free(rs);
    if (dec) free_secret((char *)dec);
    q_secure_zero(nb, sizeof nb);
    return rc;
}

q_rest_rc q_rest_sit_1_edr(const q_conf *c, const char *edr, const char *subj,
                           char *nap, size_t napcap, char *msg, size_t msgcap, int timeout_ms)
{
    char guid[40], utc[32], tmp[64];
    char *qe = NULL, *qs = NULL, *x = NULL, *d = NULL;
    q_rest_rc rc;

    if (msgcap) msg[0] = '\0';
    if (napcap) nap[0] = '\0';
    if (q_uuid4(guid, sizeof guid) != 0 || q_utc_iso_ms(utc, sizeof utc) != 0) return Q_R_BAD;
    /* email et sujet passent par q_json_quote : pas d'injection de champ */
    qe = q_json_quote(edr);
    qs = q_json_quote(subj ? subj : "");
    if (qe && qs)
        x = join("{\"c\":{\"Key\":{\"U\":\"" QOVI_KEY_LOGIN_US "\"}},\"g\":{\"k\":[1,1,1],\"u\":\"", guid,
                 "\",\"p\":{\"e\":", qe, ",\"r\":", qs, "},\"h\":\"TuI\",\"t\":[\"", utc, "\",\"", utc,
                 "\"]}}", (const char *)NULL);
    free(qe);
    free(qs);
    if (!x) return Q_R_BAD;

    rc = rest_call(c, "SiT_1_Edr", x, &d, timeout_ms);
    free(x);
    if (rc != Q_R_OK) return rc;

    if (q_json_get_str(d, "a.ChX.Prv.u", tmp, sizeof tmp) == 0 && q_uuid_valid(tmp) && strlen(tmp) < napcap) {
        memcpy(nap, tmp, strlen(tmp) + 1);
        rc = Q_R_OK;
    } else {
        if (q_json_get_str(d, "Tip.s", msg, msgcap) != 0 || msg[0] == '\0')
            snprintf(msg, msgcap, "adresse inconnue ou refusee");
        rc = Q_R_KO;
    }
    q_secure_zero(tmp, sizeof tmp);
    free_secret(d);
    return rc;
}

q_rest_rc q_rest_sit_3_end(const q_conf *c, const char *g_json, const char *nap,
                           const char *edr, char *edr_ok, size_t cap, int timeout_ms)
{
    char *qe, *x = NULL, *d = NULL;
    q_rest_rc rc;

    if (cap) edr_ok[0] = '\0';
    if (!q_uuid_valid(nap)) return Q_R_BAD;
    /* g vient du serveur (via CH4, authentifie G1) : on exige un objet JSON
     * valide avant de l'inserer tel quel, sinon {} */
    if (!g_json || g_json[0] != '{' || !q_json_valid(g_json)) g_json = "{}";
    qe = q_json_quote(edr);
    if (qe)                                       /* nap : UUID valide, sans echappement */
        x = join("{\"g\":", g_json, ",\"c\":{\"Edr\":{\"s\":", qe, "},\"NaP\":{\"u\":\"", nap,
                 "\"}}}", (const char *)NULL);
    free(qe);
    if (!x) return Q_R_BAD;

    rc = rest_call(c, "SiT_3_End", x, &d, timeout_ms);
    free_secret(x);
    if (rc != Q_R_OK) return rc;
    if (q_json_is_true(d, "a.ok") && q_json_get_str(d, "a.Edr", edr_ok, cap) == 0 && edr_ok[0])
        rc = Q_R_OK;
    else {
        if (cap) edr_ok[0] = '\0';
        rc = Q_R_KO;
    }
    free_secret(d);
    return rc;
}
