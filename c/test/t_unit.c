/* SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 Marc Gandar
 *
 * t_unit.c -- tests du C du kit Qovi TuI.
 *
 *   t_unit selftest                 vecteurs officiels + cas d'attaque
 *   t_unit net                      aller-retour TCP sur la boucle locale
 *   t_unit kid  <jeton>             -> "kid cle" en hexa
 *   t_unit seal <jeton> <aad> [nonce_hex]   STDIN -> message G1 sur stdout
 *   t_unit open <jeton> <aad> <msg> -> clair en HEX (code 1 si refuse)
 *   t_unit sign <prv> <op> <t> <n> <p>      -> "k s"
 *
 * kid/seal/open/sign servent a test/interop.py, qui croise ce C avec la
 * reference Python (python/qovi_g1.py, python/qovi_rest.py). */
#include "compat.h"
#include "qovi_auth.h"
#include "qovi_codec.h"
#include "qovi_conf.h"
#include "qovi_crypto.h"
#include "qovi_json.h"
#include "qovi_rest.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fail = 0, g_ok = 0;

#define CHECK(cond, what) do { \
    if (cond) { g_ok++; } \
    else { g_fail++; fprintf(stderr, "  ECHEC : %s (ligne %d)\n", what, __LINE__); } \
} while (0)

#define NAP  "00112233-4455-6677-8899-aabbccddeeff"
#define KID  "a4f924e70fae786bef2ae0474f7d8ecb"
#define HEX64 "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

static void t_b64(void)
{
    static const char *in[]  = { "", "f", "fo", "foo", "foob", "fooba", "foobar" };
    static const char *exp[] = { "", "Zg==", "Zm8=", "Zm9v", "Zm9vYg==", "Zm9vYmE=", "Zm9vYmFy" };
    static const char *bad[] = { "Zg=", "Z===", "Zm9v!", "Zg=a", "=Zg=", "Zm 9v" };
    char out[32];
    unsigned char dec[32];
    size_t i;

    for (i = 0; i < sizeof in / sizeof in[0]; i++) {
        size_t n = strlen(in[i]);
        long d;
        q_b64_encode((const unsigned char *)in[i], n, out, sizeof out);
        CHECK(strcmp(out, exp[i]) == 0, "base64 encodage RFC 4648");
        d = q_b64_decode(exp[i], strlen(exp[i]), dec, sizeof dec);
        CHECK(d == (long)n && memcmp(dec, in[i], n) == 0, "base64 decodage RFC 4648");
    }
    for (i = 0; i < sizeof bad / sizeof bad[0]; i++)
        CHECK(q_b64_decode(bad[i], strlen(bad[i]), dec, sizeof dec) < 0, "base64 invalide refuse");
    CHECK(q_b64_decode("Zm9vYmFy", 8, dec, 5) < 0, "base64 tampon trop petit refuse");
    CHECK(q_b64_encode((const unsigned char *)"foobar", 6, out, 8) == 0, "base64 sortie trop petite refusee");
}

static void t_hex(void)
{
    unsigned char b[4];
    char h[9];
    CHECK(q_hex_decode("00ff10Ab", b, 4) == 4 && b[1] == 0xff && b[3] == 0xab, "hexa decodage");
    CHECK(q_hex_decode("0g", b, 4) < 0 && q_hex_decode("abc", b, 4) < 0, "hexa invalide refuse");
    CHECK(q_hex_decode("0011223344", b, 4) < 0, "hexa tampon trop petit refuse");
    q_hex_encode(b, 4, h);
    CHECK(strcmp(h, "00ff10ab") == 0, "hexa encodage minuscule");
    CHECK(q_uuid_valid(NAP) && !q_uuid_valid("0011") && !q_uuid_valid(NAP "\""), "jeton UUID");
}

/* vecteurs publies par TLP le 02.11 (identiques a python/qovi_g1.py) */
static void t_g1(void)
{
    static const unsigned char nonce[12] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 };
    const char *rep = "G1AAECAwQFBgcICQoLnF+akkyYCo276cXT5/Hg/6TTBvdkE3yTV0NxV0SKlg==";
    char kid[33], kh[65], aq[40], ar[40], *m, *c, bad[128];
    unsigned char key[32], other[32];

    CHECK(q_ch4_derive(NAP, kid, key) == 0, "G1 derivation");
    q_hex_encode(key, 32, kh);
    CHECK(strcmp(kid, KID) == 0, "G1 kid officiel");
    CHECK(strcmp(kh, "decab4d165d801e21955e9d913fe92531dc53bd71d404103c0e4ce95da710893") == 0, "G1 cle officielle");
    CHECK(q_ch4_derive("00112233445566778899AABBCCDDEEFF", kid, other) == 0 && memcmp(key, other, 32) == 0,
          "G1 jeton sans tirets et en majuscules : meme cle");
    snprintf(aq, sizeof aq, "ch4q|%s", KID);
    snprintf(ar, sizeof ar, "ch4r|%s", KID);

    m = q_g1_seal(key, aq, "{\"g\":{},\"c\":{\"i\":1}}", nonce);
    CHECK(m && strcmp(m, "G1AAECAwQFBgcICQoLnF+p2QbBTdq7+MXTrq70yJOM2J+2K2KwOwYfA07NbuOYml+t") == 0,
          "G1 1re trame officielle");
    free(m);
    c = q_g1_open(key, ar, rep, strlen(rep));
    CHECK(c && strcmp(c, "{\"Tip\":{\"r\":2}}") == 0, "G1 reponse officielle");
    free(c);
    CHECK(q_g1_open(key, aq, rep, strlen(rep)) == NULL, "G1 reponse dans le mauvais sens refusee");
    snprintf(bad, sizeof bad, "%s", rep);
    bad[strlen(bad) - 4] = 'A'; bad[strlen(bad) - 3] = 'A'; bad[strlen(bad) - 2] = 'A';
    CHECK(q_g1_open(key, ar, bad, strlen(bad)) == NULL, "G1 reponse modifiee refusee");
    other[0] ^= 1;
    CHECK(q_g1_open(other, ar, rep, strlen(rep)) == NULL, "G1 mauvaise cle refusee");
    CHECK(q_g1_open(key, ar, "G1AAAA", 6) == NULL, "G1 trop court refuse");
    CHECK(q_g1_open(key, ar, "X1" "AAECAwQFBgcICQoL", 18) == NULL, "G1 prefixe faux refuse");
    m = q_g1_seal(key, aq, "x", NULL);
    c = m ? q_g1_seal(key, aq, "x", NULL) : NULL;
    CHECK(m && c && strcmp(m, c) != 0, "G1 nonce aleatoire different a chaque message");
    free(m); free(c);
    q_secure_zero(key, sizeof key);
}

/* vecteur calcule par python/qovi_rest.py (meme algorithme que qovi_sign.php) */
static void t_sign(void)
{
    const char *prv = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const char *n = "00112233445566778899aabbccddeeff";
    char k[65], s[65];
    CHECK(q_rest_sit_pub(prv, k) == 0 && strcmp(k, "71c78ddc246581c53225b1dfd144dfc8835a820094253257e50041aabcdfcfd9") == 0,
          "signature : identifiant public du site");
    CHECK(q_rest_sign(prv, "SiT_1_Edr", k, 1762160000LL, n, "eyJ4IjoxfQ==", s) == 0 &&
          strcmp(s, "bdf817256ea3fdd327c3d8d092a5d3c6f4d5b7827dc0407e0239911003789433") == 0,
          "signature de la requete");
    CHECK(q_rest_verify(prv, "SiT_1_Edr", n, "eyJhIjp7Im9rIjp0cnVlfX0=",
                        "bbd288cc62108546d8bf5bdb3a6e42b51e68b02e2ce2e1f4a7753d7248b0df11"),
          "signature de la reponse verifiee");
    CHECK(q_rest_verify(prv, "SiT_1_Edr", n, "eyJhIjp7Im9rIjp0cnVlfX0=",
                        "BBD288CC62108546D8BF5BDB3A6E42B51E68B02E2CE2E1F4A7753D7248B0DF11"),
          "signature de la reponse : majuscules acceptees");
    CHECK(!q_rest_verify(prv, "SiT_3_End", n, "eyJhIjp7Im9rIjp0cnVlfX0=",
                         "bbd288cc62108546d8bf5bdb3a6e42b51e68b02e2ce2e1f4a7753d7248b0df11"),
          "reponse d'une autre Op refusee");
    CHECK(!q_rest_verify(prv, "SiT_1_Edr", "ffffffffffffffffffffffffffffffff", "eyJhIjp7Im9rIjp0cnVlfX0=",
                         "bbd288cc62108546d8bf5bdb3a6e42b51e68b02e2ce2e1f4a7753d7248b0df11"),
          "reponse rejouee (autre nonce) refusee");
    CHECK(!q_rest_verify(prv, "SiT_1_Edr", n, "eyJhIjp7Im9rIjpmYWxzZX19",
                         "bbd288cc62108546d8bf5bdb3a6e42b51e68b02e2ce2e1f4a7753d7248b0df11"),
          "reponse modifiee refusee");
    CHECK(!q_rest_verify(prv, "SiT_1_Edr", n, "eyJhIjp7Im9rIjp0cnVlfX0=", "00"), "signature tronquee refusee");
    CHECK(q_rest_sit_pub("123", k) != 0, "cle privee mal formee refusee");
}

static void t_http(void)
{
    char a[] = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 5\r\n\r\nabcdeXYZ";
    char b[] = "HTTP/1.1 403 Forbidden\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2;x=1\r\nde\r\n0\r\n\r\n";
    char c[] = "HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\nabc";
    char d[] = "HTTP/1.0 200 OK\r\n\r\njusqu'a la fin";
    char e[] = "SSH-2.0 x\r\n\r\n";
    char f[] = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n";
    char *body;
    size_t bl;
    int st;
    CHECK(q_http_parse(a, strlen(a), &st, &body, &bl) == 0 && st == 200 && bl == 5 && !memcmp(body, "abcde", 5),
          "http Content-Length");
    CHECK(q_http_parse(b, strlen(b), &st, &body, &bl) == 0 && st == 403 && bl == 5 && !memcmp(body, "abcde", 5),
          "http chunked + statut d'erreur");
    CHECK(q_http_parse(c, strlen(c), &st, &body, &bl) != 0, "http corps incomplet refuse");
    CHECK(q_http_parse(d, strlen(d), &st, &body, &bl) == 0 && bl == strlen("jusqu'a la fin"), "http jusqu'a fermeture");
    CHECK(q_http_parse(e, strlen(e), &st, &body, &bl) != 0, "http pas du HTTP refuse");
    CHECK(q_http_parse(f, strlen(f), &st, &body, &bl) != 0, "http chunked invalide refuse");
}

static void t_url(void)
{
    char h[64], p[64];
    int port;
    CHECK(q_url_split("https://qovi.ch/RST/", h, sizeof h, &port, p, sizeof p) == 0 &&
          !strcmp(h, "qovi.ch") && port == 443 && !strcmp(p, "/RST"), "url par defaut");
    CHECK(q_url_split("https://tst.qovi.ch:8443/RST", h, sizeof h, &port, p, sizeof p) == 0 &&
          !strcmp(h, "tst.qovi.ch") && port == 8443, "url avec port");
    CHECK(q_url_split("http://qovi.ch/RST", h, sizeof h, &port, p, sizeof p) != 0, "url http refusee");
    CHECK(q_url_split("https://qovi.ch\r\nX: y/RST", h, sizeof h, &port, p, sizeof p) != 0, "url injection d'en-tete refusee");
    CHECK(q_url_split("https://qovi.ch/R ST", h, sizeof h, &port, p, sizeof p) != 0, "url avec espace refusee");
    CHECK(q_url_split("https://qovi.ch:0/RST", h, sizeof h, &port, p, sizeof p) != 0, "url port 0 refuse");
}

static void t_json(void);

static int write_file(const char *p, const char *txt)
{
    FILE *f = fopen(p, "w");
    if (!f) return -1;
    fputs(txt, f);
    fclose(f);
    return 0;
}

static void t_conf(void)
{
    const char *p = "t_unit_conf.tmp";
    q_conf c;
    char err[300];

    write_file(p, "# commentaire\nprv_us = " HEX64 "\n");
    CHECK(q_conf_load(p, &c, err, sizeof err) == 0 && !strcmp(c.api_url, "https://qovi.ch/RST") &&
          c.ch4_port == 6404 && c.port == 7777 && c.vote_timeout == 120, "conf minimale + defauts");
    q_conf_wipe(&c);
    CHECK(c.prv_us[0] == '\0', "conf effacement de la cle");
    write_file(p, "prv_us = " "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF" "\ntimeout = 600\nport=7778\n");
    CHECK(q_conf_load(p, &c, err, sizeof err) == 0 && !strcmp(c.prv_us, HEX64) && c.vote_timeout == 130 &&
          c.port == 7778, "conf cle en minuscules + plafond 130 s");
    write_file(p, "prv_us = " HEX64 "\napi_url = http://qovi.ch/RST\n");
    CHECK(q_conf_load(p, &c, err, sizeof err) != 0, "conf http refuse");
    write_file(p, "prv_us = COLLEZ_VOTRE_CLE\n");
    CHECK(q_conf_load(p, &c, err, sizeof err) != 0 && strstr(err, "non renseignee"), "conf cle non renseignee");
    write_file(p, "prv_us = 1234\n");
    CHECK(q_conf_load(p, &c, err, sizeof err) != 0 && !strstr(err, "1234"), "conf cle courte refusee, sans la citer");
    write_file(p, "prv_us = " HEX64 "\npub_us = " HEX64 "\n");
    CHECK(q_conf_load(p, &c, err, sizeof err) != 0 && strstr(err, "inconnue"), "conf cle inconnue refusee");
    write_file(p, "prv_us = " HEX64 "\ntimeout = 5\n");
    CHECK(q_conf_load(p, &c, err, sizeof err) != 0, "conf delai trop court refuse");
    if (!getenv("QOVI_PRV_US"))
        CHECK(q_conf_load("/n/existe/pas", &c, err, sizeof err) != 0 && strstr(err, "non renseignee"),
              "conf absente et pas de QOVI_PRV_US : refus");
    remove(p);
}

static void t_auth_input(void)
{
    char big[300];
    memset(big, 'x', 250); big[250] = '\0';
    CHECK(q_auth_edr_ok("m@x.ch") && q_auth_edr_ok("Marc.G+test@sous.gandar.ch"), "adresse valide");
    CHECK(!q_auth_edr_ok("") && !q_auth_edr_ok("sansarobase") && !q_auth_edr_ok("@x.ch"), "adresse vide ou sans @");
    CHECK(!q_auth_edr_ok("m@x.ch\nGo") && !q_auth_edr_ok("m x@x.ch") && !q_auth_edr_ok("m|y@x.ch"), "adresse piegee");
    CHECK(!q_auth_edr_ok("m@x") && !q_auth_edr_ok("m@x.c") && !q_auth_edr_ok("m@x.c0m") && !q_auth_edr_ok("a@b@x.ch"),
          "domaine invalide");
    CHECK(!q_auth_edr_ok("x; rm -rf /"), "adresse shell refusee");
    CHECK(q_auth_subj_ok("Connexion au serveur") && q_auth_subj_ok("\xc3\xa9t\xc3\xa9"), "raison valide");
    CHECK(!q_auth_subj_ok("a\rb") && !q_auth_subj_ok(big) && !q_auth_subj_ok("\xc3\x28"), "raison piegee refusee");
    CHECK(q_auth_subj_ml_ok("Ligne 1\r\nLigne 2") && q_auth_subj_ml_ok("L1\nL2\nL3") && q_auth_subj_ml_ok("Merci de valider \xc3\xa0 17:39"),
          "raison sur plusieurs lignes (LF, CRLF) et accentuee");
    CHECK(!q_auth_subj_ml_ok("a\rb") && !q_auth_subj_ml_ok("a\x01b") && !q_auth_subj_ml_ok("1\n2\n3\n4\n5\n6\n7\n8\n9\n10\n11")
          && !q_auth_subj_ml_ok(big), "raison multi-lignes piegee refusee (CR seul, controle, 11 lignes, trop longue)");
}

static int cmd_selftest(void)
{
    t_b64(); t_hex(); t_g1(); t_sign(); t_http(); t_url(); t_conf(); t_json(); t_auth_input();
    printf("SELFTEST : %d ok, %d echec(s)\n", g_ok, g_fail);
    return g_fail ? 1 : 0;
}

static void t_json(void)
{
    static const char *bad[] = { "{\"a\":1,}", "{\"a\":01}", "{\"a\":\"x\\q\"}", "{\"a\":1} x",
                                 "\"abc", "{\"a\":\"\x01\"}", "{a:1}", "[1,2", "{\"a\":1e}", "" };
    char out[64], deep[200];
    const char *v;
    size_t len, i;
    long r;

    CHECK(q_json_valid("{\"a\":{\"ChX\":{\"Prv\":{\"u\":\"x\"}}},\"b\":[1,-2.5e3,true,false,null]}"), "json valide");
    for (i = 0; i < sizeof bad / sizeof bad[0]; i++)
        CHECK(!q_json_valid(bad[i]), "json invalide refuse");
    memset(deep, '[', 40); memset(deep + 40, ']', 40); deep[80] = '\0';
    CHECK(!q_json_valid(deep), "json trop profond refuse (anti epuisement de pile)");

    CHECK(q_json_get_str("{\"a\":{\"ChX\":{\"Prv\":{\"u\":\"abc\"}}}}", "a.ChX.Prv.u", out, sizeof out) == 0 &&
          strcmp(out, "abc") == 0, "json chemin pointe");
    CHECK(q_json_get_str("{\"s\":\"a\\\"b\\\\c\\u00e9\\ud83d\\ude00\"}", "s", out, sizeof out) == 0 &&
          strcmp(out, "a\"b\\c\xc3\xa9\xf0\x9f\x98\x80") == 0, "json desechappement + UTF-8 + paire");
    CHECK(q_json_get_str("{\"s\":\"a\\u0000b\"}", "s", out, sizeof out) != 0, "json \\u0000 refuse");
    CHECK(q_json_get_str("{\"s\":\"\\ud83d\"}", "s", out, sizeof out) != 0, "json surrogate isole refuse");
    CHECK(q_json_get_str("{\"s\":\"abcdefghij\"}", "s", out, 5) != 0, "json chaine trop longue refusee");
    CHECK(q_json_get_str("{\"s\":1}", "s", out, sizeof out) != 0, "json pas une chaine");
    CHECK(q_json_get_str("{\"s\":\"x\"}", "t", out, sizeof out) != 0, "json cle absente");
    CHECK(q_json_get_int("{\"Tip\":{\"r\":2,\"s\":\"ok\"}}", "Tip.r", &r) == 0 && r == 2, "json entier");
    CHECK(q_json_get_int("{\"r\":2.5}", "r", &r) != 0, "json decimal refuse comme entier");
    CHECK(q_json_get_int("{\"r\":\"2\"}", "r", &r) != 0, "json chaine refusee comme entier");
    CHECK(q_json_is_true("{\"a\":{\"ok\":true}}", "a.ok") && !q_json_is_true("{\"a\":{\"ok\":\"true\"}}", "a.ok"), "json true strict");
    CHECK(q_json_find("{\"k\":1,\"k\":2}", "k", &v, &len) == 0 && *v == '1', "json cle dupliquee : premiere");

    CHECK(q_utf8_valid("\xc3\xa9\xe2\x82\xac\xf0\x9f\x98\x80", 9), "utf8 valide");
    CHECK(!q_utf8_valid("\xc0\x80", 2), "utf8 surlongueur refusee");
    CHECK(!q_utf8_valid("\xed\xa0\x80", 3), "utf8 surrogate refuse");
    CHECK(!q_utf8_valid("\xe2\x82", 2), "utf8 tronque refuse");
    CHECK(!q_utf8_valid("\xf5\x80\x80\x80", 4), "utf8 hors plage refuse");
    {
        char *q = q_json_quote("a\"b\\c\n\x01" "d");
        CHECK(q && strcmp(q, "\"a\\\"b\\\\c\\n\\u0001d\"") == 0, "json echappement");
        free(q);
        CHECK(q_json_quote("\xff") == NULL, "json echappement refuse UTF-8 invalide");
    }
}

static int cmd_net(void)
{
    const int port = 17777;
    qsock_t srv, cli, acc;
    char buf[64];
    int peer = 0, n;

    if (q_net_init() != 0) { fprintf(stderr, "net init\n"); return 1; }
    srv = q_tcp_listen("127.0.0.1", port, 1);
    CHECK(srv != QSOCK_INVALID, "net ecoute 127.0.0.1");
    cli = q_tcp_connect("127.0.0.1", port, 2000);
    CHECK(cli != QSOCK_INVALID, "net connexion");
    acc = (srv != QSOCK_INVALID) ? q_tcp_accept(srv, &peer) : QSOCK_INVALID;
    CHECK(acc != QSOCK_INVALID && peer > 0, "net acceptation + port du pair");
    if (cli != QSOCK_INVALID && acc != QSOCK_INVALID) {
        CHECK(q_send_all(cli, "ping", 4) == 0, "net envoi");
        n = q_recv_timeout(acc, buf, sizeof buf, 2000);
        CHECK(n == 4 && memcmp(buf, "ping", 4) == 0, "net reception");
        CHECK(q_recv_timeout(acc, buf, sizeof buf, 300) == Q_TIMEOUT, "net timeout");
        q_close(cli);
        cli = QSOCK_INVALID;
        CHECK(q_recv_timeout(acc, buf, sizeof buf, 2000) == 0, "net fermeture detectee");
    }
    CHECK(q_tcp_connect("127.0.0.1", 1, 1000) == QSOCK_INVALID, "net port ferme refuse");
    q_close(cli); q_close(acc); q_close(srv);
    q_net_cleanup();
    {
        char ts[32];
        CHECK(q_utc_iso_ms(ts, sizeof ts) == 0 && strlen(ts) == 23 && ts[10] == 'T', "horodatage UTC ms");
    }
    printf("NET : %d ok, %d echec(s)\n", g_ok, g_fail);
    return g_fail ? 1 : 0;
}

static char *read_stdin(void)
{
    size_t cap = 4096, n = 0;
    char *b = (char *)malloc(cap);
    int ch;
    if (!b) return NULL;
    while ((ch = getchar()) != EOF) {
        if (n + 1 >= cap) {
            char *nb;
            if (cap > 1024 * 1024) { free(b); return NULL; }
            nb = (char *)realloc(b, cap * 2);
            if (!nb) { free(b); return NULL; }
            b = nb; cap *= 2;
        }
        b[n++] = (char)ch;
    }
    b[n] = '\0';
    return b;
}

static int cmd_kid(const char *nap)
{
    char kid[33], kh[65];
    unsigned char key[32];
    if (q_ch4_derive(nap, kid, key) != 0) return 1;
    q_hex_encode(key, 32, kh);
    printf("%s %s\n", kid, kh);
    return 0;
}

static int cmd_seal(const char *nap, const char *aad, const char *nonce_hex)
{
    char kid[33], *in, *m;
    unsigned char key[32], nonce[12];
    if (q_ch4_derive(nap, kid, key) != 0) return 1;
    if (nonce_hex && q_hex_decode(nonce_hex, nonce, sizeof nonce) != 12) return 1;
    in = read_stdin();
    m = in ? q_g1_seal(key, aad, in, nonce_hex ? nonce : NULL) : NULL;
    free(in);
    if (!m) return 1;
    printf("%s\n", m);
    free(m);
    return 0;
}

static int cmd_open(const char *nap, const char *aad, const char *msg)
{
    char kid[33], *c, *h;
    unsigned char key[32];
    if (q_ch4_derive(nap, kid, key) != 0) return 1;
    c = q_g1_open(key, aad, msg, strlen(msg));
    if (!c) return 1;
    h = (char *)malloc(2 * strlen(c) + 1);
    if (!h) { free(c); return 1; }
    q_hex_encode((const unsigned char *)c, strlen(c), h);
    printf("%s\n", h);
    free(h);
    free(c);
    return 0;
}

static int cmd_sign(const char *prv, const char *op, const char *t, const char *n, const char *p)
{
    char k[65], s[65];
    if (q_rest_sit_pub(prv, k) != 0 || q_rest_sign(prv, op, k, strtoll(t, NULL, 10), n, p, s) != 0) return 1;
    printf("%s %s\n", k, s);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc >= 2 && !strcmp(argv[1], "selftest")) return cmd_selftest();
    if (argc >= 2 && !strcmp(argv[1], "net"))      return cmd_net();
    if (argc == 3 && !strcmp(argv[1], "kid"))      return cmd_kid(argv[2]);
    if ((argc == 4 || argc == 5) && !strcmp(argv[1], "seal")) return cmd_seal(argv[2], argv[3], argc == 5 ? argv[4] : NULL);
    if (argc == 5 && !strcmp(argv[1], "open"))     return cmd_open(argv[2], argv[3], argv[4]);
    if (argc == 7 && !strcmp(argv[1], "sign"))     return cmd_sign(argv[2], argv[3], argv[4], argv[5], argv[6]);
    fprintf(stderr, "usage: t_unit selftest | net | kid <jeton> | seal <jeton> <aad> [nonce] | "
                    "open <jeton> <aad> <msg> | sign <prv> <op> <t> <n> <p>\n");
    return 2;
}
