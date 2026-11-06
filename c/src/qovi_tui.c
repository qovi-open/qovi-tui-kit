/* SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 Marc Gandar
 *
 * qovi_tui.c -- client TuI (Linux, Windows). Il ne lit JAMAIS la cle du site :
 * c'est le service qovi-tuid qui la detient.
 *
 *   qovi-tui login --edr <adresse> [--subj <raison>] [--json] [--port <port>]
 *
 * --json : recopie les lignes JSON du service, une par evenement
 *          (sent, wait, puis go / ko / timeout / error) ; sinon texte lisible.
 * Port : --port, sinon la variable QOVI_TUI_PORT, sinon 7777.
 * Code de sortie : 0 go, 1 ko, 2 delai depasse, 3 erreur, 4 usage. */
#include "compat.h"
#include "qovi_json.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define WAIT_MS  (135 * 1000)   /* le service s'arrete a 130 s, plus une marge */
#define LINE_MAX 2048

enum { RC_GO = 0, RC_KO = 1, RC_TIMEOUT = 2, RC_ERR = 3, RC_USAGE = 4 };

static int g_json = 0;

static int usage(void)
{
    fprintf(stderr, "usage : qovi-tui login --edr <adresse> [--subj <raison>] [--json] [--port <port>]\n"
                    "sortie : 0 go, 1 ko, 2 delai depasse, 3 erreur, 4 usage\n");
    return RC_USAGE;
}

static int has_ctrl(const char *s)
{
    for (; *s; s++)
        if ((unsigned char)*s < 0x20 || (unsigned char)*s == 0x7F) return 1;
    return 0;
}

/* raison : sauts de ligne LF ou CRLF admis (10 lignes au plus), aucun autre
 * caractere de controle, jamais un CR seul (meme regle que le service) */
static int subj_bad(const char *s)
{
    int lines = 1;
    for (; *s; s++) {
        unsigned char ch = (unsigned char)*s;
        if (ch == '\r') { if (s[1] != '\n') return 1; continue; }
        if (ch == '\n') { if (++lines > 10) return 1; continue; }
        if (ch < 0x20 || ch == 0x7F) return 1;
    }
    return 0;
}

/* erreur locale (le service n'a rien dit) */
static int local_end(int rc, const char *ev, const char *t)
{
    if (g_json) {
        char *qt = q_json_quote(t);
        printf("{\"ev\":\"%s\",\"t\":%s}\n", ev, qt ? qt : "\"\"");
        free(qt);
    } else {
        fprintf(stderr, "%s\n", t);
    }
    fflush(stdout);
    return rc;
}

/* une ligne du service ; renvoie le code de sortie si finale, -1 sinon */
static int on_line(const char *line)
{
    char ev[16], t[600], edr[300];
    if (!q_json_valid(line) || q_json_get_str(line, "ev", ev, sizeof ev) != 0)
        return local_end(RC_ERR, "error", line[0] ? line : "reponse illisible du service");
    if (q_json_get_str(line, "t", t, sizeof t) != 0) t[0] = '\0';
    if (has_ctrl(t)) t[0] = '\0';
    if (g_json) { printf("%s\n", line); fflush(stdout); }

    if (!strcmp(ev, "sent")) {
        if (!g_json) { printf("Demande envoyee a Qovi...\n"); fflush(stdout); }
        return -1;
    }
    if (!strcmp(ev, "wait")) {
        if (!g_json) { printf("En attente du vote sur le mobile...\n"); fflush(stdout); }
        return -1;
    }
    if (!strcmp(ev, "go")) {
        if (q_json_get_str(line, "edr", edr, sizeof edr) != 0 || has_ctrl(edr)) edr[0] = '\0';
        if (!g_json) printf("OK authentifie %s\n", edr);
        return RC_GO;
    }
    if (!strcmp(ev, "ko"))      { if (!g_json) printf("Refuse : %s\n", t);  return RC_KO; }
    if (!strcmp(ev, "timeout")) { if (!g_json) printf("Delai depasse : %s\n", t); return RC_TIMEOUT; }
    if (!strcmp(ev, "error"))   { if (!g_json) printf("Erreur : %s\n", t);  return RC_ERR; }
    return -1;                                       /* evenement inconnu : ignore */
}

int main(int argc, char **argv)
{
    const char *edr = NULL, *subj = "Demande qovi-tui", *ps = getenv("QOVI_TUI_PORT");
    char *qe = NULL, *qs = NULL, *req = NULL, buf[LINE_MAX];
    long port = 7777;
    size_t n = 0;
    long long deadline;
    qsock_t s;
    int i, rc = RC_ERR;

    if (argc < 2 || strcmp(argv[1], "login") != 0) return usage();
    for (i = 2; i < argc; i++) {
        if (!strcmp(argv[i], "--json")) g_json = 1;
        else if (!strcmp(argv[i], "--edr") && i + 1 < argc) edr = argv[++i];
        else if (!strcmp(argv[i], "--subj") && i + 1 < argc) subj = argv[++i];
        else if (!strcmp(argv[i], "--port") && i + 1 < argc) ps = argv[++i];
        else return usage();
    }
    if (!edr || !*edr || strlen(edr) > 254 || has_ctrl(edr) || strlen(subj) > 200 || subj_bad(subj))
        return usage();
    if (ps && *ps) {
        char *end;
        port = strtol(ps, &end, 10);
        if (*end || port < 1 || port > 65535) return usage();
    }
    qe = q_json_quote(edr);
    qs = q_json_quote(subj);
    if (!qe || !qs) { free(qe); free(qs); return usage(); }   /* UTF-8 invalide */
    req = (char *)malloc(strlen(qe) + strlen(qs) + 32);
    if (!req) { free(qe); free(qs); return RC_ERR; }
    sprintf(req, "{\"edr\":%s,\"subj\":%s}\n", qe, qs);
    free(qe);
    free(qs);

    if (q_net_init() != 0) { free(req); return local_end(RC_ERR, "error", "initialisation reseau impossible"); }
    s = q_tcp_connect("127.0.0.1", (int)port, 5000);
    if (s == QSOCK_INVALID) {
        free(req);
        q_net_cleanup();
        return local_end(RC_ERR, "error", "service TuI injoignable");
    }
    if (q_send_all(s, req, strlen(req)) != 0) { rc = local_end(RC_ERR, "error", "envoi impossible"); goto done; }

    deadline = q_now_ms() + WAIT_MS;
    for (;;) {
        long long left = deadline - q_now_ms();
        char *nl;
        int r;
        if (left <= 0) { rc = local_end(RC_TIMEOUT, "timeout", "pas de reponse du service"); break; }
        if (n + 1 >= sizeof buf) { rc = local_end(RC_ERR, "error", "ligne trop longue"); break; }
        r = q_recv_timeout(s, buf + n, sizeof buf - 1 - n, (int)left);
        if (r == Q_TIMEOUT) continue;
        if (r <= 0) { rc = local_end(RC_ERR, "error", "connexion au service perdue"); break; }
        n += (size_t)r;
        buf[n] = '\0';
        while ((nl = memchr(buf, '\n', n)) != NULL) {
            size_t ll = (size_t)(nl - buf);
            *nl = '\0';
            if (ll > 0 && buf[ll - 1] == '\r') buf[ll - 1] = '\0';
            rc = on_line(buf);
            memmove(buf, nl + 1, n - ll - 1);
            n -= ll + 1;
            buf[n] = '\0';
            if (rc >= 0) goto done;
        }
    }
done:
    fflush(stdout);
    free(req);
    q_close(s);
    q_net_cleanup();
    return rc;
}
