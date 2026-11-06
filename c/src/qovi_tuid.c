/* SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 Marc Gandar
 *
 * qovi_tuid.c -- service TuI (detient la cle privee du site ; les applications
 * clientes ne la connaissent jamais).
 *
 *   qovi-tuid [qovi-tui.conf]                  mode service (127.0.0.1:port)
 *   qovi-tuid <qovi-tui.conf> <adresse> [raison]  essai direct, sans socket
 *   Windows : « qovi-tuid --service » (lance par le gestionnaire de services)
 *             « qovi-tuid setkey [--file <f>] [--api <url>] » (administrateur)
 *
 * Une application se connecte sur 127.0.0.1:port et envoie UNE ligne :
 *   CSV  : adresse|raison         -> UNE ligne en retour : "Go ..." ou "Ko ..."
 *   JSON : {"edr":"..","subj":".."} -> lignes JSON, une par evenement :
 *          {"ev":"sent"}                 transaction ouverte, demande partie
 *          {"ev":"wait","t":".."}        demande arrivee sur le mobile
 *          puis UNE ligne finale parmi
 *          {"ev":"go","edr":"..","t":".."} {"ev":"ko","t":".."}
 *          {"ev":"timeout","t":".."}      {"ev":"error","t":".."}
 * Limites (controlees ICI, pas chez le client) : 5 demandes en meme temps,
 * 1 par adresse, 130 s au plus par demande. Au-dela : refus immediat.
 * Un GO n'est rendu qu'apres confirmation SiT_3_End (voir qovi_auth.c). */
#include "compat.h"
#include "qovi_auth.h"
#include "qovi_conf.h"
#include "qovi_json.h"
#include "qovi_tls.h"
#ifdef _WIN32
  #include "qovi_win.h"
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define REQ_MAX        1024     /* une requete fait au plus 1 Ko                */
#define REQ_TIMEOUT_MS 10000    /* 10 s pour la recevoir (client lent = coupe)   */
#define MAX_AUTH       5        /* demandes en cours en meme temps               */
#define MAX_CONN       16       /* connexions ouvertes (lecture comprise)        */
#define DEFAULT_SUBJ   "Demande TuI"

static q_conf   g_conf;
static q_mutex  g_mx;
static FILE    *g_log = NULL;
static int      g_conns = 0;
static char     g_busy[MAX_AUTH][Q_EDR_MAX + 2];   /* adresses en cours ("" = libre) */

typedef struct { qsock_t s; int peer; } conn_t;
typedef struct { qsock_t s; int json; } out_t;

static void lower_copy(char *d, const char *s, size_t cap)
{
    size_t i;
    for (i = 0; s[i] && i + 1 < cap; i++)
        d[i] = (s[i] >= 'A' && s[i] <= 'Z') ? (char)(s[i] + 32) : s[i];
    d[i] = '\0';
}

/* reserve une place pour edr. 0 = ok ; 1 = adresse deja en cours ; 2 = plein */
static int slot_take(const char *edr)
{
    char low[Q_EDR_MAX + 2];
    int i, free_i = -1, rc;
    lower_copy(low, edr, sizeof low);
    q_mutex_lock(&g_mx);
    for (i = 0; i < MAX_AUTH; i++) {
        if (g_busy[i][0] && strcmp(g_busy[i], low) == 0) { q_mutex_unlock(&g_mx); return 1; }
        if (!g_busy[i][0] && free_i < 0) free_i = i;
    }
    if (free_i < 0) rc = 2;
    else { memcpy(g_busy[free_i], low, strlen(low) + 1); rc = 0; }
    q_mutex_unlock(&g_mx);
    return rc;
}

static void slot_give(const char *edr)
{
    char low[Q_EDR_MAX + 2];
    int i;
    lower_copy(low, edr, sizeof low);
    q_mutex_lock(&g_mx);
    for (i = 0; i < MAX_AUTH; i++)
        if (g_busy[i][0] && strcmp(g_busy[i], low) == 0) { g_busy[i][0] = '\0'; break; }
    q_mutex_unlock(&g_mx);
}

/* Journal : sortie standard (journald sous systemd) + log_file si donne.
 * edr/texte sont garantis sans caractere de controle ; les sauts de ligne de
 * la raison sont ecrits « | » : pas de fausse ligne possible. Jamais de cle
 * ni de jeton. */
static void log_line(long pid, const char *edr, const char *subj_in, const char *verdict, const char *txt)
{
    char ts[32], subj[Q_SUBJ_MAX * 3 + 1];
    size_t i, o = 0;
    for (i = 0; subj_in[i] && o + 4 < sizeof subj; i++) {
        if (subj_in[i] == '\r') continue;
        if (subj_in[i] == '\n') { memcpy(subj + o, " | ", 3); o += 3; continue; }
        subj[o++] = subj_in[i];
    }
    subj[o] = '\0';
    if (q_local_stamp(ts, sizeof ts) != 0) snprintf(ts, sizeof ts, "?");
    q_mutex_lock(&g_mx);
    if (pid > 0) printf("%s pid=%ld %s <%s> -> %s %s\n", ts, pid, edr, subj, verdict, txt);
    else         printf("%s pid=? %s <%s> -> %s %s\n", ts, edr, subj, verdict, txt);
    fflush(stdout);
    if (g_log) {
        if (pid > 0) fprintf(g_log, "%s pid=%ld %s <%s> -> %s %s\n", ts, pid, edr, subj, verdict, txt);
        else         fprintf(g_log, "%s pid=? %s <%s> -> %s %s\n", ts, edr, subj, verdict, txt);
        fflush(g_log);
    }
    q_mutex_unlock(&g_mx);
}

/* {"ev":"<ev>"[,"edr":..][,"t":..]}\n */
static void send_ev(qsock_t s, const char *ev, const char *edr, const char *t)
{
    char *qe = edr ? q_json_quote(edr) : NULL;
    char *qt = t ? q_json_quote(t) : NULL;
    size_t n = 32 + strlen(ev) + (qe ? strlen(qe) : 0) + (qt ? strlen(qt) : 0);
    char *line = (char *)malloc(n);
    if (line) {
        int k = snprintf(line, n, "{\"ev\":\"%s\"%s%s%s%s}\n", ev,
                         qe ? ",\"edr\":" : "", qe ? qe : "", qt ? ",\"t\":" : "", qt ? qt : "");
        if (k > 0 && (size_t)k < n) q_send_all(s, line, (size_t)k);
        free(line);
    }
    free(qe);
    free(qt);
}

static void on_event(const char *ev, const char *t, void *ud)
{
    out_t *o = (out_t *)ud;
    if (!o || !o->json) return;
    send_ev(o->s, ev, NULL, (t && *t) ? t : NULL);
}

/* Lit une ligne (jusqu'a '\n' ou fermeture). 0 = ok ; -1 trop longue ;
 * -2 delai depasse ; -3 erreur ou vide. */
static int read_line(qsock_t s, char *buf, size_t cap)
{
    size_t n = 0;
    long long deadline = q_now_ms() + REQ_TIMEOUT_MS;
    for (;;) {
        long long left = deadline - q_now_ms();
        int r;
        char *nl;
        if (left <= 0) return -2;
        if (n + 1 >= cap) return -1;
        r = q_recv_timeout(s, buf + n, cap - 1 - n, (int)left);
        if (r == Q_TIMEOUT) return -2;
        if (r < 0) return -3;
        if (r == 0) break;
        n += (size_t)r;
        buf[n] = '\0';
        nl = memchr(buf, '\n', n);
        if (nl) { *nl = '\0'; n = (size_t)(nl - buf); break; }
    }
    buf[n] = '\0';
    if (n > 0 && buf[n - 1] == '\r') buf[--n] = '\0';
    return n > 0 ? 0 : -3;
}

/* vide (brievement, borne) ce qu'un client trop bavard a encore envoye */
static void drain(qsock_t s)
{
    char junk[4096];
    int i;
    for (i = 0; i < 16; i++)
        if (q_recv_timeout(s, junk, sizeof junk, 200) <= 0) break;
}

/* CSV ou JSON -> edr / subj. 0 = ok ; why = raison du refus */
static int parse_request(char *req, int *json, char *edr, size_t ecap, char *subj, size_t scap,
                         char *why, size_t wcap)
{
    *json = (req[0] == '{');
    if (*json) {
        if (!q_json_valid(req) || q_json_get_str(req, "edr", edr, ecap) != 0) {
            snprintf(why, wcap, "requete JSON invalide (champ edr)");
            return -1;
        }
        if (q_json_get_str(req, "subj", subj, scap) != 0 || !subj[0]) snprintf(subj, scap, "%s", DEFAULT_SUBJ);
    } else {
        char *bar = strchr(req, '|');
        size_t el, sl;
        if (bar) *bar = '\0';
        el = strlen(req);
        if (el >= ecap) { snprintf(why, wcap, "adresse invalide"); return -1; }
        memcpy(edr, req, el + 1);
        if (bar && bar[1]) {
            sl = strlen(bar + 1);
            if (sl >= scap) { snprintf(why, wcap, "raison invalide"); return -1; }
            memcpy(subj, bar + 1, sl + 1);
        } else {
            snprintf(subj, scap, "%s", DEFAULT_SUBJ);
        }
    }
    if (!q_auth_edr_ok(edr))  { snprintf(why, wcap, "adresse invalide"); return -1; }
    /* JSON : sauts de ligne admis (echappes dans la requete) ; CSV : une ligne */
    if (*json ? !q_auth_subj_ml_ok(subj) : !q_auth_subj_ok(subj)) {
        snprintf(why, wcap, "raison invalide (max %d octets, %d lignes, sans autre caractere de controle)",
                 Q_SUBJ_MAX, Q_SUBJ_LINES);
        return -1;
    }
    return 0;
}

static void reply_final(qsock_t s, int json, q_auth_res r, const char *edr, const char *txt)
{
    if (json) {
        send_ev(s, q_auth_res_name(r), r == Q_AUTH_GO ? edr : NULL, txt);
    } else {
        char line[400];
        int k = snprintf(line, sizeof line, "%s %s\n", r == Q_AUTH_GO ? "Go" : "Ko", txt);
        if (k > 0) q_send_all(s, line, (size_t)k < sizeof line ? (size_t)k : sizeof line - 1);
    }
}

static void handle(void *arg)
{
    conn_t cn = *(conn_t *)arg;
    char req[REQ_MAX], edr[Q_EDR_MAX + 2], subj[Q_SUBJ_MAX + 2], why[160], txt[300];
    int json = 0, rc;
    long pid;
    out_t o;
    q_auth_res r;

    free(arg);
    pid = q_peer_pid(cn.peer, g_conf.port);       /* tant que le client est la */
    rc = read_line(cn.s, req, sizeof req);
    if (rc != 0) {
        const char *w = rc == -1 ? "requete trop longue" : rc == -2 ? "delai de requete depasse" : "requete vide";
        reply_final(cn.s, 0, Q_AUTH_ERR, NULL, w);
        log_line(pid, "-", "-", "error", w);
        if (rc == -1) drain(cn.s);                  /* sinon RST : reponse perdue */
        goto end;
    }
    edr[0] = subj[0] = '\0';
    if (parse_request(req, &json, edr, sizeof edr, subj, sizeof subj, why, sizeof why) != 0) {
        reply_final(cn.s, json, Q_AUTH_ERR, NULL, why);
        log_line(pid, "-", "-", "error", why);     /* entree refusee : pas journalisee */
        goto end;
    }
    rc = slot_take(edr);
    if (rc != 0) {
        const char *w = rc == 1 ? "essai deja en cours pour cette adresse" : "service occupe, reessayez";
        reply_final(cn.s, json, Q_AUTH_ERR, NULL, w);
        log_line(pid, edr, subj, "error", w);
        goto end;
    }
    o.s = cn.s;
    o.json = json;
    r = q_authenticate(&g_conf, edr, subj, on_event, &o, txt, sizeof txt);
    slot_give(edr);
    log_line(pid, edr, subj, q_auth_res_name(r), txt);   /* journal d'abord */
    reply_final(cn.s, json, r, edr, txt);

end:
    q_close(cn.s);
    q_mutex_lock(&g_mx);
    g_conns--;
    q_mutex_unlock(&g_mx);
}

static int serve(void)
{
    qsock_t srv = q_tcp_listen(Q_LISTEN_HOST, g_conf.port, 16);
    if (srv == QSOCK_INVALID) {
        fprintf(stderr, "impossible d'ecouter sur %s:%d (port deja pris ?)\n", Q_LISTEN_HOST, g_conf.port);
        return 1;
    }
    if (g_conf.log_file[0]) {
        g_log = q_log_open(g_conf.log_file);
        if (!g_log) fprintf(stderr, "ATTENTION : %s impossible a ouvrir, journal sur la sortie standard seulement\n",
                            g_conf.log_file);
    }
    printf("qovi-tuid a l'ecoute sur %s:%d (%d demandes en meme temps au plus)\n",
           Q_LISTEN_HOST, g_conf.port, MAX_AUTH);
    fflush(stdout);

    for (;;) {
        int peer = 0, full;
        conn_t *cn;
        qsock_t cl = q_tcp_accept(srv, &peer);
        if (cl == QSOCK_INVALID) { q_sleep_ms(50); continue; }
        q_mutex_lock(&g_mx);
        full = g_conns >= MAX_CONN;
        if (!full) g_conns++;
        q_mutex_unlock(&g_mx);
        if (full) {                                  /* trop de connexions : refus net */
            q_send_all(cl, "Ko service occupe, reessayez\n", 29);
            q_close(cl);
            continue;
        }
        cn = (conn_t *)malloc(sizeof *cn);
        if (cn) { cn->s = cl; cn->peer = peer; }
        if (!cn || q_thread_start(handle, cn) != 0) {
            free(cn);
            q_close(cl);
            q_mutex_lock(&g_mx);
            g_conns--;
            q_mutex_unlock(&g_mx);
        }
    }
}

static void direct_ev(const char *ev, const char *t, void *ud)
{
    (void)ud;
    printf("   ... %s %s\n", ev, t ? t : "");
    fflush(stdout);
}

/* chargement de la configuration + reseau + TLS ; 0 ou 3 (configuration) */
static char g_conf_path[512];

static int tuid_init(void)
{
    char err[300];
    if (q_conf_load(g_conf_path, &g_conf, err, sizeof err) != 0) {
        fprintf(stderr, "configuration : %s\n", err);
        fflush(stderr);
        return 3;
    }
    if (q_conf_too_open(g_conf_path, err, sizeof err)) fprintf(stderr, "ATTENTION : %s\n", err);
    q_mutex_init(&g_mx);
    if (q_net_init() != 0 || q_tls_init(g_conf.ca_file) != 0) {
        fprintf(stderr, "initialisation reseau ou TLS impossible (racines de confiance ?)\n");
        fflush(stderr);
        q_conf_wipe(&g_conf);
        return 3;
    }
    return 0;
}

int main(int argc, char **argv)
{
    int rc;
    const char *conf = argc >= 2 ? argv[1] : NULL;
#ifdef _WIN32
    char wdir[MAX_PATH], wconf[MAX_PATH], wlog[MAX_PATH];
    if (q_win_paths(wdir, sizeof wdir, wconf, sizeof wconf, wlog, sizeof wlog) != 0) return 3;
    if (argc >= 2 && !strcmp(argv[1], "setkey")) return q_win_setkey(argc, argv);
    if (argc == 2 && !strcmp(argv[1], "--service")) {
        snprintf(g_conf_path, sizeof g_conf_path, "%s", wconf);
        return q_win_service_run(wlog, tuid_init, serve);
    }
    if (!conf) conf = wconf;
#else
    if (!conf) conf = Q_DEFAULT_CONF;
#endif
    if (argc > 4 || (argc == 2 && (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help")))) {
        fprintf(stderr, "usage : qovi-tuid [qovi-tui.conf]                     (service)\n"
                        "        qovi-tuid <qovi-tui.conf> <adresse> [raison]  (essai direct)\n"
#ifdef _WIN32
                        "        qovi-tuid setkey [--file <fichier>] [--api https://...]  (console administrateur)\n"
#endif
                        );
        return 4;
    }
    if ((size_t)snprintf(g_conf_path, sizeof g_conf_path, "%s", conf) >= sizeof g_conf_path) return 4;
    rc = tuid_init();
    if (rc != 0) return rc;

    if (argc >= 3) {                                 /* essai direct */
        char txt[300];
        q_auth_res r;
        printf("qovi-tuid essai direct -> %s (attente du vote %d s)\n", g_conf.api_url, g_conf.vote_timeout);
        fflush(stdout);
        r = q_authenticate(&g_conf, argv[2], argc == 4 ? argv[3] : "Essai direct qovi-tuid",
                           direct_ev, NULL, txt, sizeof txt);
        printf("=> %s %s\n", q_auth_res_name(r), txt);
        rc = r == Q_AUTH_GO ? 0 : r == Q_AUTH_KO ? 1 : r == Q_AUTH_TIMEOUT ? 2 : 3;
    } else {
        rc = serve();
    }
    q_conf_wipe(&g_conf);
    q_tls_cleanup();
    q_net_cleanup();
    return rc;
}
