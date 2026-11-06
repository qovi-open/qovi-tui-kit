/* SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 Marc Gandar
 *
 * qovi_rest.h -- appels REST SIGNES vers Qovi (meme protocole que
 * python/qovi_rest.py et qovi_sign.php des kits PHP).
 *
 * La cle privee du site ne quitte JAMAIS la machine : elle sert seulement a
 * SIGNER la requete et a VERIFIER la reponse.
 *
 * Requete : POST <api>/<Op>, corps JSON
 *   {"v":1,"k":<id public du site>,"t":<secondes UTC>,"n":<nonce hex32>,
 *    "p":<base64 du JSON x_j>,"s":<HMAC-SHA256 hex>}
 *   k = sha256hex("qovi-sit-pub-v1:" + cle privee hexa)
 *   s = HMAC(cle privee en octets, "qovi-sit-v1\n"+Op+"\n"+k+"\n"+t+"\n"+n+"\n"+sha256hex(p))
 * Reponse : {"p":<base64 du JSON d_j>,"s":HMAC(meme cle,
 *   "qovi-pub-v1\n"+Op+"\n"+n+"\n"+sha256hex(p))} ; toute autre reponse est REJETEE.
 * Prerequis : horloge a l'heure (NTP), a +-60 s. Certificat TLS verifie. */
#ifndef QOVI_REST_H
#define QOVI_REST_H

#include <stddef.h>
#include "qovi_conf.h"

/* Type de cle « Login » : constante PUBLIQUE, identique pour tous les sites */
#define QOVI_KEY_LOGIN_US "6a9e175844d0ef2012fe7848af6c1924f1eb22fee7ac1ee8a589427c72e83613" /* gitleaks:allow (constante publique) */

typedef enum {
    Q_R_OK = 0,      /* reponse signee et positive                          */
    Q_R_KO,          /* reponse signee : refus (adresse inconnue, fin refusee) */
    Q_R_KEY,         /* cle du site absente ou mal formee                    */
    Q_R_NET,         /* Qovi injoignable                                     */
    Q_R_REFUSED,     /* reponse non signee : Qovi refuse la requete (cle ?)  */
    Q_R_SIG,         /* signature de la reponse fausse : reponse falsifiee   */
    Q_R_BAD          /* reponse illisible                                    */
} q_rest_rc;

const char *q_rest_rc_text(q_rest_rc rc);

/* Ouvre une transaction pour edr ; subj = raison affichee sur le mobile.
 * Q_R_OK : nap recoit le jeton (SECRET). Q_R_KO : raison dans msg. */
q_rest_rc q_rest_sit_1_edr(const q_conf *c, const char *edr, const char *subj,
                           char *nap, size_t napcap, char *msg, size_t msgcap, int timeout_ms);

/* Fin de login : Qovi CONFIRME le verdict (usage unique). Q_R_OK seulement si
 * a.ok est vrai ; edr_ok recoit l'adresse validee par Qovi. */
q_rest_rc q_rest_sit_3_end(const q_conf *c, const char *g_json, const char *nap,
                           const char *edr, char *edr_ok, size_t cap, int timeout_ms);

/* --- briques pures, exposees pour les tests --- */
int  q_rest_sit_pub(const char *prv_hex, char k[65]);
int  q_rest_sign(const char *prv_hex, const char *proc, const char *k, long long t,
                 const char *n, const char *p, char s[65]);
int  q_rest_verify(const char *prv_hex, const char *proc, const char *n,
                   const char *p, const char *s);
/* Reponse HTTP brute -> statut et corps (pointeur dans raw, dechunke sur place).
 * 0 = ok */
int  q_http_parse(char *raw, size_t n, int *status, char **body, size_t *blen);
/* "https://hote[:port]/chemin" -> morceaux. 0 = ok */
int  q_url_split(const char *url, char *host, size_t hcap, int *port, char *path, size_t pcap);

#endif
