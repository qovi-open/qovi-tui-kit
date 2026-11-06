/* SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 Marc Gandar
 *
 * qovi_ch4.h -- canal CH4 vers Qovi (TLS + enveloppe G1), cycle complet :
 *   ouverture (i:1) -> clic (i:2) -> « envoye au mobile » -> vote -> GO / KO.
 *
 *   Transport : TLS vers <hote>:6404, certificat et nom d'hote verifies.
 *   Framing   : [4 octets big-endian = longueur][payload]
 *   1re trame : kid + G1({"g":{},"c":{"i":1}})   (kid = identifiant PUBLIC)
 *   suivantes : G1(...) ; reponses : G1(...)      (voir qovi_crypto.h)
 *   Coupure   : si la connexion tombe, UNE reprise avec i:1 SEUL (renvoyer i:2
 *               relancerait le vote) ; Qovi renvoie alors le dernier verdict.
 *
 * RAPPEL SECURITE : le verdict CH4 est un SIGNAL ; il est TOUJOURS confirme
 * par SiT_3_End (voir qovi_auth.c). */
#ifndef QOVI_CH4_H
#define QOVI_CH4_H

#include <stddef.h>

#define Q_RES_KO 1
#define Q_RES_GO 2
#define Q_RES_OK 3
#define Q_RES_OG 7

typedef enum { Q_CH4_GO, Q_CH4_KO, Q_CH4_TIMEOUT, Q_CH4_ERR } q_ch4_verdict;

/* Rappel pour les etats intermediaires (RES_OK / RES_OG). Peut etre NULL. */
typedef void (*q_ch4_status_cb)(int r, const char *s, void *ud);

/* nap : jeton de transaction (UUID, SECRET, ne circule pas). text : message du
 * serveur ou de l'erreur. g_out (si non NULL) : objet JSON "g" du GO (malloc). */
q_ch4_verdict q_ch4_authenticate(const char *host, int port, const char *nap,
                                 int timeout_s, q_ch4_status_cb cb, void *ud,
                                 char *text, size_t textcap, char **g_out);

const char *q_ch4_verdict_name(q_ch4_verdict v);

#endif
