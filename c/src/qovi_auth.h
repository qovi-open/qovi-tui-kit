/* SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 Marc Gandar
 *
 * qovi_auth.h -- le COEUR : adresse + raison -> verdict
 *
 *   1. SiT_1_Edr (HTTPS, requete SIGNEE) -> jeton de transaction
 *   2. CH4 (TLS + G1)                    -> clic, attente du vote mobile
 *   3. SiT_3_End (SIGNEE)                -> CONFIRMATION par Qovi (usage unique)
 *
 * REGLE : GO n'est JAMAIS rendu sans l'etape 3 reussie ET l'adresse confirmee
 * identique a celle demandee. Un GO lu sur CH4 seul ne suffit pas.
 * Budget total : 130 s au plus, quelles que soient les attentes du reseau. */
#ifndef QOVI_AUTH_H
#define QOVI_AUTH_H

#include <stddef.h>
#include "qovi_conf.h"

#define Q_EDR_MAX        254
#define Q_SUBJ_MAX       200
#define Q_AUTH_BUDGET_MS 130000

typedef enum { Q_AUTH_GO, Q_AUTH_KO, Q_AUTH_TIMEOUT, Q_AUTH_ERR } q_auth_res;

/* Evenements intermediaires : ev = "sent" (transaction ouverte, demande
 * partie) ou "wait" (Qovi signale la demande sur le mobile ; t = texte). */
typedef void (*q_auth_event_cb)(const char *ev, const char *t, void *ud);

/* Adresse acceptee (meme regle que le Python). 1 = ok */
int q_auth_edr_ok(const char *edr);
/* Raison acceptee : UTF-8, sans caractere de controle, <= Q_SUBJ_MAX octets. 1 = ok */
int q_auth_subj_ok(const char *subj);
/* Idem, mais sur plusieurs lignes (au plus Q_SUBJ_LINES) : seuls les sauts de
 * ligne LF ou CRLF sont admis (jamais un CR seul). Pour les requetes JSON, ou
 * le saut de ligne est echappe ; le format CSV reste sur une ligne. 1 = ok */
#define Q_SUBJ_LINES 10
int q_auth_subj_ml_ok(const char *subj);

/* text : une ligne sans caractere de controle (raison, message du serveur). */
q_auth_res q_authenticate(const q_conf *c, const char *edr, const char *subj,
                          q_auth_event_cb cb, void *ud, char *text, size_t cap);

const char *q_auth_res_name(q_auth_res r);   /* "go" "ko" "timeout" "error" */

#endif
