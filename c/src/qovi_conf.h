/* SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 Marc Gandar
 *
 * qovi_conf.h -- configuration du service TuI, MEME format que le Python :
 *   /etc/qovi-tui.conf (ou le chemin donne), lignes « cle = valeur », # = commentaire
 *     prv_us   = <cle PRIVEE du site, 64 hexa>    (SECRET, fichier en 0600)
 *     api_url  = https://qovi.ch/RST               (defaut)
 *     ch4_port = 6404                              (defaut)
 *     port     = 7777                              (ecoute sur 127.0.0.1)
 *     timeout  = 120                               (attente du vote, 10 a 130 s)
 *     log_file = <chemin>                          (facultatif ; sinon sortie standard)
 *     ca_file  = <chemin>                          (TESTS seulement : autre racine TLS)
 * Variables d'environnement prioritaires : QOVI_PRV_US, QOVI_API_URL.
 * Aucune cle publique : l'identifiant du site est derive de la cle privee, et
 * la cle privee ne sert qu'a SIGNER (elle ne quitte jamais la machine). */
#ifndef QOVI_CONF_H
#define QOVI_CONF_H

#include <stddef.h>

#define Q_DEFAULT_CONF "/etc/qovi-tui.conf"
#define Q_LISTEN_HOST  "127.0.0.1"

typedef struct {
    char api_url[256];
    char prv_us[68];       /* 64 hexa minuscules + NUL (SECRET) */
    int  ch4_port;
    int  port;
    int  vote_timeout;
    char log_file[256];
    char ca_file[256];
} q_conf;

/* Charge et VALIDE. 0 = ok ; sinon -1 et message (sans secret) dans err. */
int  q_conf_load(const char *path, q_conf *c, char *err, size_t errcap);

/* Efface les secrets de la structure (a appeler avant de quitter). */
void q_conf_wipe(q_conf *c);

/* Linux : 1 si le fichier est lisible par d'autres que son proprietaire
 * (conseil dans msg). Windows : toujours 0 (ACL posees par l'installeur). */
int  q_conf_too_open(const char *path, char *msg, size_t cap);

#endif
