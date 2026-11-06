/* SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 Marc Gandar
 *
 * qovi_tls.h -- client TLS (OpenSSL libssl), commun a CH4 et au HTTPS.
 * TLS 1.2 minimum, certificat ET nom d'hote verifies, toujours.
 * Racines de confiance : celles du systeme (sous Windows : le magasin
 * « ROOT » de Windows), ou un fichier ca_file (tests uniquement). */
#ifndef QOVI_TLS_H
#define QOVI_TLS_H

#include <stddef.h>

typedef struct q_tls q_tls;

/* Une fois au demarrage. ca_file : NULL ou "" = racines du systeme. 0 = ok */
int    q_tls_init(const char *ca_file);
void   q_tls_cleanup(void);

/* Connexion + poignee de main + verification. NULL si echec (raison dans err,
 * sans aucun secret). */
q_tls *q_tls_connect(const char *host, int port, int timeout_ms, char *err, size_t cap);

int    q_tls_send(q_tls *t, const void *buf, size_t n);                 /* 0 = ok */
/* >0 octets lus ; 0 ferme ; -1 erreur ; Q_TIMEOUT (compat.h) */
int    q_tls_recv(q_tls *t, void *buf, size_t cap, int timeout_ms);
void   q_tls_close(q_tls *t);
/* "TLSv1.3"... (pour la trace) */
const char *q_tls_version(q_tls *t);

#endif
