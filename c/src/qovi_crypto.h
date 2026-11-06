/* SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 Marc Gandar
 *
 * qovi_crypto.h -- primitives de TuI (OpenSSL / libcrypto, API EVP).
 *
 * Enveloppe « G1 » du canal CH4 (identique a python/qovi_g1.py et au serveur) :
 *   cle  = HMAC-SHA256(jeton de transaction en 16 octets, "qovi-ch4-gcm")
 *   kid  = 16 premiers octets de HMAC-SHA256(jeton, "qovi-ch4-kid"), en hexa :
 *          identifiant PUBLIC de la transaction (le jeton ne circule jamais)
 *   msg  = "G1" + base64( nonce(12) + AES-256-GCM(clair) + tag(16) )
 *   AAD  = "ch4q|<kid>" vers Qovi, "ch4r|<kid>" vers le client : un message ne
 *          se rejoue ni dans l'autre sens ni dans une autre transaction.
 * GCM AUTHENTIFIE : un message modifie, ou chiffre avec une autre cle, est
 * refuse (q_g1_open renvoie NULL). */
#ifndef QOVI_CRYPTO_H
#define QOVI_CRYPTO_H

#include <stddef.h>

#define Q_CH4_MAX_CLEAR  (48 * 1024)   /* clair maximal accepte a l'envoi    */
#define Q_CH4_MAX_MSG    (64 * 1024)   /* message G1 maximal en reception    */

/* Octets aleatoires cryptographiques (n <= 1024). 0 = ok */
int  q_random(unsigned char *buf, size_t n);

/* UUID v4 aleatoire, format 8-4-4-4-12 minuscule (out >= 37 octets). 0 = ok */
int  q_uuid4(char *out, size_t cap);

/* SHA-256 en hexadecimal minuscule (out : 65 octets). 0 = ok */
int  q_sha256_hex(const void *data, size_t n, char out[65]);

/* HMAC-SHA256 (out : 32 octets). 0 = ok */
int  q_hmac_sha256(const unsigned char *key, size_t kl, const void *msg, size_t ml,
                   unsigned char out[32]);

/* Comparaison en temps constant. 1 si egal */
int  q_ct_equal(const void *a, const void *b, size_t n);

/* Jeton (UUID) -> kid (32 hexa + NUL) et cle G1 (32 octets). 0 = ok */
int  q_ch4_derive(const char *nap, char kid[33], unsigned char key[32]);

/* Chiffre et authentifie. nonce : NULL (aleatoire) sauf pour les tests.
 * Renvoie "G1..." alloue (free), ou NULL. */
char *q_g1_seal(const unsigned char key[32], const char *aad, const char *plain,
                const unsigned char *nonce);

/* Dechiffre msg[0..n). Renvoie le clair alloue (termine par NUL), ou NULL si
 * le message est faux, modifie, pas pour nous, ou contient un NUL. */
char *q_g1_open(const unsigned char key[32], const char *aad, const char *msg, size_t n);

#endif
