/* SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 Marc Gandar
 *
 * qovi_codec.h -- briques sans dependance : base64, hexadecimal, jeton.
 * Toutes les fonctions sont bornees : elles refusent plutot que deborder. */
#ifndef QOVI_CODEC_H
#define QOVI_CODEC_H

#include <stddef.h>
#include <stdint.h>

/* Base64 standard (avec '='). Renvoie la longueur ecrite (hors NUL),
 * ou 0 si le tampon est trop petit (n == 0 donne "" et renvoie 0). */
size_t q_b64_encode(const unsigned char *in, size_t n, char *out, size_t cap);
size_t q_b64_encoded_len(size_t n);                 /* sans le NUL final */

/* Decodage STRICT (alphabet, longueur multiple de 4, '=' en fin seulement).
 * Renvoie le nombre d'octets, ou -1 (entree invalide ou tampon trop petit). */
long q_b64_decode(const char *in, size_t n, unsigned char *out, size_t cap);

/* Hexadecimal (sans separateur) -> octets. Renvoie le nombre d'octets, -1 sinon */
int  q_hex_decode(const char *hex, unsigned char *out, size_t cap);
/* Octets -> hexadecimal minuscule ; out doit faire 2n+1 octets */
void q_hex_encode(const unsigned char *in, size_t n, char *out);

/* Jeton de transaction (UUID, tirets ignores) -> 16 octets. 0 = ok, -1 sinon
 * (il faut exactement 32 chiffres hexadecimaux). */
int q_key_from_uuid(const char *uuid, unsigned char key[16]);

/* 1 si la chaine est un UUID acceptable : 32 hex, tirets permis, <= 36
 * caracteres. Garantit qu'on peut l'inserer telle quelle dans du JSON. */
int q_uuid_valid(const char *uuid);

/* Effacement d'un secret en memoire, non supprimable par l'optimiseur */
void q_secure_zero(void *p, size_t n);

#endif
