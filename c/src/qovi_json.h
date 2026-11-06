/* SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 Marc Gandar */
/* qovi_json.h -- mini lecteur/ecrivain JSON, borne, sans dependance.
 *
 * Lecture : on VALIDE tout le document (profondeur max 32), puis on va
 * chercher une valeur par chemin pointe ("a.ChX.Prv.u").
 * Ecriture : q_json_quote() echappe une chaine fournie par un tiers
 * (email, sujet...) -- c'est LA protection contre l'injection de champs. */
#ifndef QOVI_JSON_H
#define QOVI_JSON_H

#include <stddef.h>

/* 1 si json (termine par NUL) est UN document JSON valide */
int  q_json_valid(const char *json);

/* Valeur brute au chemin donne (pointeur dans json + longueur). 0 = trouve */
int  q_json_find(const char *json, const char *path, const char **val, size_t *len);

/* Chaine desechappee (UTF-8) ; -1 si absente, pas une chaine, trop longue,
 * ou contenant \u0000. */
int  q_json_get_str(const char *json, const char *path, char *out, size_t cap);

/* Entier (sans partie decimale ni exposant). 0 = ok */
int  q_json_get_int(const char *json, const char *path, long *out);

/* 1 si la valeur est exactement true */
int  q_json_is_true(const char *json, const char *path);

/* 1 si s[0..n) est de l'UTF-8 valide (sans surlongueurs ni surrogates) */
int  q_utf8_valid(const char *s, size_t n);

/* Chaine JSON entre guillemets, echappee (malloc, a liberer).
 * NULL si s n'est pas de l'UTF-8 valide. */
char *q_json_quote(const char *s);

#endif
