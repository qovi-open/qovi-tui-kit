/* SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 Marc Gandar
 *
 * qovi_win.h -- partie propre a Windows de qovi-tuid (compilee pour Windows
 * seulement) : service Windows, sous-commande « setkey », chemins par defaut.
 *
 *   Service      : nom QoviTuI, compte virtuel « NT SERVICE\QoviTuI »
 *   Configuration: %ProgramData%\Qovi\TuI\qovi-tui.conf
 *   Journal      : %ProgramData%\Qovi\TuI\logs\qovi-tui.log
 *   Droits       : SYSTEM et Administrateurs (controle total), le service en
 *                  LECTURE seule (+ ecriture du seul dossier logs). */
#ifndef QOVI_WIN_H
#define QOVI_WIN_H
#ifdef _WIN32

#include <stddef.h>

#define Q_WIN_SERVICE "QoviTuI"

/* Chemins par defaut (0 = ok) */
int q_win_paths(char *dir, size_t dcap, char *conf, size_t ccap, char *log, size_t lcap);

/* Lance le service : init() puis serve(), sous le controle du gestionnaire
 * de services. Le journal recoit la sortie standard et la sortie d'erreur.
 * init() renvoie 0 ou un code (3 = configuration) qui devient le code
 * d'arret du service. Ne revient qu'en cas d'echec du lancement. */
int q_win_service_run(const char *log_path, int (*init)(void), int (*serve)(void));

/* « qovi-tuid setkey [--file <fichier>] [--api https://...] » (console
 * administrateur). Code de sortie : 0 ok, 1 erreur, 3 cle refusee, 4 usage. */
int q_win_setkey(int argc, char **argv);

#endif
#endif
