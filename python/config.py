#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Marc Gandar
# config.py -- configuration du service TuIp.
# TuIp DETIENT la cle privee du site ; les applications clientes ne la
# connaissent jamais. La cle n'est PAS ecrite ici : elle est lue, dans l'ordre,
#   1. dans la variable d'environnement QOVI_PRV_US,
#   2. dans le fichier /etc/qovi-tui.conf (ligne « prv_us = ... »), lisible par
#      le seul utilisateur du service (chmod 600).
# Ainsi la cle n'entre jamais dans un depot de sources.
import os

def _conf(path='/etc/qovi-tui.conf'):
    d = {}
    try:
        with open(path, encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    k, v = line.split('=', 1); d[k.strip()] = v.strip()
    except OSError:
        pass
    return d

_c = _conf(os.environ.get('QOVI_TUI_CONF', '/etc/qovi-tui.conf'))

QOVI_API_URL = os.environ.get('QOVI_API_URL') or _c.get('api_url', 'https://qovi.ch/RST')
QOVI_Prv_Us  = os.environ.get('QOVI_PRV_US') or _c.get('prv_us', '')
CH4_PORT     = int(_c.get('ch4_port', '6404'))

TUI_HOST = '127.0.0.1'   # localhost uniquement (machine de confiance)
TUI_PORT = int(_c.get('port', '7777'))
VOTE_TIMEOUT = min(int(_c.get('timeout', '120')), 130)   # plafond : 130 s
