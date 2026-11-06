#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Marc Gandar
# example_client.py — Une application SANS interface s'authentifie via Qovi.
# Regardez comme c'est court : ouvrir un socket, envoyer l'email, lire la
# reponse. Aucune cle. (Le service _tuip.py doit tourner.)
import socket
import config   # pour connaitre le port du service (TUI_PORT)

def qovi_auth(email, sujet, host='127.0.0.1', port=None):
    port = port or config.TUI_PORT
    with socket.create_connection((host, port), timeout=130) as s:
        s.sendall(f'{email}|{sujet}\n'.encode())
        return s.recv(1024).decode().strip()

if __name__ == '__main__':
    r = qovi_auth('info@qovi.ch', 'Connexion au serveur de production')
    print('OK authentifie -' if r.startswith('Go') else 'Refuse -', r[2:].strip())
