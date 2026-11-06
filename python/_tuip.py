#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Marc Gandar
# ============================================================================
#  TuIp — service d'authentification Qovi pour applications SANS interface
# ============================================================================
#  Une application locale sans ecran envoie un e-mail a authentifier ; TuIp
#  dialogue avec Qovi, declenche la demande sur le mobile de la personne,
#  attend son vote, et renvoie le verdict.
#
#  DIALOGUE (app <-> TuIp, sur 127.0.0.1:7777) :
#    ->  "email|sujet\n"                (CSV, le plus simple)
#        ou  '{"edr":"..","subj":".."}' (JSON, applications modernes)
#    <-  "Go <txt>" accepte | "Ko <txt>" refuse | "Ok <txt>" en attente
#
#  EN COULISSES (invisible pour l'app) :
#    1. SiT_1_Edr (HTTPS, requete SIGNEE) -> jeton de transaction
#    2. CH4 (TLS + G1)                   -> « clic », attend le vote mobile
#    3. SiT_3_End (SIGNEE)               -> Qovi confirme le verdict
#    4. Ok / Ko / Go                     -> application
#
#  SECURITE : ecoute 127.0.0.1 (meme machine). La cle privee ne quitte jamais
#  ce service. Le controle reste sur le mobile : l'appli ne force rien, seule
#  la personne accepte ou refuse.
# ============================================================================
import socket, json, re, sys, time, subprocess
from urllib.parse import urlsplit
import config
from qovi_rest import sit_1_edr, sit_3_end, extract_nap, QoviError
from qovi_ch4 import ch4_authenticate

LOG_FILE = 'tui.log'

def _parse_request(raw):
    """CSV « edr|subj » OU JSON. '{' -> JSON, sinon CSV."""
    raw = raw.strip()
    if raw.startswith('{'):
        d = json.loads(raw); return d.get('edr',''), d.get('subj','')
    p = raw.split('|', 1); return p[0], (p[1] if len(p) > 1 else '')

def _caller_pid(port_src):
    """Best-effort : PID local ayant ouvert ce port (tracabilite). '?' sinon."""
    try:
        out = subprocess.run(['ss','-tnpH'], capture_output=True, text=True).stdout
        for line in out.splitlines():
            if f':{port_src} ' in line and 'pid=' in line:
                pid = line.split('pid=',1)[1].split(',',1)[0]
                name = line.split('"',2)[1] if '"' in line else ''
                return f'{pid}({name})' if name else pid
    except Exception:
        pass
    return '?'

def _log(pid, edr, subj, verdict):
    try:
        with open(LOG_FILE,'a') as f:
            f.write(f'{time.strftime("%Y-%m-%d %H:%M:%S")} | pid={pid} | {edr} | "{subj}" | {verdict}\n')
    except Exception:
        pass

EDR_RE = re.compile(r'^[^@\s"<>|]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,63}$')

def authenticate(edr, subj):
    """Coeur : email + sujet -> verdict ('Go'/'Ko' + texte)."""
    edr = (edr or '').strip()
    if not EDR_RE.match(edr): return 'Ko adresse invalide'
    subj = (subj or '').strip()[:120]
    try:
        data = sit_1_edr(config.QOVI_API_URL, config.QOVI_Prv_Us, edr, subj)
    except QoviError as e:
        return {'key': 'Ko cle du site absente ou mal formee', 'net': 'Ko Qovi injoignable',
                'refused': 'Ko cle du site refusee par Qovi', 'sig': 'Ko reponse de Qovi falsifiee',
                }.get(e.code, 'Ko reponse de Qovi illisible')
    nap = extract_nap(data)
    if not nap:
        tip = data.get('Tip') or {}
        return f'Ko {tip.get("s", "adresse inconnue ou refusee")}'
    host = urlsplit(config.QOVI_API_URL).hostname
    verdict, text, g_go = ch4_authenticate(host, config.CH4_PORT, nap, timeout=config.VOTE_TIMEOUT)
    if verdict != 'GO':
        return f'Ko {text}'
    # le PuB CONFIRME la fin de login (usage unique) et renvoie l'adresse validee
    try:
        ok, edr_ok = sit_3_end(config.QOVI_API_URL, config.QOVI_Prv_Us, g_go, nap, edr)
    except QoviError as e:
        return f'Ko confirmation impossible ({e.code})'
    return f'Go {text}' if ok and edr_ok.lower() == edr.lower() else 'Ko fin de login refusee'

def serve():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((config.TUI_HOST, config.TUI_PORT)); srv.listen(5)
    print(f"TuIp a l'ecoute sur {config.TUI_HOST}:{config.TUI_PORT} "
          f"(journal: {LOG_FILE}, Ctrl+C pour arreter)")
    try:
        while True:
            conn, addr = srv.accept()
            with conn:
                raw = conn.recv(4096).decode('utf-8','replace')
                if not raw.strip(): continue
                edr, subj = _parse_request(raw)
                pid = _caller_pid(addr[1])
                print(f"  demande : {edr}  <{subj}>  [pid={pid}]")
                reply = authenticate(edr, subj)
                _log(pid, edr, subj, reply)
                print(f"  verdict : {reply}")
                conn.sendall((reply + '\n').encode('utf-8'))
    except KeyboardInterrupt:
        print("\nTuIp arrete.")
    finally:
        srv.close()

if __name__ == '__main__':
    if len(sys.argv) > 1:   # mode direct (test rapide, sans socket) :
        #   python3 _tuip.py <email> [sujet]
        print(authenticate(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else 'Demande directe'))
    else:
        serve()
