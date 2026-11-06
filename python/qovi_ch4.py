#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Marc Gandar
# qovi_ch4.py -- canal CH4 vers Qovi (TLS + enveloppe G1). Cycle complet :
#   ouverture (i:1) -> clic (i:2) -> « envoye au mobile » -> vote -> GO / KO.
#
#   Transport : TLS vers <hote>:6404, certificat verifie.
#   Framing   : [4 octets big-endian = longueur][payload UTF-8]
#   1re trame : kid + G1({"g":..,"c":{"i":1}})   (kid = identifiant PUBLIC)
#   suivantes : G1(...) ; reponses : G1(...)      (voir qovi_g1.py)
#   Coupure   : si la connexion tombe apres le clic, UNE reprise avec i:1 SEUL
#               (renvoyer i:2 relancerait le vote) ; Qovi renvoie alors le
#               dernier verdict (130 s).
#
# Isole et commente pour servir de MODELE de portage (C, C#, Java, Go...).
import json, socket, ssl, struct, sys, time
from qovi_g1 import ch4_kid, ch4_key, seal, open_

RES_KO, RES_GO, RES_OK, RES_OG = 1, 2, 3, 7      # cf. composant Qovi
MAX_FRAME = 64 * 1024

def _frame(p): return struct.pack('>I', len(p)) + p

def _connect(host, port):
    ctx = ssl.create_default_context()           # certificat et nom d'hote verifies
    raw = socket.create_connection((host, port), timeout=10)
    return ctx.wrap_socket(raw, server_hostname=host)

def ch4_authenticate(host, port, nap, g_j=None, timeout=120, on_status=None):
    """Ouvre CH4, envoie le clic, attend le verdict.
    Retourne (verdict, texte, g) avec verdict in {'GO','KO','TIMEOUT','ERR'}."""
    g_j = g_j or {}
    kid, key = ch4_kid(nap), ch4_key(nap)
    aad_q, aad_r = 'ch4q|' + kid, 'ch4r|' + kid
    enc = lambda c: seal(key, aad_q, json.dumps({'g': g_j, 'c': c}, separators=(',', ':'))).encode()
    fin = {'v': None, 't': '', 'g': None}

    def on_frame(pl):
        clr = open_(key, aad_r, pl.decode('utf-8', 'replace'))
        if clr is None: return                    # trame fausse ou pas pour nous : ignoree
        try: msg = json.loads(clr)
        except ValueError: return
        tip = msg.get('Tip') if isinstance(msg, dict) else None
        if not isinstance(tip, dict): return
        r, st = tip.get('r'), tip.get('s', '')
        if r in (RES_OK, RES_OG):
            if on_status: on_status(r, st or 'demande envoyee au mobile, vote en attente')
        elif r == RES_GO: fin.update(v='GO', t=st or 'accepte', g=msg.get('g'))
        elif r == RES_KO: fin.update(v='KO', t=st or 'refuse')

    t0 = time.time()
    clicked, retried = False, False
    while fin['v'] is None and time.time() - t0 < timeout:
        try:
            s = _connect(host, port)
        except (OSError, ssl.SSLError) as e:
            return ('ERR', f'connexion CH4 impossible ({type(e).__name__})', None)
        buf = b''
        try:
            s.sendall(_frame(kid.encode() + enc({'i': 1})))
            if not clicked:
                time.sleep(0.5)   # comme bin/test_ch4_g1.dart (clic trop tot = perdu)
                s.sendall(_frame(enc({'i': 2}))); clicked = True
            s.settimeout(2)
            while fin['v'] is None and time.time() - t0 < timeout:
                try: data = s.recv(4096)
                except socket.timeout: continue
                if not data: break                # coupure
                buf += data
                while len(buf) >= 4:
                    (ln,) = struct.unpack('>I', buf[:4])
                    if ln > MAX_FRAME: raise ValueError('trame trop longue')
                    if len(buf) < 4 + ln: break
                    on_frame(buf[4:4 + ln]); buf = buf[4 + ln:]
        except (OSError, ssl.SSLError, ValueError):
            pass
        finally:
            s.close()
        if fin['v'] is None:
            if retried: break
            retried = True                        # une seule reprise, avec i:1 seul
            time.sleep(1)
    if fin['v']: return (fin['v'], fin['t'], fin['g'])
    if time.time() - t0 >= timeout: return ('TIMEOUT', 'aucun vote dans le delai', None)
    return ('ERR', 'connexion CH4 perdue', None)

if __name__ == '__main__':
    if len(sys.argv) < 4: print('Usage: qovi_ch4.py <hote> <port> <jeton>'); sys.exit(2)
    v, t, _g = ch4_authenticate(sys.argv[1], int(sys.argv[2]), sys.argv[3],
                                on_status=lambda r, s: print(f'   ... {s}'))
    print(f'=> VERDICT: {v}  ({t})')
