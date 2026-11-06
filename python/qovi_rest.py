#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Marc Gandar
# qovi_rest.py -- appels REST SIGNES vers Qovi (meme protocole que qovi_sign.php
# des kits PHP). La cle privee du site ne quitte JAMAIS cette machine : elle sert
# seulement a SIGNER la requete et a VERIFIER la reponse.
#
# Requete : POST <api>/<Op>, corps JSON
#   {"v":1, "k":<id public du site>, "t":<secondes UTC>, "n":<nonce hex32>,
#    "p":<base64 du JSON x_j>, "s":<HMAC-SHA256 hex>}
#   k = sha256("qovi-sit-pub-v1:" + cle privee)
#   s = HMAC(cle privee en octets, "qovi-sit-v1\n"+Op+"\n"+k+"\n"+t+"\n"+n+"\n"+sha256hex(p))
# Reponse : {"p":<base64 du JSON d_j>, "s":HMAC(meme cle,
#   "qovi-pub-v1\n"+Op+"\n"+n+"\n"+sha256hex(p))} ; toute autre reponse est REJETEE.
# Prerequis : horloge a l'heure (NTP), a +-60 s. Certificat TLS de Qovi verifie.
import base64, hashlib, hmac, json, os, re, ssl, time, uuid, urllib.request, urllib.error

# Type de cle « Login » : constante PUBLIQUE, identique pour tous les sites.
QOVI_KEY_LOGIN_US = '6a9e175844d0ef2012fe7848af6c1924f1eb22fee7ac1ee8a589427c72e83613'  # gitleaks:allow (constante publique)

class QoviError(Exception):
    """code : 'key' (cle absente ou mal formee), 'net' (Qovi injoignable),
    'refused' (reponse non signee : refus de Qovi), 'sig' (signature fausse),
    'bad' (reponse illisible)."""
    def __init__(self, code, detail=''):
        super().__init__(f'{code} {detail}'.strip()); self.code = code

def _prv_bytes(prv):
    p = (prv or '').strip().lower()
    if not re.fullmatch(r'[0-9a-f]{64}', p): raise QoviError('key', 'cle privee absente ou mal formee')
    return p, bytes.fromhex(p)

def sit_pub(prv):
    """Identifiant public du site, derive de sa cle privee."""
    p, _ = _prv_bytes(prv)
    return hashlib.sha256(('qovi-sit-pub-v1:' + p).encode()).hexdigest()

def call(api_url, proc, x_j, prv, timeout=15):
    """Appelle l'Op proc ; renvoie le JSON d_j verifie, sinon QoviError."""
    p_hex, key = _prv_bytes(prv)
    p = base64.b64encode(json.dumps(x_j, separators=(',', ':')).encode()).decode()
    k = sit_pub(p_hex)
    t = int(time.time())
    n = os.urandom(16).hex()
    msg = f'qovi-sit-v1\n{proc}\n{k}\n{t}\n{n}\n' + hashlib.sha256(p.encode()).hexdigest()
    s = hmac.new(key, msg.encode(), hashlib.sha256).hexdigest()
    body = json.dumps({'v': 1, 'k': k, 't': t, 'n': n, 'p': p, 's': s}).encode()
    req = urllib.request.Request(api_url.rstrip('/') + '/' + proc, data=body, method='POST',
                                 headers={'Content-Type': 'application/json', 'User-Agent': 'Qovi_Kit_TuI'})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ssl.create_default_context()) as r:
            raw = r.read()
    except urllib.error.HTTPError as e:      # refus : le corps dit pourquoi, il n'est pas signe
        raw = e.read()
    except Exception as e:
        raise QoviError('net', type(e).__name__)
    try:
        o = json.loads(raw)
        rp, rs = o['p'], o['s']
        if not isinstance(rp, str) or not isinstance(rs, str): raise ValueError
    except Exception:
        raise QoviError('refused')
    exp = hmac.new(key, (f'qovi-pub-v1\n{proc}\n{n}\n' + hashlib.sha256(rp.encode()).hexdigest()).encode(),
                   hashlib.sha256).hexdigest()
    if not hmac.compare_digest(exp, rs.lower()): raise QoviError('sig')
    try:
        d = json.loads(base64.b64decode(rp, validate=True))
        if not isinstance(d, dict): raise ValueError
    except Exception:
        raise QoviError('bad')
    return d

def _utc_ms():
    t = time.time()
    return time.strftime('%Y-%m-%dT%H:%M:%S.', time.gmtime(t)) + f'{int(t * 1000) % 1000:03d}'

def sit_1_edr(api_url, prv, edr, subj, spk_i=1):
    """Ouvre une transaction d'authentification pour l'adresse edr ; subj est
    la raison affichee sur le mobile. Renvoie la reponse complete (dict)."""
    utc = _utc_ms()
    x_j = {'c': {'Key': {'U': QOVI_KEY_LOGIN_US}},
           'g': {'k': [spk_i, spk_i, 1], 'u': str(uuid.uuid4()),
                 'p': {'e': edr, 'r': subj}, 'h': 'TuI', 't': [utc, utc]}}
    return call(api_url, 'SiT_1_Edr', x_j, prv)

def sit_3_end(api_url, prv, g_j, nap, edr):
    """Fin de login : Qovi CONFIRME le verdict (usage unique, 120 s) et renvoie
    l'adresse validee. Renvoie (ok, adresse confirmee)."""
    d = call(api_url, 'SiT_3_End', {'g': g_j or {}, 'c': {'Edr': {'s': edr}, 'NaP': {'u': nap}}}, prv)
    a = d.get('a') or {}
    return (a.get('ok') is True and bool(a.get('Edr')), a.get('Edr', ''))

def extract_nap(data):
    """Jeton de la transaction (a.ChX.Prv.u) : cle du canal CH4, secret."""
    return (((data.get('a') or {}).get('ChX') or {}).get('Prv') or {}).get('u', '')
