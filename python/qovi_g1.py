#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Marc Gandar
# qovi_g1.py -- enveloppe « G1 » du canal CH4 (chiffrement AUTHENTIFIE).
#
#   Format  : "G1" + base64( nonce(12) + AES-256-GCM(clair) + tag(16) )
#   Cle     : HMAC-SHA256(cle de transaction, "qovi-ch4-gcm")  -> 32 octets
#   kid     : 16 premiers octets de HMAC-SHA256(cle, "qovi-ch4-kid"), en hexa :
#             identifiant PUBLIC de la transaction (la cle ne circule jamais)
#   AAD     : "ch4q|<kid>" vers Qovi, "ch4r|<kid>" vers le client : un message
#             ne se rejoue ni dans l'autre sens ni dans une autre transaction.
#
# Isole et commente pour servir de MODELE de portage (C, C#, Java, Go...).
# Dependance : cryptography (paquet Debian : python3-cryptography).
# Auto-test : python3 qovi_g1.py   (vecteurs officiels de Qovi)
import base64, hashlib, hmac, os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

LBL_KEY = b'qovi-ch4-gcm'
LBL_KID = b'qovi-ch4-kid'

def _raw(key_hex):
    """Cle hexa (avec ou sans tirets) -> octets. ValueError si invalide."""
    h = key_hex.replace('-', '').strip().lower()
    if not h or len(h) % 2: raise ValueError('cle hexa invalide')
    return bytes.fromhex(h)

def ch4_kid(nap):
    return hmac.new(_raw(nap), LBL_KID, hashlib.sha256).digest()[:16].hex()

def ch4_key(nap):
    return hmac.new(_raw(nap), LBL_KEY, hashlib.sha256).digest()

def seal(key, aad, plain, nonce=None):
    """Chiffre et authentifie. nonce : seulement pour les tests."""
    n = nonce if nonce is not None else os.urandom(12)
    ct = AESGCM(key).encrypt(n, plain.encode('utf-8'), aad.encode('utf-8'))
    return 'G1' + base64.b64encode(n + ct).decode('ascii')

def open_(key, aad, msg):
    """Dechiffre ; None si le message est faux, modifie ou pas pour nous."""
    try:
        if not msg.startswith('G1'): return None
        raw = base64.b64decode(msg[2:], validate=True)
        if len(raw) < 12 + 16: return None
        return AESGCM(key).decrypt(raw[:12], raw[12:], aad.encode('utf-8')).decode('utf-8')
    except Exception:
        return None

def selftest():
    nap = '00112233-4455-6677-8899-aabbccddeeff'
    nonce = bytes(range(12))
    kid, key = ch4_kid(nap), ch4_key(nap)
    ok = True
    def chk(nom, got, exp):
        nonlocal ok
        r = got == exp; ok = ok and r
        print(f"  {'ok' if r else 'KO'}  {nom}")
    chk('kid', kid, 'a4f924e70fae786bef2ae0474f7d8ecb')
    chk('cle', key.hex(), 'decab4d165d801e21955e9d913fe92531dc53bd71d404103c0e4ce95da710893')
    chk('1re trame', kid + seal(key, 'ch4q|' + kid, '{"g":{},"c":{"i":1}}', nonce),
        'a4f924e70fae786bef2ae0474f7d8ecbG1AAECAwQFBgcICQoLnF+p2QbBTdq7+MXTrq70yJOM2J+2K2KwOwYfA07NbuOYml+t')
    rep = 'G1AAECAwQFBgcICQoLnF+akkyYCo276cXT5/Hg/6TTBvdkE3yTV0NxV0SKlg=='
    chk('reponse', open_(key, 'ch4r|' + kid, rep), '{"Tip":{"r":2}}')
    chk('reponse dans le mauvais sens refusee', open_(key, 'ch4q|' + kid, rep), None)
    chk('reponse modifiee refusee', open_(key, 'ch4r|' + kid, rep[:-4] + 'AAA='), None)
    print('### G1 : ' + ('OK' if ok else 'KO'))
    return ok

if __name__ == '__main__':
    raise SystemExit(0 if selftest() else 1)
