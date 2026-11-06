#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Marc Gandar
# interop.py -- croise le C (t_unit) avec la reference Python du kit
# (python/qovi_g1.py, python/qovi_rest.py), octet par octet :
#   C chiffre -> Python dechiffre  |  Python chiffre -> C dechiffre
#   messages alteres, mauvais sens, mauvaise transaction refuses des DEUX cotes
#   + signature des requetes identique.
import base64, hashlib, hmac, os, subprocess, sys, uuid

HERE = os.path.dirname(os.path.abspath(__file__))
KIT  = os.path.dirname(HERE)
sys.path.insert(0, os.environ.get('TUIP_DIR', os.path.join(os.path.dirname(KIT), 'python')))
import qovi_g1                      # noqa: E402  (reference Python)

EXE = os.path.join(KIT, 't_unit' + ('.exe' if os.name == 'nt' else ''))

def run(*a, data=None):
    r = subprocess.run([EXE, *a], input=data, capture_output=True)
    return r.stdout.decode().strip() if r.returncode == 0 else None

def c_seal(nap, aad, msg): return run('seal', nap, aad, data=msg.encode('utf-8'))
def c_open(nap, aad, m):
    h = run('open', nap, aad, m)
    return bytes.fromhex(h).decode('utf-8') if h is not None else None

def tamper(m):
    i = len(m) // 2
    return m[:i] + ('B' if m[i] == 'A' else 'A') + m[i + 1:]

ok = ko = 0
def check(cond, what):
    global ok, ko
    if cond: ok += 1
    else:    ko += 1; print('  ECHEC :', what)

MSGS = ['', 'a', 'x' * 15, 'x' * 16, 'x' * 17, '{"g":{},"c":{"i":1}}',
        '{"Tip":{"r":2,"s":"accepté"},"g":{"k":[1,1,1]}}', 'Accents éàüç — € 日本', 'z' * 3000]

for i, msg in enumerate(MSGS):
    nap = str(uuid.uuid4())
    if i % 3 == 1: nap = nap.upper()
    if i % 3 == 2: nap = nap.replace('-', '')
    other = str(uuid.uuid4())
    kid, key = qovi_g1.ch4_kid(nap), qovi_g1.ch4_key(nap)
    tag = f'cas {i} ({len(msg)} car.)'
    check(run('kid', nap) == f'{kid} {key.hex()}', f'{tag} meme kid et meme cle')
    aq, ar = 'ch4q|' + kid, 'ch4r|' + kid

    cm = c_seal(nap, aq, msg)
    check(cm is not None and qovi_g1.open_(key, aq, cm) == msg, f'{tag} C -> Python')
    pm = qovi_g1.seal(key, ar, msg)
    check(c_open(nap, ar, pm) == msg, f'{tag} Python -> C')
    check(c_open(nap, aq, pm) is None, f'{tag} mauvais sens refuse par C')
    check(c_open(other, ar, pm) is None, f'{tag} autre transaction refusee par C')
    check(c_open(nap, ar, tamper(pm)) is None, f'{tag} message Python altere refuse par C')
    if cm:
        check(qovi_g1.open_(key, ar, cm) is None, f'{tag} mauvais sens refuse par Python')
        check(qovi_g1.open_(key, aq, tamper(cm)) is None, f'{tag} message C altere refuse par Python')

# nonce impose : sortie identique a l'octet pres
nap = str(uuid.uuid4()); kid, key = qovi_g1.ch4_kid(nap), qovi_g1.ch4_key(nap)
nonce = os.urandom(12)
check(run('seal', nap, 'ch4q|' + kid, nonce.hex(), data=b'{"g":{},"c":{"i":2}}') ==
      qovi_g1.seal(key, 'ch4q|' + kid, '{"g":{},"c":{"i":2}}', nonce), 'G1 identique a nonce egal')

# signature des requetes (meme calcul que python/qovi_rest.py)
for _ in range(5):
    prv, n, t = os.urandom(32).hex(), os.urandom(16).hex(), 1762160000
    p = base64.b64encode(os.urandom(40)).decode()
    k = hashlib.sha256(('qovi-sit-pub-v1:' + prv).encode()).hexdigest()
    s = hmac.new(bytes.fromhex(prv), f'qovi-sit-v1\nSiT_3_End\n{k}\n{t}\n{n}\n'.encode() +
                 hashlib.sha256(p.encode()).hexdigest().encode(), hashlib.sha256).hexdigest()
    check(run('sign', prv, 'SiT_3_End', str(t), n, p) == f'{k} {s}', 'signature identique au Python')

print(f'INTEROP : {ok} ok, {ko} echec(s)')
sys.exit(1 if ko else 0)
