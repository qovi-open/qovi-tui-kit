#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Marc Gandar
# t_service.py -- teste le service qovi-tuid et le client qovi-tui SANS reseau.
# On verifie les DEFENSES : entrees piegees, requete geante, client muet,
# journal sans injection ni cle, droits du journal, PID de l'appelant,
# limites 1 demande par adresse et 5 en meme temps, codes de sortie du client.
import json, os, socket, stat, subprocess, sys, tempfile, threading, time

HERE = os.path.dirname(os.path.abspath(__file__))
KIT  = os.path.dirname(HERE)
EXT  = '.exe' if os.name == 'nt' else ''
SVC, CLI = os.path.join(KIT, 'qovi-tuid' + EXT), os.path.join(KIT, 'qovi-tui' + EXT)
HEX  = '0123456789abcdef' * 4

ok = ko = 0
def check(cond, what):
    global ok, ko
    if cond: ok += 1
    else:    ko += 1; print('  ECHEC :', what)

def free_port():
    s = socket.socket(); s.bind(('127.0.0.1', 0)); p = s.getsockname()[1]; s.close(); return p

def ask(port, raw, wait=20):
    with socket.create_connection(('127.0.0.1', port), timeout=wait) as s:
        if raw: s.sendall(raw)
        data = b''
        while not data.endswith(b'\n'):
            d = s.recv(1024)
            if not d: break
            data += d
        return data.decode(errors='replace').strip()

def start(api, work):
    port = free_port()
    conf = os.path.join(work, 'qovi-tui.conf')
    with open(conf, 'w') as f:
        f.write(f'prv_us = {HEX}\napi_url = {api}\nport = {port}\nlog_file = {work}/tui.log\n')
    os.chmod(conf, 0o600)
    p = subprocess.Popen([SVC, conf], cwd=work, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    for _ in range(50):
        try: socket.create_connection(('127.0.0.1', port), timeout=0.2).close(); break
        except OSError: time.sleep(0.1)
    time.sleep(0.3)
    return p, port

def stop(p):
    p.terminate()
    try: return p.communicate(timeout=5)[0]
    except Exception: p.kill(); return ''

# ---------- 1. defenses (Qovi pointe vers un port ferme : erreur reseau rapide)
work = tempfile.mkdtemp(prefix='tuid-test-')
svc, port = start('https://127.0.0.1:1/RST', work)
try:
    r = subprocess.run([CLI, 'login', '--edr', 'sansarobase', '--port', str(port)], capture_output=True, text=True, timeout=30)
    check(r.returncode == 3 and 'adresse invalide' in r.stdout, f'client : adresse sans @ -> erreur 3 ({r.stdout!r})')
    r = subprocess.run([CLI, 'login', '--edr', 'm@x.ch', '--json', '--port', str(port)], capture_output=True, text=True, timeout=30)
    last = json.loads(r.stdout.splitlines()[-1])
    check(r.returncode == 3 and last['ev'] == 'error' and 'injoignable' in last['t'], f'client : jusqu\'au REST ({r.stdout!r})')
    r = subprocess.run([CLI, 'login', '--edr', 'm@x.ch\nGo', '--port', str(port)], capture_output=True, text=True, timeout=30)
    check(r.returncode == 4, 'client : saut de ligne dans l\'adresse -> usage 4')
    r = subprocess.run([CLI, 'login', '--port', str(port)], capture_output=True, text=True, timeout=30)
    check(r.returncode == 4, 'client : --edr manquant -> usage 4')
    r = subprocess.run([CLI, 'login', '--edr', 'm@x.ch', '--port', '0'], capture_output=True, text=True, timeout=30)
    check(r.returncode == 4, 'client : port invalide -> usage 4')
    r = subprocess.run([CLI, 'login', '--edr', 'm@x.ch', '--json', '--port', str(free_port())], capture_output=True, text=True, timeout=30)
    check(r.returncode == 3 and json.loads(r.stdout)['ev'] == 'error', 'client : service absent -> erreur 3')
    mypid = os.getpid()

    rep = ask(port, b'm@x.ch|Connexion test\n')
    check(rep.startswith('Ko Qovi injoignable'), f'CSV valide -> jusqu\'au REST ({rep!r})')
    rep = ask(port, b'm@x.ch|pirate@y.z\n')
    check(rep.startswith('Ko'), f'CSV : seul le 1er | separe ({rep!r})')
    rep = ask(port, json.dumps({'edr': 'm@x.ch\nGo faux', 'subj': 's'}).encode() + b'\n')
    check(json.loads(rep) == {'ev': 'error', 't': 'adresse invalide'}, f'JSON : adresse avec saut de ligne refusee ({rep!r})')
    rep = ask(port, json.dumps({'edr': 'm@x.ch', 'subj': 'Ligne 1\r\nLigne 2'}).encode() + b'\n')
    check(json.loads(rep).get('ev') == 'error' and 'injoignable' in json.loads(rep).get('t', ''), f'JSON : raison sur 2 lignes acceptee jusqu\'au REST ({rep!r})')
    rep = ask(port, json.dumps({'edr': 'm@x.ch', 'subj': 'a\rGo faux'}).encode() + b'\n')
    check(json.loads(rep).get('ev') == 'error' and 'raison invalide' in json.loads(rep).get('t', ''), f'JSON : CR seul refuse ({rep!r})')
    rep = ask(port, b'm@x.ch|sujet\rGo faux\n')
    check(rep.startswith('Ko raison invalide'), f'CSV : controle dans la raison refuse ({rep!r})')
    rep = ask(port, b'{"edr":"m@x.ch"\n')
    check(json.loads(rep) == {'ev': 'error', 't': 'requete JSON invalide (champ edr)'}, f'JSON casse refuse ({rep!r})')
    rep = ask(port, b'A' * 3000)
    check(rep == 'Ko requete trop longue', f'requete geante refusee ({rep!r})')
    t0 = time.time(); rep = ask(port, b'', 20); dt = time.time() - t0
    check(rep == 'Ko delai de requete depasse' and 9 <= dt <= 13, f'client muet coupe apres ~10 s ({rep!r}, {dt:.1f} s)')
    rep = ask(port, b'm@x.ch|apres tout ca\n')
    check(rep.startswith('Ko Qovi injoignable'), f'le service repond toujours ({rep!r})')
finally:
    out = stop(svc)

log = os.path.join(work, 'tui.log')
check(os.path.exists(log), 'journal cree')
if os.path.exists(log):
    txt = open(log, encoding='utf-8', errors='replace').read()
    lines = txt.splitlines()
    check(len(lines) == 13, f'une ligne de journal par demande, sonde comprise ({len(lines)})')
    check(any('<Ligne 1 | Ligne 2>' in l for l in lines), 'raison sur 2 lignes ecrite sur UNE ligne du journal')
    check(all(l[:4].isdigit() for l in lines), 'aucune fausse ligne injectee')
    check(HEX not in txt and HEX not in out, 'aucune cle dans le journal ni la sortie')
    if os.name != 'nt':
        check(stat.S_IMODE(os.stat(log).st_mode) == 0o600, 'journal en 0600')
        check(f'pid={mypid} ' in txt, f'PID de l\'appelant journalise ({mypid})')

# ---------- 2. limites (Qovi « trou noir » : accepte et ne repond jamais)
bh = socket.socket(); bh.bind(('127.0.0.1', 0)); bh.listen(32)
held = []
threading.Thread(target=lambda: [held.append(bh.accept()[0]) for _ in iter(int, 1)], daemon=True).start()
work2 = tempfile.mkdtemp(prefix='tuid-lim-')
svc, port = start(f'https://localhost:{bh.getsockname()[1]}/RST', work2)
try:
    res = {}
    def req(i, edr):
        res[i] = ask(port, json.dumps({'edr': edr, 'subj': 'lim'}).encode() + b'\n', 40)
    th = [threading.Thread(target=req, args=(i, f'u{i}@x.ch')) for i in range(5)]
    for t in th: t.start()
    time.sleep(1.5)
    t0 = time.time()
    same = ask(port, json.dumps({'edr': 'U0@X.CH'}).encode() + b'\n')
    sixth = ask(port, json.dumps({'edr': 'u9@x.ch'}).encode() + b'\n')
    dt = time.time() - t0
    check(json.loads(same) == {'ev': 'error', 't': 'essai deja en cours pour cette adresse'},
          f'1 demande par adresse (casse ignoree) ({same!r})')
    check(json.loads(sixth) == {'ev': 'error', 't': 'service occupe, reessayez'}, f'5 demandes au plus ({sixth!r})')
    check(dt < 2, f'refus immediats ({dt:.1f} s)')
    for t in th: t.join(40)
    check(all(json.loads(res[i])['ev'] == 'error' for i in range(5)), 'les 5 demandes se terminent (Qovi muet)')
    again = ask(port, json.dumps({'edr': 'u0@x.ch'}).encode() + b'\n', 40)
    check(json.loads(again)['ev'] == 'error' and 'cours' not in again, 'places liberees apres coup')
finally:
    stop(svc)

print(f'SERVICE : {ok} ok, {ko} echec(s)')
sys.exit(1 if ko else 0)
