#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Marc Gandar
# fake_qovi.py -- test de bout en bout SANS reseau du C : un faux Qovi local
# (HTTPS signe + CH4 TLS/G1, ecrit avec la reference python/qovi_g1.py) contre
# les vrais binaires qovi-tuid et qovi-tui. Verifie : requetes signees, aucune
# cle envoyee, kid a la place du jeton, G1 dans les deux sens, reprise apres
# coupure avec i:1 SEUL, fin de login confirmee, reponses falsifiees refusees,
# certificat inconnu refuse, flux JSON du client.
import base64, hashlib, hmac, http.server, json, os, socket, ssl, struct, subprocess, sys, tempfile, threading, time

HERE = os.path.dirname(os.path.abspath(__file__))
KIT  = os.path.dirname(HERE)
sys.path.insert(0, os.environ.get('TUIP_DIR', os.path.join(os.path.dirname(KIT), 'python')))
import qovi_g1                                       # noqa: E402

EXT = '.exe' if os.name == 'nt' else ''
SVC, CLI = os.path.join(KIT, 'qovi-tuid' + EXT), os.path.join(KIT, 'qovi-tui' + EXT)
D = tempfile.mkdtemp(prefix='tui-fake-')
CRT, KEY = os.path.join(D, 'c.pem'), os.path.join(D, 'k.pem')
subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', KEY, '-out', CRT,
                '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'],
               check=True, capture_output=True)
PRV = os.urandom(32).hex()
NAP = '00112233-4455-6677-8899-aabbccddeeff'
S = {}

def reset(**kw):
    S.clear()
    S.update(cut=False, falsify=False, unknown=False, other_edr=False, verdict=2,
             opens=0, clicks=0, bad=[], seen_prv=False, ops=[])
    S.update(kw)

def sctx():
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); c.load_cert_chain(CRT, KEY); return c

class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_POST(self):
        op = self.path.rsplit('/', 1)[-1]
        raw = self.rfile.read(int(self.headers['Content-Length']))
        if PRV.encode() in raw or PRV.upper().encode() in raw: S['seen_prv'] = True
        r = json.loads(raw)
        key = bytes.fromhex(PRV)
        exp = hmac.new(key, f"qovi-sit-v1\n{op}\n{r['k']}\n{r['t']}\n{r['n']}\n{hashlib.sha256(r['p'].encode()).hexdigest()}".encode(),
                       hashlib.sha256).hexdigest()
        if r.get('v') != 1 or r['k'] != hashlib.sha256(('qovi-sit-pub-v1:' + PRV).encode()).hexdigest() \
                or r['s'] != exp or abs(time.time() - r['t']) > 60:
            S['bad'].append('requete mal signee')
            out = b'{"e":"refus"}'
            self.send_response(403); self.send_header('Content-Length', str(len(out))); self.end_headers(); self.wfile.write(out); return
        x = json.loads(base64.b64decode(r['p']))
        S['ops'].append(op)
        if 'SaM' in json.dumps(x): S['bad'].append('cle envoyee')
        if op == 'SiT_1_Edr':
            if x['c']['Key']['U'] != '6a9e175844d0ef2012fe7848af6c1924f1eb22fee7ac1ee8a589427c72e83613': S['bad'].append('type de cle')
            d = {'Tip': {'r': 1, 's': 'adresse inconnue'}} if S['unknown'] else {'a': {'ChX': {'Prv': {'u': NAP}}}}
        else:
            if x['c']['NaP']['u'] != NAP or x['g'].get('x') != 1: S['bad'].append('SiT_3 incomplet')
            d = {'a': {'ok': True, 'Edr': 'autre@example.com' if S['other_edr'] else x['c']['Edr']['s']}}
        p = base64.b64encode(json.dumps(d).encode()).decode()
        s = hmac.new(key, f"qovi-pub-v1\n{op}\n{r['n']}\n{hashlib.sha256(p.encode()).hexdigest()}".encode(), hashlib.sha256).hexdigest()
        if S['falsify']: s = '0' * 64
        out = json.dumps({'p': p, 's': s}).encode()
        # reponse en morceaux (chunked) une fois sur deux : le C doit lire les deux formes
        if len(S['ops']) % 2:
            self.send_response(200); self.send_header('Content-Length', str(len(out))); self.end_headers(); self.wfile.write(out)
        else:
            self.send_response(200); self.send_header('Transfer-Encoding', 'chunked'); self.end_headers()
            for i in range(0, len(out), 37):
                part = out[i:i + 37]; self.wfile.write(b'%x\r\n%s\r\n' % (len(part), part))
            self.wfile.write(b'0\r\n\r\n')
    protocol_version = 'HTTP/1.1'

def ch4_conn(c):
    kid, key = qovi_g1.ch4_kid(NAP), qovi_g1.ch4_key(NAP)
    try:
        c = sctx().wrap_socket(c, server_side=True)
        buf, first = b'', True
        def send(o):
            p = qovi_g1.seal(key, 'ch4r|' + kid, json.dumps(o)).encode()
            c.sendall(struct.pack('>I', len(p)) + p)
        while True:
            d = c.recv(4096)
            if not d: break
            buf += d
            while len(buf) >= 4:
                (ln,) = struct.unpack('>I', buf[:4])
                if len(buf) < 4 + ln: break
                pl = buf[4:4 + ln].decode(); buf = buf[4 + ln:]
                if NAP.replace('-', '') in pl or NAP in pl: S['bad'].append('jeton en clair sur CH4')
                if first:
                    if pl[:32] != kid: S['bad'].append('kid absent'); return
                    pl = pl[32:]; first = False
                m = json.loads(qovi_g1.open_(key, 'ch4q|' + kid, pl) or 'null')
                if m is None: S['bad'].append('trame G1 refusee'); continue
                send({'g': {}, 'Tip': {'r': 5}})              # bruit : ignore par le client
                c.sendall(struct.pack('>I', 8) + b'G1AAAAAA')   # trame fausse : ignoree
                if m['c']['i'] == 1:
                    S['opens'] += 1
                    if S['opens'] >= 2 or (not S['cut'] and S['clicks']):
                        send({'Tip': {'r': S['verdict'], 's': 'accepte' if S['verdict'] == 2 else 'refuse'}, 'g': {'x': 1}})
                elif m['c']['i'] == 2:
                    S['clicks'] += 1
                    send({'Tip': {'r': 3, 's': 'envoye au mobile'}})
                    if S['cut']: time.sleep(0.3); return
                    send({'Tip': {'r': S['verdict'], 's': 'accepte' if S['verdict'] == 2 else 'refuse'}, 'g': {'x': 1}})
    except Exception:
        pass
    finally:
        c.close()

def ch4_server(ls):
    while True:
        c, _ = ls.accept()
        threading.Thread(target=ch4_conn, args=(c,), daemon=True).start()

hs = http.server.ThreadingHTTPServer(('127.0.0.1', 0), H)
hs.socket = sctx().wrap_socket(hs.socket, server_side=True)
threading.Thread(target=hs.serve_forever, daemon=True).start()
ls = socket.socket(); ls.bind(('127.0.0.1', 0)); ls.listen(8)
threading.Thread(target=ch4_server, args=(ls,), daemon=True).start()

def conf(name, ca=True, port=0):
    p = os.path.join(D, name)
    with open(p, 'w') as f:
        f.write(f'prv_us = {PRV}\napi_url = https://localhost:{hs.server_address[1]}/RST\n'
                f'ch4_port = {ls.getsockname()[1]}\ntimeout = 20\n')
        if ca: f.write(f'ca_file = {CRT}\n')
        if port: f.write(f'port = {port}\n')
    os.chmod(p, 0o600)
    return p

C1, C0 = conf('ok.conf'), conf('sans_ca.conf', ca=False)
ok = ko = 0
def check(cond, what):
    global ok, ko
    if cond: ok += 1; print('  ok  ', what)
    else:    ko += 1; print('  KO  ', what)

def direct(cf, edr='test@example.com'):
    r = subprocess.run([SVC, cf, edr, 'Essai'], capture_output=True, text=True, timeout=60)
    return r.returncode, r.stdout + r.stderr

reset(cut=True)
rc, out = direct(C1)
check(rc == 0 and '=> go' in out, 'Go apres coupure et reprise')
check(S['clicks'] == 1 and S['opens'] == 2, f"un seul clic (i:2), deux ouvertures (i:1) ({S['clicks']}, {S['opens']})")
check(S['ops'] == ['SiT_1_Edr', 'SiT_3_End'], 'SiT_1 puis SiT_3 (fin de login confirmee)')
check(not S['bad'] and not S['seen_prv'], f"aucune anomalie, aucune cle recue {S['bad']}")
check(PRV not in out and NAP not in out, 'ni cle ni jeton dans la sortie')

reset(); rc, out = direct(C1)
check(rc == 0 and '=> go' in out and S['opens'] == 1, 'Go sans coupure')
reset(verdict=1); rc, out = direct(C1)
check(rc == 1 and '=> ko' in out and S['ops'] == ['SiT_1_Edr'], 'Ko du mobile, pas de SiT_3')
reset(falsify=True); rc, out = direct(C1)
check(rc == 3 and 'falsifiee' in out, 'reponse falsifiee refusee')
reset(unknown=True); rc, out = direct(C1)
check(rc == 1 and 'adresse inconnue' in out, 'adresse inconnue : Ko')
reset(other_edr=True); rc, out = direct(C1)
check(rc == 1 and 'fin de login refusee' in out, 'SiT_3 confirme une autre adresse : Ko')
reset(); rc, out = direct(C0)
check(rc == 3 and S['ops'] == [], 'certificat inconnu refuse (rien envoye)')
reset(); rc, out = direct(C1, 'x; rm -rf /')
check(rc == 1 and 'adresse invalide' in out and S['ops'] == [], 'adresse invalide refusee avant tout envoi')

# service + client JSON
s = socket.socket(); s.bind(('127.0.0.1', 0)); port = s.getsockname()[1]; s.close()
svc = subprocess.Popen([SVC, conf('svc.conf', port=port)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
try:
    for _ in range(50):
        try: socket.create_connection(('127.0.0.1', port), timeout=0.2).close(); break
        except OSError: time.sleep(0.1)
    reset(cut=True)
    r = subprocess.run([CLI, 'login', '--edr', 'test@example.com', '--subj', 'Essai JSON', '--json', '--port', str(port)],
                       capture_output=True, text=True, timeout=60)
    ev = [json.loads(l)['ev'] for l in r.stdout.splitlines()]
    check(r.returncode == 0 and ev[0] == 'sent' and 'wait' in ev and ev[-1] == 'go', f'client --json : {ev} code {r.returncode}')
    check(json.loads(r.stdout.splitlines()[-1]).get('edr') == 'test@example.com', 'adresse confirmee dans la ligne go')
    reset(verdict=1)
    r = subprocess.run([CLI, 'login', '--edr', 'test@example.com', '--port', str(port)], capture_output=True, text=True, timeout=60)
    check(r.returncode == 1 and 'Refuse' in r.stdout, 'client texte : Ko, code 1')
    reset()
    r = subprocess.run([CLI, 'login', '--edr', 'test@example.com', '--json', '--port', str(port)],
                       capture_output=True, text=True, timeout=60)
    check(r.returncode == 0, 'le service enchaine les demandes')
finally:
    svc.terminate()
    try: log = svc.communicate(timeout=5)[0]
    except Exception: svc.kill(); log = ''
check(PRV not in log and NAP not in log and 'test@example.com' in log, 'journal : adresse oui, cle et jeton non')

print(f'FAUX QOVI : {ok} ok, {ko} echec(s)')
sys.exit(1 if ko else 0)
