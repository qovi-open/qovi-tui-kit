#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Marc Gandar
# test_fake_qovi.py -- test de bout en bout SANS reseau : un faux Qovi local
# (HTTPS signe + CH4 TLS/G1) et le vrai code de TuIp. Verifie : signature des
# requetes et des reponses, kid a la place de la cle, G1 dans les deux sens,
# reprise apres coupure avec i:1 seul, fin de login confirmee, refus d'une
# reponse falsifiee. Usage : python3 test_fake_qovi.py   (dure ~5 s)
import base64, hashlib, hmac, http.server, json, os, socket, ssl, struct, subprocess, sys, tempfile, threading, time
D = tempfile.mkdtemp()
CRT, KEY = os.path.join(D, 'c.pem'), os.path.join(D, 'k.pem')
subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', KEY, '-out', CRT,
                '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'],
               check=True, capture_output=True)
os.environ['SSL_CERT_FILE'] = CRT
PRV = os.urandom(32).hex()
NAP = '00112233-4455-6677-8899-aabbccddeeff'
os.environ['QOVI_PRV_US'] = PRV
os.environ['QOVI_TUI_CONF'] = os.path.join(D, 'absent.conf')
import qovi_rest, qovi_g1
STATE = {'cut': True, 'falsify': False, 'opens': 0, 'clicks': 0, 'bad': []}

def sctx():
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); c.load_cert_chain(CRT, KEY); return c

class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_POST(self):
        op = self.path.rsplit('/', 1)[-1]
        r = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        key = bytes.fromhex(PRV)
        exp = hmac.new(key, f"qovi-sit-v1\n{op}\n{r['k']}\n{r['t']}\n{r['n']}\n{hashlib.sha256(r['p'].encode()).hexdigest()}".encode(), hashlib.sha256).hexdigest()
        if r['k'] != qovi_rest.sit_pub(PRV) or r['s'] != exp or abs(time.time() - r['t']) > 60:
            STATE['bad'].append('requete mal signee'); self.send_response(403); self.end_headers(); self.wfile.write(b'{"e":"refus"}'); return
        x = json.loads(base64.b64decode(r['p']))
        if 'SaM' in x.get('c', {}): STATE['bad'].append('cle envoyee')
        d = {'a': {'ChX': {'Prv': {'u': NAP}}}} if op == 'SiT_1_Edr' else {'a': {'ok': True, 'Edr': x['c']['Edr']['s']}}
        p = base64.b64encode(json.dumps(d).encode()).decode()
        s = hmac.new(key, f"qovi-pub-v1\n{op}\n{r['n']}\n{hashlib.sha256(p.encode()).hexdigest()}".encode(), hashlib.sha256).hexdigest()
        if STATE['falsify']: s = '0' * 64
        out = json.dumps({'p': p, 's': s}).encode()
        self.send_response(200); self.send_header('Content-Length', str(len(out))); self.end_headers(); self.wfile.write(out)

def ch4_server(lsock):
    kid, key = qovi_g1.ch4_kid(NAP), qovi_g1.ch4_key(NAP)
    while True:
        c, _ = lsock.accept()
        try:
            c = sctx().wrap_socket(c, server_side=True)
            buf = b''; first = True
            send = lambda o: c.sendall((lambda p: struct.pack('>I', len(p)) + p)(qovi_g1.seal(key, 'ch4r|' + kid, json.dumps(o)).encode()))
            while True:
                d = c.recv(4096)
                if not d: break
                buf += d
                while len(buf) >= 4:
                    (ln,) = struct.unpack('>I', buf[:4])
                    if len(buf) < 4 + ln: break
                    pl = buf[4:4 + ln].decode(); buf = buf[4 + ln:]
                    if first:
                        if pl[:32] != kid: STATE['bad'].append('kid absent'); return
                        pl = pl[32:]; first = False
                    m = json.loads(qovi_g1.open_(key, 'ch4q|' + kid, pl) or 'null')
                    if m is None: STATE['bad'].append('trame G1 refusee'); continue
                    if m['c']['i'] == 1:
                        STATE['opens'] += 1
                        if STATE['opens'] == 2: send({'Tip': {'r': 2, 's': 'accepte'}, 'g': {'x': 1}})
                    elif m['c']['i'] == 2:
                        STATE['clicks'] += 1; send({'Tip': {'r': 3}})
                        if STATE['cut']: STATE['cut'] = False; time.sleep(0.3); raise ConnectionError
        except Exception:
            pass
        finally:
            c.close()

def main():
    hs = http.server.HTTPServer(('127.0.0.1', 0), H); hs.socket = sctx().wrap_socket(hs.socket, server_side=True)
    threading.Thread(target=hs.serve_forever, daemon=True).start()
    ls = socket.socket(); ls.bind(('127.0.0.1', 0)); ls.listen(5)
    threading.Thread(target=ch4_server, args=(ls,), daemon=True).start()
    os.environ['QOVI_API_URL'] = f'https://localhost:{hs.server_address[1]}/RST'
    import config; config.QOVI_API_URL = os.environ['QOVI_API_URL']; config.CH4_PORT = ls.getsockname()[1]
    import _tuip
    ok = True
    def chk(nom, cond):
        nonlocal ok; ok = ok and cond; print(f"  {'ok' if cond else 'KO'}  {nom}")
    r = _tuip.authenticate('test@example.com', 'Test')
    chk('verdict Go apres coupure et reprise', r.startswith('Go'))
    chk('un seul clic (i:2), deux ouvertures (i:1)', STATE['clicks'] == 1 and STATE['opens'] == 2)
    chk('aucune anomalie cote serveur ' + str(STATE['bad']), not STATE['bad'])
    STATE['falsify'] = True
    chk('reponse falsifiee refusee', _tuip.authenticate('test@example.com', 'Test').startswith('Ko reponse de Qovi falsifiee'))
    chk('adresse invalide refusee', _tuip.authenticate('x; rm -rf /', 'Test') == 'Ko adresse invalide')
    print('### TuIp contre faux Qovi : ' + ('OK' if ok else 'KO'))
    return ok

if __name__ == '__main__':
    raise SystemExit(0 if main() else 1)
