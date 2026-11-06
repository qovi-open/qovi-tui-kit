/* SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 Marc Gandar
 *
 * qovi_win.c -- service Windows et « setkey » de qovi-tuid (Windows seulement) */
#ifdef _WIN32
#include "qovi_win.h"
#include "qovi_codec.h"
#include "qovi_conf.h"
#include "qovi_rest.h"
#include <winsock2.h>
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------ chemins */

int q_win_paths(char *dir, size_t dcap, char *conf, size_t ccap, char *log, size_t lcap)
{
    char pd[MAX_PATH];
    DWORD n = GetEnvironmentVariableA("ProgramData", pd, sizeof pd);
    if (n == 0 || n >= sizeof pd) snprintf(pd, sizeof pd, "C:\\ProgramData");
    if (dir  && (size_t)snprintf(dir,  dcap, "%s\\Qovi\\TuI", pd) >= dcap) return -1;
    if (conf && (size_t)snprintf(conf, ccap, "%s\\Qovi\\TuI\\qovi-tui.conf", pd) >= ccap) return -1;
    if (log  && (size_t)snprintf(log,  lcap, "%s\\Qovi\\TuI\\logs\\qovi-tui.log", pd) >= lcap) return -1;
    return 0;
}

/* ------------------------------------------------------------ service */

static SERVICE_STATUS_HANDLE g_ssh;
static SERVICE_STATUS        g_ss;
static int (*g_init)(void);
static int (*g_serve)(void);

static void set_status(DWORD state, DWORD code)
{
    g_ss.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_ss.dwCurrentState = state;
    g_ss.dwControlsAccepted = (state == SERVICE_RUNNING) ? (SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN) : 0;
    g_ss.dwWin32ExitCode = code ? ERROR_SERVICE_SPECIFIC_ERROR : NO_ERROR;
    g_ss.dwServiceSpecificExitCode = code;
    g_ss.dwWaitHint = (state == SERVICE_START_PENDING) ? 10000 : 0;
    if (g_ssh) SetServiceStatus(g_ssh, &g_ss);
}

static DWORD WINAPI svc_handler(DWORD ctrl, DWORD type, LPVOID data, LPVOID ctx)
{
    (void)type; (void)data; (void)ctx;
    if (ctrl == SERVICE_CONTROL_STOP || ctrl == SERVICE_CONTROL_SHUTDOWN) {
        printf("arret du service demande\n");
        fflush(stdout);
        set_status(SERVICE_STOPPED, 0);
        ExitProcess(0);                     /* aucun etat a sauver */
    }
    return NO_ERROR;
}

static void WINAPI svc_main(DWORD argc, LPSTR *argv)
{
    int rc;
    (void)argc; (void)argv;
    g_ssh = RegisterServiceCtrlHandlerExA(Q_WIN_SERVICE, svc_handler, NULL);
    if (!g_ssh) return;
    set_status(SERVICE_START_PENDING, 0);
    rc = g_init();
    if (rc != 0) { set_status(SERVICE_STOPPED, (DWORD)rc); return; }
    set_status(SERVICE_RUNNING, 0);
    rc = g_serve();
    set_status(SERVICE_STOPPED, rc ? (DWORD)rc : 1);
}

int q_win_service_run(const char *log_path, int (*init)(void), int (*serve)(void))
{
    SERVICE_TABLE_ENTRYA table[2];
    g_init = init;
    g_serve = serve;
    /* un service n'a pas de console : sorties vers le journal (si le dossier
     * existe, c'est-a-dire apres un premier « setkey ») */
    if (log_path && *log_path) {
        if (freopen(log_path, "a", stdout)) setvbuf(stdout, NULL, _IOLBF, 4096);
        freopen(log_path, "a", stderr);
    }
    table[0].lpServiceName = (LPSTR)Q_WIN_SERVICE;
    table[0].lpServiceProc = svc_main;
    table[1].lpServiceName = NULL;
    table[1].lpServiceProc = NULL;
    if (!StartServiceCtrlDispatcherA(table)) {
        fprintf(stderr, "qovi-tuid --service : a lancer par le gestionnaire de services Windows\n");
        return 1;
    }
    return 0;
}

/* ------------------------------------------------------------- setkey */

static int is_admin(void)
{
    BYTE sid[SECURITY_MAX_SID_SIZE];
    DWORD n = sizeof sid;
    BOOL member = FALSE;
    if (!CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, sid, &n)) return 0;
    if (!CheckTokenMembership(NULL, sid, &member)) return 0;
    return member ? 1 : 0;
}

/* SID texte du compte virtuel du service (le service doit etre installe) */
static char *service_sid(void)
{
    BYTE sid[SECURITY_MAX_SID_SIZE];
    DWORD sl = sizeof sid, dl = 256;
    char dom[256], *s = NULL;
    SID_NAME_USE use;
    if (!LookupAccountNameA(NULL, "NT SERVICE\\" Q_WIN_SERVICE, sid, &sl, dom, &dl, &use)) return NULL;
    if (!ConvertSidToStringSidA(sid, &s)) return NULL;
    return s;                                 /* LocalFree */
}

/* Pose une DACL PROTEGEE (pas d'heritage du parent) decrite en SDDL */
static int set_acl(const char *path, const char *sddl)
{
    PSECURITY_DESCRIPTOR sd = NULL;
    PACL dacl = NULL;
    BOOL present = FALSE, def = FALSE;
    DWORD rc;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorA(sddl, SDDL_REVISION_1, &sd, NULL)) return -1;
    if (!GetSecurityDescriptorDacl(sd, &present, &dacl, &def) || !present) { LocalFree(sd); return -1; }
    rc = SetNamedSecurityInfoA((LPSTR)path, SE_FILE_OBJECT,
                               DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                               NULL, NULL, dacl, NULL);
    LocalFree(sd);
    return rc == ERROR_SUCCESS ? 0 : -1;
}

/* lecture masquee depuis la console */
static int read_secret(char *buf, size_t cap)
{
    HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    int masked = GetConsoleMode(h, &mode) ? 1 : 0;
    char *r;
    if (masked) SetConsoleMode(h, mode & ~(DWORD)ENABLE_ECHO_INPUT);
    r = fgets(buf, (int)cap, stdin);
    if (masked) SetConsoleMode(h, mode);
    fprintf(stderr, "\n");
    return r ? 0 : -1;
}

/* garde les seuls caracteres utiles, reconnait une cle collee deux fois,
 * exige 64 hexa ; met en minuscules. 0 = ok */
static int normalize_key(char *k)
{
    size_t i, n = 0;
    for (i = 0; k[i]; i++)
        if (!isspace((unsigned char)k[i])) k[n++] = k[i];
    k[n] = '\0';
    if (n == 128 && memcmp(k, k + 64, 64) == 0) {
        k[64] = '\0'; n = 64;
        fprintf(stderr, "(cle collee deux fois : prise une seule fois)\n");
    }
    if (n != 64) return n ? (int)n : -1;
    for (i = 0; i < 64; i++) {
        if (!isxdigit((unsigned char)k[i])) return -2;
        k[i] = (char)tolower((unsigned char)k[i]);
    }
    return 0;
}

static int api_ok(const char *u)
{
    size_t i;
    if (strncmp(u, "https://", 8) != 0 || strlen(u) > 200) return 0;
    for (i = 8; u[i]; i++)
        if (!(isalnum((unsigned char)u[i]) || strchr(".-:/_", u[i]))) return 0;
    return 1;
}

/* efface un fichier apres l'avoir ecrase */
static int shred_file(const char *path)
{
    FILE *f = fopen(path, "r+b");
    long n, i;
    if (f) {
        fseek(f, 0, SEEK_END);
        n = ftell(f);
        fseek(f, 0, SEEK_SET);
        for (i = 0; i < n; i++) fputc(0, f);
        fflush(f);
        fclose(f);
    }
    return DeleteFileA(path) ? 0 : -1;
}

/* arrete puis demarre le service ; 0 si il tourne */
static int restart_service(void)
{
    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    SC_HANDLE svc;
    SERVICE_STATUS st;
    int i, rc = -1;
    if (!scm) return -1;
    svc = OpenServiceA(scm, Q_WIN_SERVICE, SERVICE_START | SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (!svc) { CloseServiceHandle(scm); return -1; }
    ControlService(svc, SERVICE_CONTROL_STOP, &st);
    for (i = 0; i < 50; i++) {
        if (QueryServiceStatus(svc, &st) && st.dwCurrentState == SERVICE_STOPPED) break;
        Sleep(200);
    }
    if (StartServiceA(svc, 0, NULL) || GetLastError() == ERROR_SERVICE_ALREADY_RUNNING) {
        for (i = 0; i < 50; i++) {
            if (QueryServiceStatus(svc, &st)) {
                if (st.dwCurrentState == SERVICE_RUNNING) { Sleep(500); }
                if (st.dwCurrentState == SERVICE_RUNNING && QueryServiceStatus(svc, &st) &&
                    st.dwCurrentState == SERVICE_RUNNING) { rc = 0; break; }
                if (st.dwCurrentState == SERVICE_STOPPED) break;
            }
            Sleep(200);
        }
    }
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return rc;
}

int q_win_setkey(int argc, char **argv)
{
    const char *file = NULL, *api = NULL;
    char key[4200], dir[MAX_PATH], conf[MAX_PATH], logp[MAX_PATH], logs[MAX_PATH], tmp[MAX_PATH + 8];
    char sddl[512], k[65], line[700], *sid = NULL, err[300];
    FILE *in, *out;
    q_conf c;
    int i, rc = 1;

    for (i = 2; i < argc; i++) {
        if (!strcmp(argv[i], "--file") && i + 1 < argc) file = argv[++i];
        else if (!strcmp(argv[i], "--api") && i + 1 < argc) api = argv[++i];
        else { fprintf(stderr, "usage : qovi-tuid setkey [--file <fichier>] [--api https://...]\n"); return 4; }
    }
    if (api && !api_ok(api)) { fprintf(stderr, "--api : adresse https:// invalide\n"); return 4; }
    if (!is_admin()) {
        fprintf(stderr, "a lancer dans une console ADMINISTRATEUR (clic droit : Executer en tant qu'administrateur)\n");
        return 1;
    }
    if (q_win_paths(dir, sizeof dir, conf, sizeof conf, logp, sizeof logp) != 0) return 1;
    snprintf(logs, sizeof logs, "%s\\logs", dir);
    sid = service_sid();
    if (!sid) { fprintf(stderr, "service " Q_WIN_SERVICE " absent : reinstallez Qovi TuI\n"); return 1; }

    /* 1. la cle */
    memset(key, 0, sizeof key);
    if (file) {
        DWORD at = GetFileAttributesA(file);
        size_t n;
        if (at == INVALID_FILE_ATTRIBUTES) {
            fprintf(stderr, "--file : %s introuvable.\n"
                            "Windows masque souvent l'extension : le fichier s'appelle peut-etre %s.txt\n"
                            "(verifiez avec : dir %s*)\n", file, file, file);
            rc = 4; goto out;
        }
        if (at & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) {
            fprintf(stderr, "--file : %s n'est pas un fichier ordinaire\n", file); rc = 4; goto out;
        }
        in = fopen(file, "rb");
        if (!in) { fprintf(stderr, "--file : %s illisible\n", file); goto out; }
        n = fread(key, 1, sizeof key - 1, in);
        fclose(in);
        if (n >= 4096) { fprintf(stderr, "--file : %s est trop gros pour une cle\n", file); goto out; }
        key[n] = '\0';
    } else {
        fprintf(stderr, "Si Windows vient de demander une confirmation, c'etait pour la console administrateur.\n");
        fprintf(stderr, "Colle la cle PRIVEE du site (64 caracteres hexadecimaux, rien ne s'affiche) puis Entree : ");
        if (read_secret(key, sizeof key) != 0) goto out;
    }
    i = normalize_key(key);
    if (i != 0) {
        if (i == -2) fprintf(stderr, "REFUSE : la cle contient des caracteres non hexadecimaux. Rien n'est modifie.\n");
        else fprintf(stderr, "REFUSE : il faut 64 caracteres hexadecimaux, recu %d caracteres. Rien n'est modifie.\n", i > 0 ? i : 0);
        if (!file) fprintf(stderr, "Si le collage est capricieux, enregistrez la cle dans un fichier et utilisez --file.\n");
        rc = 3; goto out;
    }

    /* 2. dossiers et droits : SYSTEM et Administrateurs, service en lecture */
    {   /* %ProgramData%\Qovi puis %ProgramData%\Qovi\TuI */
        char qovi[MAX_PATH], *sl;
        snprintf(qovi, sizeof qovi, "%s", dir);
        sl = strrchr(qovi, '\\');
        if (sl) { *sl = '\0'; CreateDirectoryA(qovi, NULL); }
        CreateDirectoryA(dir, NULL);
    }
    CreateDirectoryA(logs, NULL);
    snprintf(sddl, sizeof sddl, "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;%s)", sid);
    if (set_acl(dir, sddl) != 0) { fprintf(stderr, "droits de %s impossibles a poser\n", dir); goto out; }
    snprintf(sddl, sizeof sddl, "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1301bf;;;%s)", sid);
    if (set_acl(logs, sddl) != 0) { fprintf(stderr, "droits de %s impossibles a poser\n", logs); goto out; }

    /* 3. configuration : on garde les autres lignes, ecriture atomique */
    snprintf(tmp, sizeof tmp, "%s.tmp", conf);
    out = fopen(tmp, "wb");
    if (!out) { fprintf(stderr, "ecriture de %s impossible\n", tmp); goto out; }
    in = fopen(conf, "rb");
    if (in) {
        while (fgets(line, sizeof line, in)) {
            const char *t = line;
            while (*t == ' ' || *t == '\t') t++;
            if (!strncmp(t, "prv_us", 6)) continue;
            if (api && !strncmp(t, "api_url", 7)) continue;
            fputs(line, out);
        }
        fclose(in);
    } else {
        fputs("# qovi-tui.conf -- configuration du service Qovi TuI (ecrite par qovi-tuid setkey)\r\n", out);
    }
    if (api) fprintf(out, "api_url  = %s\r\n", api);
    fprintf(out, "prv_us   = %s\r\n", key);
    fflush(out);
    fclose(out);
    if (!MoveFileExA(tmp, conf, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        DeleteFileA(tmp); fprintf(stderr, "remplacement de %s impossible\n", conf); goto out;
    }
    snprintf(sddl, sizeof sddl, "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GR;;;%s)", sid);
    set_acl(conf, sddl);
    q_secure_zero(line, sizeof line);

    /* 4. bilan : identifiant public et serveur utilise */
    if (q_rest_sit_pub(key, k) == 0) printf("cle enregistree dans %s (identifiant PUBLIC du site : %.12s...)\n", conf, k);
    if (q_conf_load(conf, &c, err, sizeof err) == 0) {
        printf("serveur Qovi : %s (%s)\n", c.api_url,
               strncmp(c.api_url, "https://qovi.ch/", 16) == 0 ? "production" : "autre que la production");
        q_conf_wipe(&c);
    }
    q_secure_zero(key, sizeof key);

    if (file) {
        char r[8] = "";
        fprintf(stderr, "Effacer definitivement le fichier %s, qui contient la cle ? [o/N] ", file);
        if (fgets(r, sizeof r, stdin) && (r[0] == 'o' || r[0] == 'O' || r[0] == 'y' || r[0] == 'Y'))
            printf(shred_file(file) == 0 ? "fichier efface\n" : "ATTENTION : effacement impossible\n");
        else
            printf("ATTENTION : %s contient toujours la cle ; effacez-le des que possible\n", file);
    }

    /* 5. (re)demarrage du service */
    if (restart_service() == 0) { printf("service Qovi TuI demarre\n"); rc = 0; }
    else printf("le service ne demarre pas : voir %s\n", logp);

out:
    q_secure_zero(key, sizeof key);
    if (sid) LocalFree(sid);
    return rc;
}

#endif /* _WIN32 */
