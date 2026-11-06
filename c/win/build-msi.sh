#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Marc Gandar
#
# build-msi.sh -- fabrique qovi-tui.msi : les .exe sont compiles sous Linux
# (make win, compilation croisee), puis le paquet est construit par WiX 5 sur
# une machine Windows joignable en ssh (PowerShell).
#
#   QOVI_WIN_HOST=<machine windows> c/win/build-msi.sh     -> c/dist-win/qovi-tui.msi
#
# Prerequis Windows : WiX 5 (« dotnet tool install --global wix ») dans
# %USERPROFILE%\.dotnet\tools ; l'extension WixToolset.UI.wixext (assistant
# d'installation) est ajoutee au besoin depuis nuget.org.
# Version du paquet = VERSION de deb/build-deb.sh.
set -euo pipefail
H=${QOVI_WIN_HOST:?"QOVI_WIN_HOST : machine Windows de fabrication (ssh, PowerShell)"}
C=$(cd "$(dirname "$0")/.." && pwd)
KIT=$(dirname "$C")
VER=$(sed -n 's/^VERSION=//p' "$C/deb/build-deb.sh")
[ -n "$VER" ] || { echo "ERREUR : version introuvable dans deb/build-deb.sh"; exit 1; }
make -C "$C" -s win
OSSL=${OSSL_MINGW:-$HOME/.cache/qovi-tui/openssl-3.5.9-mingw64}
[ -s "$OSSL/LICENSE-OpenSSL.txt" ] || { echo "ERREUR : $OSSL/LICENSE-OpenSSL.txt absent (relancer c/win/build-openssl-mingw.sh)"; exit 1; }
for f in qovi-tuid.exe qovi-tui.exe; do [ -s "$C/dist-win/$f" ] || { echo "ERREUR : $f absent"; exit 1; }; done
# aucun chemin de la machine de fabrication dans les .exe (KO de Git du 03.11)
for f in qovi-tuid.exe qovi-tui.exe; do
    if strings -a "$C/dist-win/$f" | grep -E '/home/|wlexit|\.cache/'; then echo "ERREUR : $f contient un chemin de fabrication (ci-dessus) : rien n'est fabrique"; exit 1; fi
done
# dossiers OpenSSL graves : exactement ceux-ci (sous Program Files, administrateurs seuls)
D=$(strings -a "$C/dist-win/qovi-tuid.exe" | grep -E '^(OPENSSLDIR|ENGINESDIR|MODULESDIR):' | sort)
E=$(printf '%s\n' 'ENGINESDIR: "C:/Program Files/Qovi/TuI/lib/engines-3"' 'MODULESDIR: "C:/Program Files/Qovi/TuI/lib/ossl-modules"' 'OPENSSLDIR: "C:/Program Files/Qovi/TuI/ssl"' | sort)
[ "$D" = "$E" ] || { echo "ERREUR : dossiers OpenSSL inattendus dans qovi-tuid.exe :"; echo "$D"; exit 1; }
echo "== .exe sans chemin de fabrication ; dossiers OpenSSL graves :"; echo "$D" | sed 's/^/   /'
R='C:\dev\qovi_tui_msi'
ssh -n "$H" "Remove-Item -Recurse -Force $R -ErrorAction SilentlyContinue; New-Item -ItemType Directory $R | Out-Null"
scp -q "$C/dist-win/qovi-tuid.exe" "$C/dist-win/qovi-tui.exe" "$C/win/Product.wxs" "$C/win/qovi-tui.conf.example" "$C/win/License.rtf" "$KIT/README.html" "$KIT/LICENSE" "$KIT/NOTICE" "$OSSL/LICENSE-OpenSSL.txt" "$H:C:/dev/qovi_tui_msi/"
# extension UI de la meme version que WiX (installee une fois, cache global)
ssh -n "$H" "\$env:DOTNET_ROOT=\"\$HOME\\.dotnet\"; \$w=\"\$HOME\\.dotnet\\tools\\wix.exe\"; \$v=(& \$w --version).Split('+')[0]; if (-not ((& \$w extension list -g) -match 'WixToolset.UI.wixext')) { & \$w extension add -g \"WixToolset.UI.wixext/\$v\" }; if (\$LASTEXITCODE -ne 0) { exit 1 }"
ssh -n "$H" "\$env:DOTNET_ROOT=\"\$HOME\\.dotnet\"; Set-Location $R; & \"\$HOME\\.dotnet\\tools\\wix.exe\" build Product.wxs -arch x64 -ext WixToolset.UI.wixext -culture fr-FR -d Ver=$VER -d Src=$R -o qovi-tui.msi; if (\$LASTEXITCODE -ne 0) { exit 1 }"
scp -q "$H:C:/dev/qovi_tui_msi/qovi-tui.msi" "$C/dist-win/qovi-tui.msi"
ls -l "$C/dist-win/qovi-tui.msi"
sha256sum "$C/dist-win/qovi-tui.msi"
echo "== qovi-tui.msi $VER fabrique"
