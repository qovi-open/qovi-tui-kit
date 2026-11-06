#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Marc Gandar
#
# build-openssl-mingw.sh -- OpenSSL STATIQUE pour Windows x64, par compilation
# croisee MinGW depuis Linux (les .exe de TuI n'ont alors besoin d'aucune DLL).
#
#   c/win/build-openssl-mingw.sh [version]      (defaut : 3.5.9, LTS jusqu'en 2030)
#
# Resultat : ~/.cache/qovi-tui/openssl-<version>-mingw64/{include,lib,LICENSE-OpenSSL.txt}
#
# SECURITE (KO de Git du 03.11) : OpenSSL grave dans les .exe ses dossiers
# OPENSSLDIR, ENGINESDIR et MODULESDIR. Un dossier de fabrication (/home/...)
# deviendrait sous Windows C:\home\..., creable par tout usager, qui pourrait y
# poser un openssl.cnf faisant charger son module DANS le service (lecteur de
# la cle du site). D'ou :
#   - no-autoload-config : aucun openssl.cnf n'est lu ;
#   - no-dso, no-engine  : aucun module ni moteur ne peut etre charge ;
#   - --prefix/--openssldir dans Program Files\Qovi\TuI (administrateurs seuls),
#     valeurs inertes de toute facon ;
#   - rien n'est « installe » : bibliotheques et en-tetes copies depuis l'arbre
#     de compilation vers le cache (le cache n'apparait dans aucun .exe).
# build-msi.sh refuse ensuite tout .exe contenant /home/, wlexit ou .cache/.
# Prerequis (Debian) : mingw-w64 gnupg curl perl make
# L'archive est VERIFIEE par sa signature PGP : seule la cle de publication
# d'OpenSSL (empreinte epinglee ci-dessous, publiee sur openssl-library.org)
# est acceptee. Rien n'est compile sinon.
set -euo pipefail
VER=${1:-3.5.9}
FPR=B146647E45A7B33947AB226B2A2C87D161692D40
PREFIX=${QOVI_OSSL_MINGW:-$HOME/.cache/qovi-tui/openssl-$VER-mingw64}
WINDIR="C:/Program Files/Qovi/TuI"
OPTS="mingw64 no-shared no-dso no-engine no-autoload-config no-tests no-docs"
SIG="$VER | $OPTS | $WINDIR | ssl"
if [ -f "$PREFIX/lib/libssl.a" ] && [ -f "$PREFIX/lib/libcrypto.a" ] && [ -f "$PREFIX/LICENSE-OpenSSL.txt" ] && [ "$(cat "$PREFIX/qovi-build.txt" 2>/dev/null)" = "$SIG" ]; then echo "deja construit : $PREFIX"; exit 0; fi
rm -rf "$PREFIX"
for c in x86_64-w64-mingw32-gcc gpg curl perl make; do command -v "$c" >/dev/null || { echo "ERREUR : $c absent (sudo apt install mingw-w64 gnupg curl perl make)"; exit 1; }; done
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
cd "$W"
URL=https://github.com/openssl/openssl/releases/download/openssl-$VER/openssl-$VER.tar.gz
echo "== telechargement d'OpenSSL $VER"
curl -fsSL -o o.tar.gz "$URL"
curl -fsSL -o o.tar.gz.asc "$URL.asc"
curl -fsSL -o pubkeys.asc https://openssl-library.org/source/pubkeys.asc
export GNUPGHOME=$W/gnupg; mkdir -m 700 "$GNUPGHOME"
gpg --batch --quiet --import pubkeys.asc 2>/dev/null
# VALIDSIG : le dernier champ est l'empreinte de la cle PRINCIPALE qui a signe
if ! gpg --batch --status-fd 1 --verify o.tar.gz.asc o.tar.gz 2>/dev/null | awk -v f="$FPR" '$2=="VALIDSIG" && $NF==f {ok=1} END {exit !ok}'; then
    echo "ERREUR : signature PGP d'OpenSSL absente ou fausse : rien n'est compile"; exit 1
fi
echo "== signature d'OpenSSL verifiee (cle $FPR)"
sha256sum o.tar.gz
tar xzf o.tar.gz
cd "openssl-$VER"
echo "== compilation (quelques minutes)"
# shellcheck disable=SC2086
./Configure $OPTS --cross-compile-prefix=x86_64-w64-mingw32- --prefix="$WINDIR" --openssldir=ssl --libdir=lib > "$W/configure.log" 2>&1 || { tail -20 "$W/configure.log"; exit 1; }
make -j"$(nproc)" build_libs > "$W/make.log" 2>&1 || { tail -30 "$W/make.log"; exit 1; }
mkdir -p "$PREFIX/lib" "$PREFIX/include"
cp libssl.a libcrypto.a "$PREFIX/lib/"
cp -r include/openssl "$PREFIX/include/"
cp LICENSE.txt "$PREFIX/LICENSE-OpenSSL.txt"     # a livrer avec les .exe (Apache-2.0)
echo "$SIG" > "$PREFIX/qovi-build.txt"
ls -l "$PREFIX/lib/libssl.a" "$PREFIX/lib/libcrypto.a"
echo "== OpenSSL $VER statique pour Windows x64 : $PREFIX"
