#!/bin/bash
# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Marc Gandar
#
# build-deb.sh -- fabrique qovi-tui_<version>_<arch>.deb depuis les sources C.
#   cd c && ./deb/build-deb.sh            -> dist/qovi-tui_<version>_<arch>.deb
# Prerequis : build-essential libssl-dev dpkg-dev
set -eu
VERSION=1.0.6
HERE=$(cd "$(dirname "$0")" && pwd)
C=$(dirname "$HERE")
cd "$C"
ARCH=$(dpkg --print-architecture)
OUT="$C/dist"
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
chmod 755 "$STAGE"

make clean >/dev/null
make qovi-tuid qovi-tui >/dev/null
mkdir -p "$STAGE/DEBIAN" "$STAGE/usr/sbin" "$STAGE/usr/bin" "$STAGE/lib/systemd/system" "$STAGE/usr/share/qovi-tui" "$STAGE/usr/share/doc/qovi-tui"
install -m 755 -s qovi-tuid "$STAGE/usr/sbin/qovi-tuid"
install -m 755 -s qovi-tui  "$STAGE/usr/bin/qovi-tui"
install -m 755 deb/qovi-tui-setkey "$STAGE/usr/sbin/qovi-tui-setkey"
install -m 644 deb/qovi-tui.service "$STAGE/lib/systemd/system/qovi-tui.service"
install -m 644 qovi-tui.conf.example "$STAGE/usr/share/qovi-tui/qovi-tui.conf.example"
install -m 644 deb/copyright "$STAGE/usr/share/doc/qovi-tui/copyright"
install -m 755 deb/postinst deb/prerm deb/postrm "$STAGE/DEBIAN/"
make clean >/dev/null

SIZE=$(du -sk --exclude=DEBIAN "$STAGE" | cut -f1)
cat > "$STAGE/DEBIAN/control" <<CTL
Package: qovi-tui
Version: $VERSION
Architecture: $ARCH
Maintainer: Marc Gandar <security@qovi.ch>
Installed-Size: $SIZE
Depends: libc6, libssl3 | libssl3t64, passwd
Section: net
Priority: optional
Homepage: https://qovi.ch/tui/
Description: Qovi TuI - authentification Qovi pour applications locales
 Service qovi-tuid (127.0.0.1) qui detient la cle privee du site et client
 qovi-tui (login --edr <adresse> --json) qui ne la lit jamais. Requetes
 signees, canal CH4 chiffre (TLS + AES-256-GCM), verdict confirme par Qovi.
 Renseigner la cle : sudo qovi-tui-setkey
CTL
( cd "$STAGE" && find usr lib -type f -exec md5sum {} + > DEBIAN/md5sums )
mkdir -p "$OUT"
DEB="$OUT/qovi-tui_${VERSION}_${ARCH}.deb"
dpkg-deb --root-owner-group --build "$STAGE" "$DEB" >/dev/null
echo "$DEB"
