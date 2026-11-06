# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Marc Gandar
#
# Makefile -- kit Qovi TuI, partie C (Linux : gcc ; Windows : MSYS2 MinGW-w64)
#   make          compile qovi-tuid (service), qovi-tui (client) et t_unit (tests)
#   make test     autotests + interop avec le Python + faux Qovi + service (sans reseau)
#   make deb      paquet Debian dans dist/ (prerequis : dpkg-dev)
#   make win      qovi-tuid.exe et qovi-tui.exe dans dist-win/ (compilation croisee)
#   make msi      paquet Windows qovi-tui.msi (WiX 5 sur la machine Windows de fabrication)
#   make clean
# Dependances Linux (Debian) : build-essential libssl-dev
#                              + python3-cryptography et openssl pour les tests

CC      ?= cc
CFLAGS  += -std=c11 -O2 -Wall -Wextra -Wpedantic -Wshadow -Wformat=2 -Isrc
LIB     = src/compat.c src/qovi_codec.c src/qovi_crypto.c src/qovi_tls.c src/qovi_conf.c \
          src/qovi_json.c src/qovi_ch4.c src/qovi_rest.c src/qovi_auth.c
HDR     = $(wildcard src/*.h)
CLI     = src/qovi_tui.c src/compat.c src/qovi_json.c

ifeq ($(OS),Windows_NT)
  EXE      = .exe
  CFLAGS  += -D_WIN32_WINNT=0x0600
  LDFLAGS += -static
  SSLLIBS ?= $(shell pkg-config --static --libs libssl libcrypto)
  NETLIBS  = -lws2_32 -liphlpapi
  LDLIBS  += $(SSLLIBS) -lcrypt32 $(NETLIBS)
else
  EXE      =
  # durcissement : protection de pile + controles de debordement glibc
  CFLAGS  += -D_POSIX_C_SOURCE=200809L -fstack-protector-strong -D_FORTIFY_SOURCE=2 -pthread -fPIE
  LDFLAGS += -pie -Wl,-z,relro,-z,now
  SSLLIBS ?= -lssl -lcrypto
  NETLIBS  = -pthread
  LDLIBS  += $(SSLLIBS) -pthread
endif

all: qovi-tuid$(EXE) qovi-tui$(EXE) t_unit$(EXE)

qovi-tuid$(EXE): src/qovi_tuid.c $(LIB) $(HDR)
	$(CC) $(CFLAGS) -o $@ src/qovi_tuid.c $(LIB) $(LDFLAGS) $(LDLIBS)

# le client n'a besoin que des sockets : ni OpenSSL, ni cle
qovi-tui$(EXE): $(CLI) $(HDR)
	$(CC) $(CFLAGS) -o $@ $(CLI) $(LDFLAGS) $(NETLIBS)

t_unit$(EXE): test/t_unit.c $(LIB) $(HDR)
	$(CC) $(CFLAGS) -o $@ test/t_unit.c $(LIB) $(LDFLAGS) $(LDLIBS)

test: all
	./t_unit$(EXE) selftest
	./t_unit$(EXE) net
	python3 test/interop.py
	python3 test/fake_qovi.py
	python3 test/t_service.py

# Windows x64 par compilation croisee (depuis Linux) : dist-win/qovi-tuid.exe et qovi-tui.exe
# Prerequis : mingw-w64 + OpenSSL statique (c/win/build-openssl-mingw.sh)
OSSL_MINGW ?= $(HOME)/.cache/qovi-tui/openssl-3.5.9-mingw64
WCC        ?= x86_64-w64-mingw32-gcc
WFLAGS      = -std=c11 -O2 -Wall -Wextra -Isrc -I$(OSSL_MINGW)/include -D_WIN32_WINNT=0x0601
win: dist-win/qovi-tuid.exe dist-win/qovi-tui.exe

dist-win/qovi-tuid.exe: src/qovi_tuid.c src/qovi_win.c $(LIB) $(HDR)
	@mkdir -p dist-win
	$(WCC) $(WFLAGS) -static -s -o $@ src/qovi_tuid.c src/qovi_win.c $(LIB) $(OSSL_MINGW)/lib/libssl.a $(OSSL_MINGW)/lib/libcrypto.a -lws2_32 -lcrypt32 -liphlpapi -ladvapi32

dist-win/qovi-tui.exe: $(CLI) $(HDR)
	@mkdir -p dist-win
	$(WCC) $(WFLAGS) -static -s -o $@ $(CLI) -lws2_32 -liphlpapi

# paquet Windows : compile ci-dessus puis WiX 5 sur la machine Windows de fabrication
msi: win
	./win/build-msi.sh

# paquet Debian (service systemd + client) : dist/qovi-tui_<version>_<arch>.deb
deb:
	./deb/build-deb.sh

clean:
	rm -f qovi-tuid qovi-tui t_unit qovi-tuid.exe qovi-tui.exe t_unit.exe t_unit_conf.tmp
	rm -rf dist-win

.PHONY: all test deb win msi clean
