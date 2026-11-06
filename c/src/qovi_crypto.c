/* SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 Marc Gandar
 *
 * qovi_crypto.c -- G1 (AES-256-GCM), HMAC-SHA256, SHA-256, via OpenSSL EVP */
#include "qovi_crypto.h"
#include "qovi_codec.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

int q_random(unsigned char *buf, size_t n)
{
    if (n > 1024) return -1;
    return RAND_bytes(buf, (int)n) == 1 ? 0 : -1;
}

int q_uuid4(char *out, size_t cap)
{
    unsigned char b[16];
    int n;
    if (cap < 37 || q_random(b, sizeof b) != 0) return -1;
    b[6] = (unsigned char)((b[6] & 0x0F) | 0x40);   /* version 4 */
    b[8] = (unsigned char)((b[8] & 0x3F) | 0x80);   /* variante RFC 4122 */
    n = snprintf(out, cap,
        "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]);
    return n == 36 ? 0 : -1;
}

int q_sha256_hex(const void *data, size_t n, char out[65])
{
    unsigned char md[32];
    unsigned int ml = 0;
    if (EVP_Digest(data, n, md, &ml, EVP_sha256(), NULL) != 1 || ml != 32) return -1;
    q_hex_encode(md, 32, out);
    return 0;
}

int q_hmac_sha256(const unsigned char *key, size_t kl, const void *msg, size_t ml,
                  unsigned char out[32])
{
    unsigned int ol = 0;
    if (kl > 1024) return -1;
    if (!HMAC(EVP_sha256(), key, (int)kl, (const unsigned char *)msg, ml, out, &ol) || ol != 32)
        return -1;
    return 0;
}

int q_ct_equal(const void *a, const void *b, size_t n)
{
    return CRYPTO_memcmp(a, b, n) == 0;
}

int q_ch4_derive(const char *nap, char kid[33], unsigned char key[32])
{
    unsigned char raw[16], h[32];
    int rc = -1;
    if (q_key_from_uuid(nap, raw) != 0) return -1;
    if (q_hmac_sha256(raw, 16, "qovi-ch4-kid", 12, h) == 0 &&
        q_hmac_sha256(raw, 16, "qovi-ch4-gcm", 12, key) == 0) {
        q_hex_encode(h, 16, kid);
        rc = 0;
    }
    q_secure_zero(raw, sizeof raw);
    q_secure_zero(h, sizeof h);
    return rc;
}

char *q_g1_seal(const unsigned char key[32], const char *aad, const char *plain,
                const unsigned char *nonce)
{
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char *raw = NULL;
    char *out = NULL;
    size_t pl, rl, ol;
    int l1 = 0, l2 = 0, ok = 0;

    if (!key || !aad || !plain) return NULL;
    pl = strlen(plain);
    if (pl > Q_CH4_MAX_CLEAR) return NULL;
    rl = 12 + pl + 16;
    raw = (unsigned char *)malloc(rl);
    if (!raw) return NULL;
    if (nonce) memcpy(raw, nonce, 12);
    else if (q_random(raw, 12) != 0) goto end;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) goto end;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto end;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1) goto end;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, raw) != 1) goto end;
    if (EVP_EncryptUpdate(ctx, NULL, &l1, (const unsigned char *)aad, (int)strlen(aad)) != 1) goto end;
    if (EVP_EncryptUpdate(ctx, raw + 12, &l1, (const unsigned char *)plain, (int)pl) != 1) goto end;
    if (EVP_EncryptFinal_ex(ctx, raw + 12 + l1, &l2) != 1) goto end;
    if ((size_t)(l1 + l2) != pl) goto end;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, raw + 12 + pl) != 1) goto end;

    ol = q_b64_encoded_len(rl);
    out = (char *)malloc(2 + ol + 1);
    if (!out) goto end;
    out[0] = 'G'; out[1] = '1';
    if (q_b64_encode(raw, rl, out + 2, ol + 1) != ol) goto end;
    ok = 1;

end:
    EVP_CIPHER_CTX_free(ctx);
    if (raw) { q_secure_zero(raw, rl); free(raw); }
    if (!ok) { free(out); out = NULL; }
    return out;
}

char *q_g1_open(const unsigned char key[32], const char *aad, const char *msg, size_t n)
{
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char *raw = NULL, *plain = NULL;
    char *out = NULL;
    long rl = 0;
    size_t cl = 0;
    int l1 = 0, l2 = 0, ok = 0;

    if (!key || !aad || !msg || n < 2 || n > Q_CH4_MAX_MSG) return NULL;
    if (msg[0] != 'G' || msg[1] != '1') return NULL;
    raw = (unsigned char *)malloc(n);
    if (!raw) return NULL;
    rl = q_b64_decode(msg + 2, n - 2, raw, n);
    if (rl < 12 + 16) goto end;
    cl = (size_t)rl - 12 - 16;
    plain = (unsigned char *)malloc(cl + 1);
    if (!plain) goto end;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) goto end;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto end;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1) goto end;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, raw) != 1) goto end;
    if (EVP_DecryptUpdate(ctx, NULL, &l1, (const unsigned char *)aad, (int)strlen(aad)) != 1) goto end;
    if (EVP_DecryptUpdate(ctx, plain, &l1, raw + 12, (int)cl) != 1) goto end;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, raw + 12 + cl) != 1) goto end;
    if (EVP_DecryptFinal_ex(ctx, plain + l1, &l2) != 1) goto end;    /* tag faux : refus */
    if ((size_t)(l1 + l2) != cl) goto end;
    if (memchr(plain, '\0', cl) != NULL) goto end;                     /* NUL interne */
    plain[cl] = '\0';
    out = (char *)plain;
    plain = NULL;
    ok = 1;

end:
    EVP_CIPHER_CTX_free(ctx);
    if (raw) { q_secure_zero(raw, n); free(raw); }
    if (plain) { q_secure_zero(plain, cl + 1); free(plain); }
    if (!ok) out = NULL;
    return out;
}
