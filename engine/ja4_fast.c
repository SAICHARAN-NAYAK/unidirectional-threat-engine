#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <openssl/sha.h>

#define MAX_ITEMS 128

static inline int is_grease(uint16_t x) {
    return ((x & 0x0F0F) == 0x0A0A) && (((x >> 8) & 0xF0) == (x & 0xF0));
}

static inline uint16_t rd16(const uint8_t *p) {
    return ((uint16_t)p[0] << 8) | (uint16_t)p[1];
}

static int cmp_u16(const void *a, const void *b) {
    return (*(const uint16_t *)a - *(const uint16_t *)b);
}

static void sha256_trunc12(const char *input, size_t len, char out[13]) {
    if (len == 0) {
        memcpy(out, "000000000000", 12);
        out[12] = '\0';
        return;
    }
    uint8_t hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char *)input, len, hash);
    for (int i = 0; i < 6; i++) {
        sprintf(&out[i * 2], "%02x", hash[i]);
    }
    out[12] = '\0';
}

int extract_ja4(const uint8_t *pkt, size_t len, char transport, char out_ja4[37]) {
    // Basic bounds check for TLS Handshake Record
    if (len < 5 || pkt[0] != 0x16) return -1;
    if (len < 9 || pkt[5] != 0x01) return -1; // 0x01 = ClientHello

    const uint8_t *ptr = pkt + 9;
    const uint8_t *end = pkt + len;

    if (ptr + 34 > end) return -1;
    uint16_t client_version = rd16(ptr);
    ptr += 2 + 32; // Skip version and random

    // Session ID
    uint8_t sess_len = *ptr++;
    if (ptr + sess_len > end) return -1;
    ptr += sess_len;

    // Cipher Suites
    if (ptr + 2 > end) return -1;
    uint16_t cipher_len = rd16(ptr);
    ptr += 2;
    if (ptr + cipher_len > end) return -1;

    uint16_t ciphers[MAX_ITEMS];
    int cipher_count = 0;
    for (size_t i = 0; i < cipher_len; i += 2) {
        uint16_t c = rd16(ptr + i);
        if (!is_grease(c) && cipher_count < MAX_ITEMS) {
            ciphers[cipher_count++] = c;
        }
    }
    ptr += cipher_len;

    // Compression Methods
    if (ptr + 1 > end) return -1;
    uint8_t comp_len = *ptr++;
    if (ptr + comp_len > end) return -1;
    ptr += comp_len;

    // Extensions Parsing
    int has_sni = 0;
    char alpn[3] = "00";
    uint16_t max_supported_version = 0;
    uint16_t extensions[MAX_ITEMS];
    int ext_count = 0;
    int ext_hash_count = 0;
    uint16_t ext_for_hash[MAX_ITEMS];
    uint16_t sig_algs[MAX_ITEMS];
    int sig_alg_count = 0;

    if (ptr + 2 <= end) {
        uint16_t ext_total_len = rd16(ptr);
        ptr += 2;
        const uint8_t *ext_end = ptr + ext_total_len;
        if (ext_end > end) ext_end = end;

        while (ptr + 4 <= ext_end) {
            uint16_t etype = rd16(ptr);
            uint16_t elen = rd16(ptr + 2);
            ptr += 4;
            if (ptr + elen > ext_end) break;

            if (!is_grease(etype)) {
                if (ext_count < MAX_ITEMS) extensions[ext_count++] = etype;
                if (etype != 0x0000 && etype != 0x0010 && ext_hash_count < MAX_ITEMS) {
                    ext_for_hash[ext_hash_count++] = etype;
                }

                if (etype == 0x0000) {
                    has_sni = 1;
                } else if (etype == 0x0010 && elen >= 3) {
                    // ALPN: read first entry
                    uint8_t first_len = ptr[2];
                    if (elen >= 3 + first_len && first_len > 0) {
                        char first = 0, last = 0;
                        for (int k = 0; k < first_len; k++) {
                            if (isalnum(ptr[3 + k])) {
                                if (!first) first = ptr[3 + k];
                                last = ptr[3 + k];
                            }
                        }
                        if (first && last) {
                            alpn[0] = first;
                            alpn[1] = last;
                            alpn[2] = '\0';
                        }
                    }
                } else if (etype == 0x002B && elen > 1) { // supported_versions
                    uint8_t vlen = ptr[0];
                    for (int k = 1; k + 1 < elen && k <= vlen; k += 2) {
                        uint16_t sv = rd16(ptr + k);
                        if (!is_grease(sv) && sv > max_supported_version) {
                            max_supported_version = sv;
                        }
                    }
                } else if (etype == 0x000D && elen >= 2) { // signature_algorithms
                    uint16_t sal_len = rd16(ptr);
                    for (int k = 2; k + 1 < elen && (k - 2) < sal_len; k += 2) {
                        if (sig_alg_count < MAX_ITEMS) {
                            sig_algs[sig_alg_count++] = rd16(ptr + k);
                        }
                    }
                }
            }
            ptr += elen;
        }
    }

    // Resolve TLS version token
    uint16_t final_ver = (max_supported_version != 0) ? max_supported_version : client_version;
    const char *ver_str = "00";
    switch (final_ver) {
        case 0x0304: ver_str = "13"; break;
        case 0x0303: ver_str = "12"; break;
        case 0x0302: ver_str = "11"; break;
        case 0x0301: ver_str = "10"; break;
        case 0x0300: ver_str = "s3"; break;
    }

    // Section A
    char ja4_a[11];
    int c_count_disp = (cipher_count > 99) ? 99 : cipher_count;
    int e_count_disp = (ext_count > 99) ? 99 : ext_count;
    snprintf(ja4_a, sizeof(ja4_a), "%c%s%c%02d%02d%s", 
             transport, ver_str, has_sni ? 'd' : 'i', c_count_disp, e_count_disp, alpn);

    // Section B: Cipher Hash
    char ja4_b[13];
    if (cipher_count > 0) {
        qsort(ciphers, cipher_count, sizeof(uint16_t), cmp_u16);
        char c_buf[MAX_ITEMS * 5];
        int pos = 0;
        for (int i = 0; i < cipher_count; i++) {
            pos += snprintf(c_buf + pos, sizeof(c_buf) - pos, "%s%04x", (i == 0 ? "" : ","), ciphers[i]);
        }
        sha256_trunc12(c_buf, pos, ja4_b);
    } else {
        memcpy(ja4_b, "000000000000", 13);
    }

    // Section C: Extension + Signature Algorithm Hash
    char ja4_c[13];
    if (ext_hash_count > 0 || sig_alg_count > 0) {
        qsort(ext_for_hash, ext_hash_count, sizeof(uint16_t), cmp_u16);
        char e_buf[MAX_ITEMS * 10];
        int pos = 0;
        for (int i = 0; i < ext_hash_count; i++) {
            pos += snprintf(e_buf + pos, sizeof(e_buf) - pos, "%s%04x", (i == 0 ? "" : ","), ext_for_hash[i]);
        }
        if (sig_alg_count > 0) {
            pos += snprintf(e_buf + pos, sizeof(e_buf) - pos, "_");
            for (int i = 0; i < sig_alg_count; i++) {
                pos += snprintf(e_buf + pos, sizeof(e_buf) - pos, "%s%04x", (i == 0 ? "" : ","), sig_algs[i]);
            }
        }
        sha256_trunc12(e_buf, pos, ja4_c);
    } else {
        memcpy(ja4_c, "000000000000", 13);
    }

    snprintf(out_ja4, 37, "%s_%s_%s", ja4_a, ja4_b, ja4_c);
    return 0;
}
