// arcvault-encrypt: pack a file into an encrypted ArcVault container
//
// commands:
//   pack <input> <vault.bin> [license.key]
//   verify <vault.bin> [license.key]          (decrypt-all + hash check)
//   info <vault.bin>
//   genkey [out.license.key]
//   selftest-xts                              (known-answer cross-check helper)

#include "crypto.h"
#include "vault.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifndef NT_SUCCESS
#define NT_SUCCESS(s) (((NTSTATUS)(s)) >= 0)
#endif

static void hex_print(const uint8_t *p, size_t n)
{
    for (size_t i = 0; i < n; i++) printf("%02x", p[i]);
    printf("\n");
}

static int cmd_genkey(const wchar_t *outPath)
{
    char lic[64];
    unsigned g[3];
    if (!acv_gen_random((uint8_t *)g, sizeof g)) { printf("ERR: rng\n"); return 1; }
    snprintf(lic, sizeof lic, "ARC-%04X-%04X-%04X-0000", g[0] & 0xFFFF, g[1] & 0xFFFF, g[2] & 0xFFFF);
    // compute checksum group
    uint16_t crc = 0xFFFF;
    for (const char *p = lic; *p && p - lic < 14; p++) {
        crc ^= (uint8_t)*p;
        for (int k = 0; k < 8; k++) crc = (crc & 1) ? (uint16_t)((crc >> 1) ^ 0xA001) : (uint16_t)(crc >> 1);
    }
    // recompute using acv_license_valid semantics: crc over "ARC-XXXX-XXXX-XXXX"
    {
        char stem[32]; snprintf(stem, sizeof stem, "ARC-%04X-%04X-%04X", g[0] & 0xFFFF, g[1] & 0xFFFF, g[2] & 0xFFFF);
        uint16_t c = 0xFFFF;
        for (const char *p = stem; *p; p++) {
            c ^= (uint8_t)*p;
            for (int k = 0; k < 8; k++) c = (c & 1) ? (uint16_t)((c >> 1) ^ 0xA001) : (uint16_t)(c >> 1);
        }
        uint16_t last = (uint16_t)((c % 0xFFFEu) + 1);
        snprintf(lic, sizeof lic, "ARC-%04X-%04X-%04X-%04X", g[0] & 0xFFFF, g[1] & 0xFFFF, g[2] & 0xFFFF, last);
    }
    (void)crc;
    if (!acv_license_valid(lic)) { printf("ERR: generated key failed validation\n"); return 1; }

    uint8_t x[64]; char b64[128];
    acv_license_xor(lic, x);
    if (!acv_b64_encode(x, strlen(lic), b64, sizeof b64)) { printf("ERR: b64\n"); return 1; }

    wchar_t def[] = L"license.key";
    if (!outPath) outPath = def;
    if (!acv_write_file(outPath, b64, strlen(b64))) { printf("ERR: write file\n"); return 1; }
    printf("OK: %ls\nlicense = %s\n", outPath, lic);
    return 0;
}

static int cmd_pack(const wchar_t *inPath, const wchar_t *outPath, const wchar_t *licPath)
{
    if (!licPath) licPath = L"license.key";
    char lic[64];
    int rc = acv_license_load(licPath, lic);
    if (rc != ACV_OK) {
        printf("ERR: cannot load license (rc=%d) — run: arcvault-encrypt genkey\n", rc);
        return 1;
    }

    uint8_t *plain = 0; size_t plainLen = 0;
    if (!acv_read_file(inPath, &plain, &plainLen)) { printf("ERR: cannot read input\n"); return 1; }

    AcvHeader H; memset(&H, 0, sizeof H);
    memcpy(H.magic, "ACVF", 4);
    H.version = ACVF_VERSION;
    H.headerSize = ACVF_HEADER_SIZE;
    H.sectorSize = ACV_SECTOR_SIZE;
    H.flags = ACVF_FLAG_HWID;
    H.originalSize = plainLen;
    H.sectorCount = (plainLen + ACV_SECTOR_SIZE - 1) / ACV_SECTOR_SIZE;
    H.dataOffset = (uint32_t)(ACVF_HEADER_SIZE + H.sectorCount * 4);

    char hwid[65];
    if (!acv_hwid(hwid)) { printf("ERR: hwid\n"); free(plain); return 1; }
    if (!acv_sha256(plain, plainLen, H.shaPlain)) { printf("ERR: sha\n"); free(plain); return 1; }

    uint8_t wrapKey[64], contentKey[64];
    if (!acv_license_wrap_key(lic, hwid, wrapKey)) { printf("ERR: wrapkey\n"); free(plain); return 1; }
    if (!acv_gen_random(contentKey, sizeof contentKey)) { printf("ERR: rng\n"); free(plain); return 1; }
    if (!acv_wrap_key(contentKey, wrapKey, H.wrappedKey)) { printf("ERR: wrap\n"); free(plain); return 1; }

    // encrypt sectors
    AcvXtsKey xk;
    if (!acv_xts_init(&xk, contentKey)) { printf("ERR: xts init\n"); free(plain); return 1; }

    uint64_t nsec = H.sectorCount;
    uint8_t *cipher = (uint8_t *)malloc((size_t)(nsec * ACV_SECTOR_SIZE));
    if (!cipher) { printf("ERR: nomem\n"); free(plain); return 1; }
    memset(cipher, 0, (size_t)(nsec * ACV_SECTOR_SIZE));
    memcpy(cipher, plain, plainLen);
    free(plain);

    for (uint64_t i = 0; i < nsec; i++) {
        if (!acv_xts_encrypt(&xk, i, cipher + i * ACV_SECTOR_SIZE, ACV_SECTOR_SIZE)) {
            printf("ERR: xts encrypt sector %llu\n", (unsigned long long)i);
            free(cipher);
            return 1;
        }
    }
    acv_xts_free(&xk);

    uint32_t *crcs = (uint32_t *)malloc((size_t)(nsec * 4));
    if (!crcs) { printf("ERR: nomem\n"); free(cipher); return 1; }
    for (uint64_t i = 0; i < nsec; i++)
        crcs[i] = acv_crc32(0, cipher + i * ACV_SECTOR_SIZE, ACV_SECTOR_SIZE);

    // ciphertext sha over the whole sector region
    {
        BCRYPT_ALG_HANDLE alg = 0; BCRYPT_HASH_HANDLE hh = 0;
        bool ok = false;
        NTSTATUS st1 = BCryptOpenAlgorithmProvider(&alg, L"SHA256", 0, 0);
        NTSTATUS st2 = st1, st3 = st1, st4 = st1;
        if (NT_SUCCESS(st1)) {
            st2 = BCryptCreateHash(alg, &hh, 0, 0, 0, 0, 0);
            if (NT_SUCCESS(st2)) {
                ok = true;
                for (uint64_t i = 0; i < nsec && ok; i++) {
                    st3 = BCryptHashData(hh, cipher + i * ACV_SECTOR_SIZE, ACV_SECTOR_SIZE, 0);
                    ok = NT_SUCCESS(st3);
                }
                st4 = BCryptFinishHash(hh, H.shaCipher, 32, 0);
                ok = ok && NT_SUCCESS(st4);
                BCryptDestroyHash(hh);
            }
            BCryptCloseAlgorithmProvider(alg, 0);
        }
        if (!ok) { printf("ERR: sha stream (open=0x%08lX create=0x%08lX hash=0x%08lX finish=0x%08lX)\n",
            (unsigned long)st1, (unsigned long)st2, (unsigned long)st3, (unsigned long)st4);
            free(crcs); free(cipher); return 1; }
    }

    H.headerCrc = acv_crc32(0, &H, 168);

    FILE *f = _wfopen(outPath, L"wb");
    if (!f) { printf("ERR: cannot create output\n"); free(crcs); free(cipher); return 1; }
    bool ok = fwrite(&H, 1, sizeof H, f) == sizeof H
        && fwrite(crcs, 1, (size_t)(nsec * 4), f) == (size_t)(nsec * 4)
        && fwrite(cipher, 1, (size_t)(nsec * ACV_SECTOR_SIZE), f) == (size_t)(nsec * ACV_SECTOR_SIZE);
    fclose(f);
    free(crcs); free(cipher);
    if (!ok) { printf("ERR: write output\n"); return 1; }

    wprintf(L"OK: %s  (%.2f MB -> %.2f MB, %llu sectors)\n", outPath,
        plainLen / 1048576.0, (nsec * ACV_SECTOR_SIZE + H.dataOffset) / 1048576.0,
        (unsigned long long)nsec);
    printf("machine HWID: %s\n", hwid);
    return 0;
}

static int cmd_info(const wchar_t *path)
{
    AcvHeader H;
    FILE *f = _wfopen(path, L"rb");
    if (!f) { printf("ERR: cannot open\n"); return 1; }
    if (fread(&H, 1, sizeof H, f) != sizeof H) { fclose(f); printf("ERR: header\n"); return 1; }
    fclose(f);
    if (memcmp(H.magic, "ACVF", 4) != 0) { printf("ERR: bad magic\n"); return 1; }
    uint32_t crc = acv_crc32(0, &H, 168);
    printf("version      : %u\n", H.version);
    printf("sector size  : %u\n", H.sectorSize);
    printf("originalSize : %llu\n", (unsigned long long)H.originalSize);
    printf("sectorCount  : %llu\n", (unsigned long long)H.sectorCount);
    printf("headerCrc    : %s\n", crc == H.headerCrc ? "OK" : "FAIL");
    printf("hwid-bound   : %s\n", (H.flags & ACVF_FLAG_HWID) ? "yes" : "no");
    printf("shaPlain     : "); hex_print(H.shaPlain, 8); printf("  (first 8 bytes)\n");
    return 0;
}

static int cmd_verify(const wchar_t *path, const wchar_t *licPath)
{
    if (!licPath) licPath = L"license.key";
    AcvHeader H;
    {
        FILE *f = _wfopen(path, L"rb");
        if (!f) { printf("ERR: cannot open\n"); return 1; }
        bool ok = fread(&H, 1, sizeof H, f) == sizeof H;
        fclose(f);
        if (!ok) { printf("ERR: header\n"); return 1; }
    }
    if (memcmp(H.magic, "ACVF", 4) != 0 || H.version != ACVF_VERSION) { printf("ERR: format\n"); return 1; }
    if (acv_crc32(0, &H, 168) != H.headerCrc) { printf("ERR: header crc\n"); return 1; }

    char lic[64];
    int rc = acv_license_load(licPath, lic);
    if (rc != ACV_OK) { printf("ERR: license (rc=%d)\n", rc); return 1; }
    char hwid[65];
    if (!acv_hwid(hwid)) { printf("ERR: hwid\n"); return 1; }
    uint8_t wrapKey[64], contentKey[64];
    acv_license_wrap_key(lic, hwid, wrapKey);
    if (!acv_unwrap_key(H.wrappedKey, wrapKey, contentKey)) { printf("ERR: unwrap — wrong license or machine\n"); return 1; }
    AcvXtsKey xk;
    if (!acv_xts_init(&xk, contentKey)) { printf("ERR: xts init\n"); return 1; }

    // read ciphertext region once: hash it, decrypt in place, hash plaintext
    uint64_t cipherLen = H.sectorCount * ACV_SECTOR_SIZE;
    uint8_t *buf = (uint8_t *)malloc((size_t)cipherLen);
    if (!buf) { printf("ERR: nomem\n"); return 1; }
    {
        uint8_t *whole = 0; size_t wholeLen = 0;
        if (!acv_read_file(path, &whole, &wholeLen)) { printf("ERR: read\n"); return 1; }
        if (wholeLen < acv_data_offset(&H) + cipherLen) { free(whole); printf("ERR: truncated store\n"); return 1; }
        memcpy(buf, whole + acv_data_offset(&H), (size_t)cipherLen);
        free(whole);
    }

    uint8_t shaC[32];
    if (!acv_sha256(buf, (size_t)cipherLen, shaC)) { printf("ERR: sha\n"); return 1; }
    if (memcmp(shaC, H.shaCipher, 32) != 0) { printf("ERR: ciphertext hash mismatch (corrupted store)\n"); return 1; }

    for (uint64_t i = 0; i < H.sectorCount; i++)
        if (!acv_xts_decrypt(&xk, i, buf + i * ACV_SECTOR_SIZE, ACV_SECTOR_SIZE)) { printf("ERR: decrypt %llu\n", (unsigned long long)i); return 1; }
    acv_xts_free(&xk);

    uint8_t shaP[32];
    if (!acv_sha256(buf, (size_t)H.originalSize, shaP)) { printf("ERR: sha\n"); return 1; }
    if (memcmp(shaP, H.shaPlain, 32) != 0) { printf("FAIL: plaintext hash mismatch\n"); return 1; }
    printf("OK: decrypt-all verified (%llu bytes)\n", (unsigned long long)H.originalSize);
    return 0;
}

static int cmd_selftest_xts()
{
    // deterministic vectors for cross-check against OpenSSL (node crypto)
    uint8_t key[64], buf[64];
    for (int i = 0; i < 64; i++) key[i] = (uint8_t)i;
    for (int i = 0; i < 64; i++) buf[i] = (uint8_t)(0xF0 ^ i);
    AcvXtsKey k;
    if (!acv_xts_init(&k, key)) { printf("ERR: init\n"); return 1; }
    acv_xts_encrypt(&k, 0, buf, 64);
    printf("XTS unit=0 enc[0..31]: "); hex_print(buf, 32);
    acv_xts_decrypt(&k, 0, buf, 64);
    printf("dec roundtrip: %s\n", memcmp(buf, "\xF0\xF1\xF2\xF3\xF4\xF5\xF6\xF7\xF8\xF9\xFA\xFB\xFC\xFD\xFE\xFF\xE0\xE1\xE2\xE3\xE4\xE5\xE6\xE7\xE8\xE9\xEA\xEB\xEC\xED\xEE\xEF", 32) == 0 ? "OK" : "FAIL");
    acv_xts_encrypt(&k, 0x123456789ABCDEF0ull, buf, 64);
    printf("XTS unit=123456789ABCDEF0 enc[0..31]: "); hex_print(buf, 32);
    acv_xts_free(&k);
    return 0;
}

int wmain(int argc, wchar_t **argv)
{
    if (argc < 2) {
        printf("usage:\n"
               "  arcvault-encrypt pack <input> <vault.bin> [license.key]\n"
               "  arcvault-encrypt verify <vault.bin> [license.key]\n"
               "  arcvault-encrypt info <vault.bin>\n"
               "  arcvault-encrypt genkey [out.license.key]\n"
               "  arcvault-encrypt selftest-xts\n");
        return 2;
    }
    if (!wcscmp(argv[1], L"pack") && argc >= 4) return cmd_pack(argv[2], argv[3], argc >= 5 ? argv[4] : 0);
    if (!wcscmp(argv[1], L"verify") && argc >= 3) return cmd_verify(argv[2], argc >= 4 ? argv[3] : 0);
    if (!wcscmp(argv[1], L"info") && argc >= 3) return cmd_info(argv[2]);
    if (!wcscmp(argv[1], L"genkey")) return cmd_genkey(argc >= 3 ? argv[2] : 0);
    if (!wcscmp(argv[1], L"selftest-xts")) return cmd_selftest_xts();
    printf("ERR: unknown args\n");
    return 2;
}
