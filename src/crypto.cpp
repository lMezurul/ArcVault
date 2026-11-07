#include "crypto.h"
#include <bcrypt.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#pragma comment(lib, "bcrypt.lib") // ignored by mingw; we link -lbcrypt

#ifndef NT_SUCCESS
#define NT_SUCCESS(s) (((NTSTATUS)(s)) >= 0)
#endif

#define BCRYPT_SHA256_ALG_A    L"SHA256"
#define BCRYPT_AES_ALG_A       L"AES"

static void hex_str(const uint8_t *in, size_t n, char *out)
{
    static const char d[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[i * 2 + 0] = d[in[i] >> 4];
        out[i * 2 + 1] = d[in[i] & 15];
    }
    out[n * 2] = 0;
}

// ---------------- SHA-256 ----------------
bool acv_sha256(const void *data, size_t len, uint8_t out[32])
{
    BCRYPT_ALG_HANDLE alg = 0;
    BCRYPT_HASH_HANDLE hh = 0;
    bool ok = false;
    if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALG_A, 0, 0)))
        return false;
    if (NT_SUCCESS(BCryptCreateHash(alg, &hh, 0, 0, 0, 0, 0))) {
        // hash in chunks to keep lengths inside ULONG
        const uint8_t *p = (const uint8_t *)data;
        ok = true;
        while (len && ok) {
            ULONG chunk = len > (1u << 30) ? (1u << 30) : (ULONG)len;
            ok = NT_SUCCESS(BCryptHashData(hh, (PUCHAR)p, chunk, 0));
            p += chunk;
            len -= chunk;
        }
        ok = ok && NT_SUCCESS(BCryptFinishHash(hh, out, 32, 0));
        BCryptDestroyHash(hh);
    }
    BCryptCloseAlgorithmProvider(alg, 0);
    return ok;
}

bool acv_sha256_stream(HANDLE hFile, uint64_t offset, uint64_t size, uint8_t out[32])
{
    BCRYPT_ALG_HANDLE alg = 0;
    BCRYPT_HASH_HANDLE hh = 0;
    bool ok = false;
    uint8_t buf[256 * 1024];
    if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALG_A, 0, 0)))
        return false;
    if (!NT_SUCCESS(BCryptCreateHash(alg, &hh, 0, 0, 0, 0, 0)))
        goto exit;

    LARGE_INTEGER li; li.QuadPart = (LONGLONG)offset;
    if (offset) {
        if (!SetFilePointerEx(hFile, li, 0, FILE_BEGIN)) goto exit;
    }
    while (size) {
        DWORD chunk = (DWORD)((size < sizeof buf) ? size : sizeof buf);
        DWORD got = 0;
        OVERLAPPED ov; memset(&ov, 0, sizeof ov); // handle may be FILE_FLAG_OVERLAPPED
        ov.Offset = (DWORD)offset; ov.OffsetHigh = (DWORD)(offset >> 32);
        if (!ReadFile(hFile, buf, chunk, &got, &ov)) {
            if (GetLastError() != ERROR_IO_PENDING || !GetOverlappedResult(hFile, &ov, &got, TRUE))
                goto exit;
        }
        if (got != chunk) goto exit;
        if (!NT_SUCCESS(BCryptHashData(hh, buf, got, 0))) goto exit;
        offset += got;
        size -= got;
    }
    ok = NT_SUCCESS(BCryptFinishHash(hh, out, 32, 0));
exit:
    if (hh) BCryptDestroyHash(hh);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    return ok;
}

// ---------------- CRC32 (IEEE) ----------------
uint32_t acv_crc32(uint32_t crc, const void *data, size_t len)
{
    static uint32_t table[256]; static bool init = false;
    if (!init) {
        for (uint32_t i = 0; i < 256; i++) {
            uint32_t c = i;
            for (int k = 0; k < 8; k++) c = (c & 1) ? 0xEDB88320u ^ (c >> 1) : c >> 1;
            table[i] = c;
        }
        init = true;
    }
    const uint8_t *p = (const uint8_t *)data;
    crc ^= 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++)
        crc = table[(crc ^ p[i]) & 0xFF] ^ (crc >> 8);
    return crc ^ 0xFFFFFFFFu;
}

// ---------------- AES-256-XTS ----------------
// XTS per IEEE 1619: C_i = E(P_i ^ T_i) ^ T_i, T_i = T0 * a^i in GF(2^128),
// T0 = data unit number as 128-bit little-endian.
// Implemented over CNG AES-ECB: one ECB call per whole buffer (blocks are independent).

static void xts_mul2(uint8_t T[16])
{
    uint8_t carry = 0;
    for (int j = 0; j < 16; j++) {
        uint8_t c = (uint8_t)(T[j] >> 7);
        T[j] = (uint8_t)((T[j] << 1) | carry);
        carry = c;
    }
    if (carry) T[0] ^= 0x87;
}

static BCRYPT_ALG_HANDLE g_aesAlg() {
    static BCRYPT_ALG_HANDLE g_alg = 0;
    if (!g_alg) {
        BCRYPT_ALG_HANDLE alg = 0;
        if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALG_A, 0, 0)))
            return 0;
        if (!NT_SUCCESS(BCryptSetProperty(alg, (LPCWSTR)BCRYPT_CHAINING_MODE,
            (PUCHAR)BCRYPT_CHAIN_MODE_ECB, sizeof BCRYPT_CHAIN_MODE_ECB, 0))) {
            BCryptCloseAlgorithmProvider(alg, 0);
            return 0;
        }
        g_alg = alg; // held for process lifetime
    }
    return g_alg;
}

bool acv_xts_init(AcvXtsKey *k, const uint8_t key[64])
{
    memset(k, 0, sizeof *k);
    BCRYPT_ALG_HANDLE g_alg = g_aesAlg();
    if (!g_alg)
        return false;

    if (!NT_SUCCESS(BCryptGenerateSymmetricKey(g_alg, (BCRYPT_KEY_HANDLE *)&k->enc, 0, 0,
        (PUCHAR)key, 32, 0)))
        return false;
    if (!NT_SUCCESS(BCryptGenerateSymmetricKey(g_alg, (BCRYPT_KEY_HANDLE *)&k->tweak, 0, 0,
        (PUCHAR)key + 32, 32, 0))) {
        BCryptDestroyKey((BCRYPT_KEY_HANDLE)k->enc);
        k->enc = 0;
        return false;
    }
    return true;
}

void acv_xts_free(AcvXtsKey *k)
{
    if (k->enc) BCryptDestroyKey((BCRYPT_KEY_HANDLE)k->enc);
    if (k->tweak) BCryptDestroyKey((BCRYPT_KEY_HANDLE)k->tweak);
    memset(k, 0, sizeof *k);
}

static bool xts_apply(const AcvXtsKey *k, uint64_t unitNumber, void *buf, size_t len, bool encrypt)
{
    if (len < 16 || (len & 15) || len > (1u << 20)) return false;

    uint8_t *T = (uint8_t *)_aligned_malloc(len < 4096 ? 4096 : len, 16);
    uint8_t *Tb = (uint8_t *)_aligned_malloc(len < 4096 ? 4096 : len, 16);
    if (!T || !Tb) { _aligned_free(T); _aligned_free(Tb); return false; }

    // T stream per IEEE 1619: T0 = E_K2(dataUnitNumber LE128), T_i = T0 * alpha^i
    memset(T, 0, len);
    size_t nblocks = len / 16;
    {
        uint8_t tw[16];
        memset(tw, 0, 16);
        for (int i = 0; i < 8; i++) tw[i] = (uint8_t)(unitNumber >> (8 * i));
        ULONG d = 0;
        if (!NT_SUCCESS(BCryptEncrypt((BCRYPT_KEY_HANDLE)k->tweak, tw, 16, 0, 0, 0, tw, 16, &d, 0))) {
            _aligned_free(T);
            _aligned_free(Tb);
            return false;
        }
        for (size_t b = 0; b < nblocks; b++) {
            if (b) xts_mul2(tw);
            memcpy(T + b * 16, tw, 16);
        }
    }

    // tmp = P ^ T  (or C ^ T)
    uint8_t *d = (uint8_t *)buf;
    for (size_t i = 0; i < len; i++)
        Tb[i] = d[i] ^ T[i];

    // single ECB pass over all blocks
    ULONG done = 0;
    NTSTATUS st = encrypt
        ? BCryptEncrypt((BCRYPT_KEY_HANDLE)k->enc, (PUCHAR)Tb, (ULONG)len, 0, 0, 0, (PUCHAR)Tb, (ULONG)len, &done, 0)
        : BCryptDecrypt((BCRYPT_KEY_HANDLE)k->enc, (PUCHAR)Tb, (ULONG)len, 0, 0, 0, (PUCHAR)Tb, (ULONG)len, &done, 0);
    bool ok = NT_SUCCESS(st) && done == len;
    if (ok) {
        // out = tmp ^ T
        for (size_t i = 0; i < len; i++)
            d[i] = Tb[i] ^ T[i];
    }
    _aligned_free(T);
    _aligned_free(Tb);
    return ok;
}

bool acv_xts_encrypt(const AcvXtsKey *k, uint64_t unitNumber, void *buf, size_t len)
{ return xts_apply(k, unitNumber, buf, len, true); }

bool acv_xts_decrypt(const AcvXtsKey *k, uint64_t unitNumber, void *buf, size_t len)
{ return xts_apply(k, unitNumber, buf, len, false); }

// ---------------- HWID ----------------
bool acv_hwid(char out[65])
{
    char guid[128] = {0};
    DWORD sz = sizeof guid;
    LONG r = RegGetValueA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Cryptography",
        "MachineGuid", RRF_RT_REG_SZ, 0, guid, &sz);
    if (r != ERROR_SUCCESS) return false;

    wchar_t root[4] = L"C:\\";
    wchar_t sys[MAX_PATH]; UINT n = GetSystemDirectoryW(sys, MAX_PATH);
    if (n >= 1) root[0] = sys[0];
    DWORD volSer = 0;
    if (!GetVolumeInformationW(root, 0, 0, &volSer, 0, 0, 0, 0)) volSer = 0;

    char buf[256];
    int bl = snprintf(buf, sizeof buf, "%s|%08lX", guid, (unsigned long)volSer);
    if (bl <= 0) return false;
    uint8_t h[32];
    if (!acv_sha256(buf, (size_t)bl, h)) return false;
    hex_str(h, 32, out);
    return true;
}

// ---------------- License ----------------
static int b16(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return 10 + c - 'A';
    if (c >= 'a' && c <= 'f') return 10 + c - 'a';
    return -1;
}

static uint16_t lic_crc16(const char *s)
{
    uint16_t crc = 0xFFFF;
    for (; *s; s++) {
        crc ^= (uint8_t)*s;
        for (int k = 0; k < 8; k++)
            crc = (crc & 1) ? (uint16_t)((crc >> 1) ^ 0xA001) : (uint16_t)(crc >> 1);
    }
    return crc;
}

bool acv_license_valid(const char *lic)
{
    // ARC-XXXX-XXXX-XXXX-XXXX ; groups 1..3 base16, group 4 = (crc16 % 0xFFFE) + 1
    if (strncmp(lic, "ARC-", 4) != 0) return false;
    int v[4] = {0};
    const char *p = lic + 4;
    for (int g = 0; g < 4; g++) {
        for (int i = 0; i < 4; i++) {
            int d = b16(p[i]);
            if (d < 0) return false;
            v[g] = v[g] * 16 + d;
        }
        p += 4;
        if (g < 3) { if (*p != '-') return false; p++; }
    }
    if (*p) return false;
    char stem[32];
    snprintf(stem, sizeof stem, "ARC-%04X-%04X-%04X", v[0], v[1], v[2]);
    uint16_t want = (uint16_t)((lic_crc16(stem) % 0xFFFEu) + 1);
    return want == (uint16_t)v[3];
}

static const char B64T[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

bool acv_b64_encode(const uint8_t *data, size_t len, char *out, size_t outCap)
{
    size_t need = ((len + 2) / 3) * 4 + 1;
    if (outCap < need) return false;
    size_t o = 0, i = 0;
    for (; i + 3 <= len; i += 3) {
        uint32_t v = (uint32_t)(data[i] << 16 | data[i + 1] << 8 | data[i + 2]);
        out[o++] = B64T[(v >> 18) & 63]; out[o++] = B64T[(v >> 12) & 63];
        out[o++] = B64T[(v >> 6) & 63];  out[o++] = B64T[v & 63];
    }
    if (len - i == 1) {
        uint32_t v = (uint32_t)(data[i] << 16);
        out[o++] = B64T[(v >> 18) & 63]; out[o++] = B64T[(v >> 12) & 63];
        out[o++] = '='; out[o++] = '=';
    } else if (len - i == 2) {
        uint32_t v = (uint32_t)(data[i] << 16 | data[i + 1] << 8);
        out[o++] = B64T[(v >> 18) & 63]; out[o++] = B64T[(v >> 12) & 63];
        out[o++] = B64T[(v >> 6) & 63];  out[o++] = '=';
    }
    out[o] = 0;
    return true;
}

bool acv_b64_decode(const char *in, uint8_t *out, size_t outCap, size_t *outLen)
{
    static int8_t rev[256]; static bool init = false;
    if (!init) {
        memset(rev, -1, sizeof rev);
        for (int i = 0; i < 64; i++) rev[(uint8_t)B64T[i]] = (int8_t)i;
        init = true;
    }
    size_t n = strlen(in), o = 0;
    uint32_t acc = 0; int bits = 0;
    for (size_t i = 0; i < n; i++) {
        char c = in[i];
        if (c == '=' || c == '\r' || c == '\n') continue;
        int8_t d = rev[(uint8_t)c];
        if (d < 0) return false;
        acc = (acc << 6) | (uint32_t)d;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (o >= outCap) return false;
            out[o++] = (uint8_t)(acc >> bits);
        }
    }
    *outLen = o;
    return true;
}

static const char *g_pad = "acv-license-pad-v1!"; // obfuscation only, not encryption

void acv_license_xor(const char *lic, uint8_t *out)
{
    size_t n = strlen(lic);
    for (size_t i = 0; i < n; i++)
        out[i] = (uint8_t)(lic[i] ^ g_pad[i % strlen(g_pad)]);
}

bool acv_license_wrap_key(const char *lic, const char *hwid, uint8_t out64[64])
{
    // K2 = SHA256(domain || license || hwid); expand to 64 bytes with counter
    uint8_t seed[32];
    char buf[256];
    int n = snprintf(buf, sizeof buf, "ACVFv1|%s|%s", lic, hwid);
    if (n <= 0 || !acv_sha256(buf, (size_t)n, seed)) return false;
    for (int b = 0; b < 2; b++) {
        uint8_t blk[33];
        memcpy(blk, seed, 32);
        blk[32] = (uint8_t)b;
        if (!acv_sha256(blk, 33, out64 + b * 32)) return false;
    }
    return true;
}

int acv_license_load(const wchar_t *path, char lic[64])
{
    uint8_t *data = 0; size_t len = 0;
    if (!acv_read_file(path, &data, &len)) return ACV_ERR_IO;
    if (len < 4 || len > 512) { free(data); return ACV_ERR_FORMAT; }

    uint8_t raw[512]; size_t rawLen = 0;
    char b64[768];
    memcpy(b64, data, len < sizeof b64 - 1 ? len : sizeof b64 - 1);
    b64[len < sizeof b64 - 1 ? len : sizeof b64 - 1] = 0;
    free(data);
    // trim whitespace
    for (char *p = b64; *p; p++)
        if (*p == '\r' || *p == '\n' || *p == ' ') { memmove(p, p + 1, strlen(p)); p--; }
    if (!acv_b64_decode(b64, raw, sizeof raw, &rawLen)) return ACV_ERR_FORMAT;

    uint8_t dec[256];
    if (rawLen < 19 || rawLen > sizeof dec) return ACV_ERR_FORMAT;
    for (size_t i = 0; i < rawLen; i++)
        dec[i] = raw[i] ^ (uint8_t)g_pad[i % strlen(g_pad)];
    if (dec[rawLen]) return ACV_ERR_FORMAT; // must be NUL-terminated
    if (!acv_license_valid((const char *)dec)) return ACV_ERR_LICENSE;

    strncpy(lic, (const char *)dec, 63);
    lic[63] = 0;
    return ACV_OK;
}

// ---------------- key wrapping ----------------
bool acv_wrap_key(const uint8_t contentKey[64], const uint8_t wrapKey[64], uint8_t wrapped[64])
{
    for (int b = 0; b < 2; b++) {
        uint8_t blk[65];
        memcpy(blk, wrapKey, 64);
        blk[64] = (uint8_t)b;
        uint8_t s[32];
        if (!acv_sha256(blk, 65, s)) return false;
        for (int i = 0; i < 32; i++)
            wrapped[b * 32 + i] = contentKey[b * 32 + i] ^ s[i];
    }
    return true;
}

bool acv_unwrap_key(const uint8_t wrapped[64], const uint8_t wrapKey[64], uint8_t contentKey[64])
{
    return acv_wrap_key(wrapped, wrapKey, contentKey);
}

bool acv_gen_random(uint8_t *buf, size_t len)
{
    return NT_SUCCESS(BCryptGenRandom(0, buf, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG));
}

// ---------------- file io ----------------
bool acv_read_file(const wchar_t *path, uint8_t **data, size_t *len)
{
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, 0,
        OPEN_EXISTING, 0, 0);
    if (h == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER sz;
    if (!GetFileSizeEx(h, &sz) || sz.QuadPart < 0) { CloseHandle(h); return false; }
    uint8_t *buf = (uint8_t *)malloc(sz.LowPart ? (size_t)sz.QuadPart : 1);
    if (!buf) { CloseHandle(h); return false; }
    DWORD got = 0;
    bool ok = !!ReadFile(h, buf, (DWORD)sz.QuadPart, &got, 0) && got == (DWORD)sz.QuadPart;
    CloseHandle(h);
    if (!ok) { free(buf); return false; }
    *data = buf; *len = got;
    return true;
}

bool acv_write_file(const wchar_t *path, const void *data, size_t len)
{
    HANDLE h = CreateFileW(path, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, 0, 0);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD put = 0;
    bool ok = len == 0 || (WriteFile(h, data, (DWORD)len, &put, 0) && put == (DWORD)len);
    CloseHandle(h);
    return ok;
}
