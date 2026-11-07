// arc-vault crypto: AES-256-XTS (CNG), SHA-256 (CNG), CRC32, HWID, license
#pragma once
#include <windows.h>
#include <stdint.h>
#include <stddef.h>

#define ACV_OK              0
#define ACV_ERR_GEN        -1
#define ACV_ERR_ARG        -2
#define ACV_ERR_IO         -3
#define ACV_ERR_FORMAT     -4
#define ACV_ERR_LICENSE    -5
#define ACV_ERR_NOMEM      -6

#define ACV_SECTOR_SIZE     65536       // data unit for XTS
#define ACV_KEY_SIZE        32          // 256-bit content key (XTS-AES-256 uses two of these)

// ---- SHA-256 (CNG) ----
bool acv_sha256(const void *data, size_t len, uint8_t out[32]);
bool acv_sha256_stream(HANDLE hFile, uint64_t offset, uint64_t size, uint8_t out[32]);

// ---- CRC32 ----
uint32_t acv_crc32(uint32_t crc, const void *data, size_t len);

// ---- AES-256-XTS ----
// key = 64 bytes (k_data[32] || k_tweak[32]); unitNumber = data unit index.
// data/len: len must be a multiple of 16 and <= 2^20 (single data unit).
struct AcvXtsKey {
    void *enc;   // BCRYPT_KEY_HANDLE
    void *tweak; // BCRYPT_KEY_HANDLE
};
bool acv_xts_init(AcvXtsKey *k, const uint8_t key[64]);
void acv_xts_free(AcvXtsKey *k);
bool acv_xts_encrypt(const AcvXtsKey *k, uint64_t unitNumber, void *buf, size_t len);
bool acv_xts_decrypt(const AcvXtsKey *k, uint64_t unitNumber, void *buf, size_t len);

// ---- HWID ----
// MachineGuid + system volume serial -> sha256 -> hex (64 chars + NUL)
bool acv_hwid(char out[65]);

// ---- key wrapping ----
// contentKey/wrapKey are 64-byte XTS keys; wrapped = contentKey XOR SHA256-stream(wrapKey)
bool acv_wrap_key(const uint8_t contentKey[64], const uint8_t wrapKey[64], uint8_t wrapped[64]);
bool acv_unwrap_key(const uint8_t wrapped[64], const uint8_t wrapKey[64], uint8_t contentKey[64]);
bool acv_gen_random(uint8_t *buf, size_t len);

// ---- License ----
// Format: ARC-XXXX-XXXX-XXXX-XXXX (last group = CRC16/modbus of the rest, mod 0xFFFE + 1)
bool acv_license_valid(const char *lic);
// key file: base64(xor(license, pad)); returns ACV_OK or error
int  acv_license_load(const wchar_t *path, char lic[64]);
// deobfuscated license -> 64-byte XTS wrap key
bool acv_license_wrap_key(const char *lic, const char *hwid, uint8_t out64[64]);
// obfuscate/deobfuscate license string for the key file (same op)
void acv_license_xor(const char *lic, uint8_t *out);

// ---- base64 ----
bool acv_b64_encode(const uint8_t *data, size_t len, char *out, size_t outCap);
bool acv_b64_decode(const char *in, uint8_t *out, size_t outCap, size_t *outLen);

// misc
bool acv_read_file(const wchar_t *path, uint8_t **data, size_t *len);
bool acv_write_file(const wchar_t *path, const void *data, size_t len);
