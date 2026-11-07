// ArcVault container format (vault.bin)
#pragma once
#include <stdint.h>

#define ACVF_MAGIC_0        'A'
#define ACVF_VERSION        1
#define ACVF_HEADER_SIZE    176
#define ACVF_FLAG_HWID      1u  // wrappedKey is bound to license + HWID

#pragma pack(push, 1)
struct AcvHeader {
    char     magic[4];        // "ACVF"
    uint16_t version;         // 1
    uint16_t headerSize;      // 176
    uint32_t sectorSize;      // data unit size (65536)
    uint32_t flags;           // ACVF_FLAG_*
    uint64_t originalSize;    // plaintext size
    uint64_t sectorCount;     // number of 64KB ciphertext sectors
    uint32_t dataOffset;      // offset where CRC table starts (ciphertext follows it)
    uint32_t reserved0;
    uint8_t  shaPlain[32];    // sha256 of plaintext (audit / verify tool)
    uint8_t  shaCipher[32];   // sha256 of ciphertext region (fast mount-time check)
    uint8_t  wrappedKey[64];  // content XTS key XOR SHA256-stream(license+hwid key)
    uint32_t headerCrc;       // crc32 of header bytes [0, 168)
    uint32_t reserved1;
};
#pragma pack(pop)

static_assert(sizeof(AcvHeader) == ACVF_HEADER_SIZE, "AcvHeader must be 176 bytes");

// CRC table sits right after the header; dataOffset field already points at ciphertext
inline uint64_t acv_crc_table_offset(const AcvHeader *) { return ACVF_HEADER_SIZE; }
inline uint64_t acv_data_offset(const AcvHeader *h) { return h->dataOffset; }
