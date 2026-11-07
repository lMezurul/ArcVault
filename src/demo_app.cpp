// demo-app.exe — minimal stand-in for the trusted application.
//
// usage: demo-app <path-to-virtual-file>   -> reads the whole file, prints size + sha256
//        demo-app --denied <path>         -> expects open to FAIL (guard check), exit 0 = denied

#include "crypto.h"
#include <stdio.h>
#include <string.h>

int wmain(int argc, wchar_t **argv)
{
    bool expectDenied = false;
    const wchar_t *path = 0, *outPath = 0;
    for (int i = 1; i < argc; i++) {
        if (!wcscmp(argv[i], L"--denied")) expectDenied = true;
        else if (!wcscmp(argv[i], L"--out") && i + 1 < argc) outPath = argv[++i];
        else path = argv[i];
    }
    if (!path) {
        printf("usage: demo-app [--denied] [--out <file>] <file>\n");
        return 2;
    }

    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, 0,
        OPEN_EXISTING, 0, 0);
    if (h == INVALID_HANDLE_VALUE) {
        printf("OPEN FAILED: win32 %lu\n", GetLastError());
        if (expectDenied) { printf("EXPECTED-DENIED: OK\n"); return 0; }
        return 1;
    }
    if (expectDenied) {
        printf("ERROR: open SUCCEEDED but denial was expected\n");
        CloseHandle(h);
        return 1;
    }

    LARGE_INTEGER sz;
    if (!GetFileSizeEx(h, &sz)) { printf("ERR: size\n"); return 1; }
    uint8_t *buf = (uint8_t *)malloc((size_t)sz.QuadPart + 1);
    if (!buf) { printf("ERR: nomem\n"); return 1; }
    LARGE_INTEGER freq, t0, t1;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t0);
    uint64_t total = 0;
    // read with a deliberately unaligned chunk size to exercise partial sectors
    const DWORD chunk = 8192 + 137;
    while (total < (uint64_t)sz.QuadPart) {
        DWORD want = (DWORD)((sz.QuadPart - total) < chunk ? (sz.QuadPart - total) : chunk);
        DWORD got = 0;
        if (!ReadFile(h, buf + total, want, &got, 0) || got != want) {
            printf("ERR: read at %llu (win32 %lu)\n", (unsigned long long)total, GetLastError());
            return 1;
        }
        total += got;
    }
    QueryPerformanceCounter(&t1);
    CloseHandle(h);

    double ms = (double)(t1.QuadPart - t0.QuadPart) * 1000.0 / (double)freq.QuadPart;
    uint8_t sha[32];
    if (!acv_sha256(buf, (size_t)total, sha)) { printf("ERR: sha\n"); return 1; }
    char report[320];
    int n = snprintf(report, sizeof report, "SIZE: %llu\nREAD_MS: %.0f\nSHA256: ",
        (unsigned long long)total, ms);
    for (int i = 0; i < 32 && n < (int)sizeof report; i++)
        n += snprintf(report + n, sizeof report - (size_t)n, "%02x", sha[i]);
    n += snprintf(report + n, sizeof report - (size_t)n, "\nOK\n");
    printf("%s", report);
    if (outPath) acv_write_file(outPath, report, (size_t)n);
    return 0;
}
