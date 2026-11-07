// arcvault.exe — mounts an encrypted container as a virtual read-only file
//
// The container (vault.bin) exists on disk only as AES-256-XTS ciphertext. At
// runtime WinFsp exposes it as one file (vault.bin by default) inside the mount
// point; reads are decrypted on the fly, sector by sector, and only the process
// named with --watch is allowed to open it.
//
// flow: load store -> validate license/HWID -> unwrap content key -> mount (WinFsp)
//       -> optionally start the app -> keep mounted while it runs -> unmount.

#include "crypto.h"
#include "vault.h"

#include <windows.h>
#include <winternl.h>
#include <intrin.h>
#undef _ReadWriteBarrier        // mingw defines this as a macro; fsctl.h declares it as a function
#include <winfsp/winfsp.h>
#include <sddl.h>
#include <shellapi.h>
#include <tlhelp32.h>
#include <stdarg.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// ---------------------------------------------------------------- WinFsp binding
// WinFsp 2.x does not ship an import lib usable by mingw; bind the DLL at runtime.

typedef NTSTATUS (*FspFileSystemPreflight_t)(PWSTR DevicePath, PWSTR MountPoint);
typedef NTSTATUS (*FspFileSystemCreate_t)(PWSTR DevicePath,
    const FSP_FSCTL_VOLUME_PARAMS *VolumeParams,
    const FSP_FILE_SYSTEM_INTERFACE *Interface, FSP_FILE_SYSTEM **PFileSystem);
typedef VOID (*FspFileSystemDelete_t)(FSP_FILE_SYSTEM *FileSystem);
typedef NTSTATUS (*FspFileSystemSetMountPoint_t)(FSP_FILE_SYSTEM *FileSystem, PWSTR MountPoint);
typedef NTSTATUS (*FspFileSystemStartDispatcher_t)(FSP_FILE_SYSTEM *FileSystem, ULONG ThreadCount);
typedef VOID (*FspFileSystemStopDispatcher_t)(FSP_FILE_SYSTEM *FileSystem);
typedef FSP_FILE_SYSTEM_OPERATION_CONTEXT *(*FspFileSystemGetOperationContext_t)(VOID);
typedef BOOLEAN (*FspFileSystemAddDirInfo_t)(FSP_FSCTL_DIR_INFO *DirInfo,
    PVOID Buffer, ULONG Length, PULONG PBytesTransferred);
typedef DWORD (*FspWin32FromNtStatus_t)(NTSTATUS Status);
typedef NTSTATUS (*FspVersion_t)(PUINT32 PVersion);
typedef PWSTR  (*FspSxsIdent_t)(VOID);
typedef NTSTATUS (*FspFsctlStartService_t)(VOID);
typedef NTSTATUS (*FspFsctlCreateVolume_t)(PWSTR DevicePath,
    const FSP_FSCTL_VOLUME_PARAMS *VolumeParams, PWSTR VolumeNameBuf, SIZE_T VolumeNameSize,
    PHANDLE PVolumeHandle);
typedef VOID (*FspFileSystemRemoveMountPoint_t)(FSP_FILE_SYSTEM *FileSystem);
typedef NTSTATUS (*FspFileSystemOp_t)(FSP_FILE_SYSTEM *,
    FSP_FSCTL_TRANSACT_REQ *, FSP_FSCTL_TRANSACT_RSP *);
typedef VOID (*FspDebugLogSetHandle_t)(HANDLE Handle);

static FspFileSystemPreflight_t            FspFileSystemPreflight_;
static FspFileSystemCreate_t               FspFileSystemCreate_;
static FspFileSystemDelete_t               FspFileSystemDelete_;
static FspFileSystemSetMountPoint_t        FspFileSystemSetMountPoint_;
static FspFileSystemStartDispatcher_t      FspFileSystemStartDispatcher_;
static FspFileSystemStopDispatcher_t       FspFileSystemStopDispatcher_;
static FspFileSystemGetOperationContext_t  FspFileSystemGetOperationContext_;
static FspFileSystemAddDirInfo_t           FspFileSystemAddDirInfo_;
static FspWin32FromNtStatus_t              FspWin32FromNtStatus_;
static FspVersion_t                        FspVersion_;
static FspSxsIdent_t                       FspSxsIdent_;
static FspFsctlStartService_t              FspFsctlStartService_;
static FspFsctlCreateVolume_t              FspFsctlCreateVolume_;
static FspFileSystemRemoveMountPoint_t     FspFileSystemRemoveMountPoint_;
static FspFileSystemOp_t
    OpCreate_, OpOverwrite_, OpCleanup_, OpClose_, OpRead_, OpWrite_,
    OpQueryInformation_, OpSetInformation_, OpQueryVolumeInformation_,
    OpSetVolumeInformation_, OpQueryDirectory_, OpFileSystemControl_,
    OpDeviceControl_, OpQuerySecurity_, OpSetSecurity_, OpFlushBuffers_,
    OpQueryStreamInformation_, OpEnter_, OpLeave_;
static FspDebugLogSetHandle_t              FspDebugLogSetHandle_;

static bool BindWinFsp()
{
    HMODULE m = 0;

    /* Explicit override from the launcher, useful for portable/custom installs
       and for forcing the active WinFsp 2.x SxS copy. */
    {
        wchar_t fromEnv[MAX_PATH] = {0};
        DWORD n = GetEnvironmentVariableW(L"WINFSP_DLL", fromEnv, MAX_PATH);
        if (n > 0 && n < MAX_PATH) m = LoadLibraryW(fromEnv);
    }

    /* WinFsp 2.x uses SxS and writes SxsDir only to the 32-bit registry view.
       A 64-bit process must therefore read SOFTWARE\\WOW6432Node\\WinFsp
       explicitly: the generic Software\\WinFsp lookup redirects only for
       32-bit callers and returns nothing here. Loading bin\\winfsp-x64.dll
       instead of the active SxS copy makes WinFsp reject the mount. */
    const wchar_t* roots[] = { L"Software\\WinFsp", L"SOFTWARE\\WOW6432Node\\WinFsp" };
    const wchar_t* values[] = { L"SxsDir", L"InstallDir" };
    for (int r = 0; r < 2 && !m; r++) {
        for (int v = 0; v < 2 && !m; v++) {
            wchar_t dir[MAX_PATH] = {0};
            DWORD sz = sizeof dir;
            if (RegGetValueW(HKEY_LOCAL_MACHINE, roots[r], values[v],
                    RRF_RT_REG_SZ, 0, dir, &sz) != ERROR_SUCCESS || !dir[0]) continue;
            wchar_t dll[MAX_PATH];
            _snwprintf(dll, MAX_PATH, L"%s\\bin\\winfsp-x64.dll", dir);
            m = LoadLibraryW(dll);
        }
    }

    if (!m) m = LoadLibraryW(L"winfsp-x64.dll"); // System32 (older layout)
    if (!m) return false;


#define BIND(var, name) do { var = (decltype(var))GetProcAddress(m, name); if (!var) return false; } while (0)
    BIND(FspFileSystemPreflight_, "FspFileSystemPreflight");
    BIND(FspFileSystemCreate_, "FspFileSystemCreate");
    BIND(FspFileSystemDelete_, "FspFileSystemDelete");
    BIND(FspFileSystemSetMountPoint_, "FspFileSystemSetMountPoint");
    BIND(FspFileSystemStartDispatcher_, "FspFileSystemStartDispatcher");
    BIND(FspFileSystemStopDispatcher_, "FspFileSystemStopDispatcher");
    BIND(FspFileSystemGetOperationContext_, "FspFileSystemGetOperationContext");
    BIND(FspFileSystemAddDirInfo_, "FspFileSystemAddDirInfo");
    BIND(FspWin32FromNtStatus_, "FspWin32FromNtStatus");
    BIND(FspVersion_, "FspVersion");
    BIND(FspSxsIdent_, "FspSxsIdent");
    BIND(FspFsctlStartService_, "FspFsctlStartService");
    BIND(FspFsctlCreateVolume_, "FspFsctlCreateVolume");
    BIND(FspFileSystemRemoveMountPoint_, "FspFileSystemRemoveMountPoint");
    BIND(OpCreate_, "FspFileSystemOpCreate");
    BIND(OpOverwrite_, "FspFileSystemOpOverwrite");
    BIND(OpCleanup_, "FspFileSystemOpCleanup");
    BIND(OpClose_, "FspFileSystemOpClose");
    BIND(OpRead_, "FspFileSystemOpRead");
    BIND(OpWrite_, "FspFileSystemOpWrite");
    BIND(OpQueryInformation_, "FspFileSystemOpQueryInformation");
    BIND(OpSetInformation_, "FspFileSystemOpSetInformation");
    BIND(OpQueryVolumeInformation_, "FspFileSystemOpQueryVolumeInformation");
    BIND(OpSetVolumeInformation_, "FspFileSystemOpSetVolumeInformation");
    BIND(OpQueryDirectory_, "FspFileSystemOpQueryDirectory");
    BIND(OpFileSystemControl_, "FspFileSystemOpFileSystemControl");
    BIND(OpDeviceControl_, "FspFileSystemOpDeviceControl");
    BIND(OpQuerySecurity_, "FspFileSystemOpQuerySecurity");
    BIND(OpSetSecurity_, "FspFileSystemOpSetSecurity");
    BIND(OpFlushBuffers_, "FspFileSystemOpFlushBuffers");
    BIND(OpQueryStreamInformation_, "FspFileSystemOpQueryStreamInformation");
    BIND(OpEnter_, "FspFileSystemOpEnter");
    BIND(OpLeave_, "FspFileSystemOpLeave");
    FspDebugLogSetHandle_ = (FspDebugLogSetHandle_t)GetProcAddress(m, "FspDebugLogSetHandle");
#undef BIND
    return true;
}

// ---------------------------------------------------------------- state
struct FileCtx {
    bool isDir;
};

static HANDLE   g_store = INVALID_HANDLE_VALUE;
static AcvHeader g_hdr;
static AcvXtsKey g_xk;
static wchar_t  g_vname[256] = L"vault.bin";       // virtual file name ("\\vault.bin")
static uint64_t g_originalSize;
static uint64_t g_sectorCount;
static uint64_t g_dataOffset;

static volatile LONG g_allowedPid = 0;
static HANDLE g_allowedProcess = 0;                // keeps PID from being reused
static wchar_t g_watchName[256] = L"";             // trusted process image name (required)
static wchar_t g_watchPath[1024] = L"";            // optional substring of the full image path
static HANDLE g_stopEvent = 0;
static volatile LONG g_denyCount = 0;
static DWORD g_idleExitSec = 10;
static volatile LONG g_everAdopted = 0;
static bool g_trace = false;

static void LogLine(const wchar_t *fmt, ...)
{
    // vwprintf produces nothing when stdout is redirected to a file/pipe;
    // format wide, then emit UTF-8 bytes explicitly.
    wchar_t wbuf[2048];
    va_list ap;
    va_start(ap, fmt);
    _vsnwprintf(wbuf, 2047, fmt, ap);
    va_end(ap);
    wbuf[2047] = 0;
    char u8[4200];
    int n = WideCharToMultiByte(CP_UTF8, 0, wbuf, -1, u8, (int)sizeof u8 - 1, 0, 0);
    if (n > 0) {
        u8[n - 1] = '\n';           // replace NUL terminator with newline
        fwrite(u8, 1, (size_t)n, stdout);
    }
    fflush(stdout);
}

static void LowerWcs(wchar_t *dst, size_t cap, const wchar_t *src)
{
    size_t i = 0;
    for (; src[i] && i < cap - 1; i++) dst[i] = (wchar_t)towlower(src[i]);
    dst[i] = 0;
}

// ---------------------------------------------------------------- guard
enum GuardAccess { ACCESS_STRICT = 0, ACCESS_OFF = 1 };
static GuardAccess g_access = ACCESS_STRICT;

static bool TrustedPidCheck(uint32_t pid)
{
    if (!pid) return false;
    if (pid == (uint32_t)g_allowedPid) {
        // our handle keeps the process object alive -> PID cannot be recycled while we hold it
        if (g_allowedProcess && WaitForSingleObject(g_allowedProcess, 0) == WAIT_TIMEOUT)
            return true;
        g_allowedPid = 0; // stale
    }

    HANDLE h = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return false;
    wchar_t path[1024] = {0};
    DWORD psz = sizeof path;
    bool ok = !!QueryFullProcessImageNameW(h, 0, path, &psz);
    if (ok) {
        // name = last path component
        const wchar_t *name = path;
        for (const wchar_t *p = path; *p; p++)
            if (*p == L'\\') name = p + 1;
        ok = _wcsicmp(name, g_watchName) == 0;
        if (ok && g_watchPath[0]) {
            // case-insensitive substring on full image path
            wchar_t pl[1024], wl[1024];
            LowerWcs(pl, 1024, path);
            LowerWcs(wl, 1024, g_watchPath);
            ok = wcsstr(pl, wl) != 0;
        }
    }
    if (!ok) { CloseHandle(h); return false; }

    // adopt: swap in verified process
    HANDLE old = g_allowedProcess;
    g_allowedProcess = h;
    g_allowedPid = (LONG)pid;
    g_everAdopted = 1;
    if (old) CloseHandle(old);
    LogLine(L"[guard] trusted process adopted: pid %lu  %s", (unsigned long)pid, path);
    return true;
}

static bool AllowAccess(uint32_t pid)
{
    if (g_access == ACCESS_OFF) return true;
    return TrustedPidCheck(pid);
}

static uint32_t CallerPid()
{
    // only valid during Create/Open (all opens are FspFsctlTransactCreateKind)
    FSP_FILE_SYSTEM_OPERATION_CONTEXT *oc = FspFileSystemGetOperationContext_();
    if (!oc || !oc->Request) return 0;
    FSP_FSCTL_TRANSACT_REQ *req = oc->Request;
    if (req->Kind != FspFsctlTransactCreateKind) return 0;
    return FSP_FSCTL_TRANSACT_REQ_TOKEN_PID(req->Req.Create.AccessToken);
}

static uint32_t CallerPid();

static FSP_FILE_SYSTEM *CreateFileSystemManual(const FSP_FSCTL_VOLUME_PARAMS *P);
static void DeleteFileSystemManual(FSP_FILE_SYSTEM *fs);

// ---------------------------------------------------------------- store io
static bool StorePread(uint64_t off, void *buf, DWORD len)
{
    OVERLAPPED ov; memset(&ov, 0, sizeof ov);
    ov.Offset = (DWORD)off;
    ov.OffsetHigh = (DWORD)(off >> 32);
    DWORD got = 0;
    if (!ReadFile(g_store, buf, len, &got, &ov)) {
        if (GetLastError() != ERROR_IO_PENDING) return false;
        if (!GetOverlappedResult(g_store, &ov, &got, TRUE)) return false;
    }
    return got == len;
}

// ---------------------------------------------------------------- FS interface
static NTSTATUS FsGetVolumeInfo(FSP_FILE_SYSTEM *fs, FSP_FSCTL_VOLUME_INFO *Info)
{
    (void)fs;
    uint64_t total = g_dataOffset + g_sectorCount * ACV_SECTOR_SIZE;
    Info->TotalSize = total;
    Info->FreeSize = 0;
    Info->VolumeLabelLength = 7;
    wcscpy(Info->VolumeLabel, L"ACVAULT");
    return STATUS_SUCCESS;
}

static PSECURITY_DESCRIPTOR g_sd = 0;
static SIZE_T g_sdSize = 0;

static NTSTATUS FsGetSecurityByName(FSP_FILE_SYSTEM *fs, PWSTR FileName,
    PUINT32 PFileAttributes, PSECURITY_DESCRIPTOR SecurityDescriptor, SIZE_T *PSecurityDescriptorSize)
{
    (void)fs;
    if (PFileAttributes) {
        if (0 == wcscmp(FileName, L"\\"))
            *PFileAttributes = FILE_ATTRIBUTE_DIRECTORY;
        else
            *PFileAttributes = FILE_ATTRIBUTE_NORMAL;
    }
    if (SecurityDescriptor && PSecurityDescriptorSize) {
        if (*PSecurityDescriptorSize < g_sdSize) {
            *PSecurityDescriptorSize = g_sdSize;
            return STATUS_BUFFER_OVERFLOW;
        }
        memcpy(SecurityDescriptor, g_sd, g_sdSize);
        *PSecurityDescriptorSize = g_sdSize;
    }
    return STATUS_SUCCESS;
}

static NTSTATUS FsOpen(FSP_FILE_SYSTEM *fs, PWSTR FileName, UINT32 CreateOptions,
    UINT32 GrantedAccess, PVOID *PFileContext, FSP_FSCTL_FILE_INFO *FileInfo)
{
    (void)fs; (void)CreateOptions; (void)GrantedAccess;

    uint32_t pid = CallerPid();
    if (!AllowAccess(pid)) {
        InterlockedIncrement(&g_denyCount);
        LogLine(L"[guard] DENIED open of %s from pid %lu", FileName, (unsigned long)pid);
        return STATUS_ACCESS_DENIED;
    }

    // WinFsp paths look like "\vault.bin"; root is "\\"
    const wchar_t *rel = FileName + (FileName[0] == L'\\' ? 1 : 0);
    bool isDir = !*rel;
    bool isFile = !isDir && 0 == _wcsicmp(rel, g_vname);
    if (!isDir && !isFile)
        return STATUS_OBJECT_NAME_NOT_FOUND;

    FileCtx *ctx = new FileCtx();
    ctx->isDir = isDir;
    *PFileContext = ctx;

    memset(FileInfo, 0, sizeof *FileInfo);
    FileInfo->FileAttributes = isDir ? FILE_ATTRIBUTE_DIRECTORY : FILE_ATTRIBUTE_NORMAL;
    FileInfo->AllocationSize = g_originalSize;
    FileInfo->FileSize = isDir ? 0 : g_originalSize;
    FileInfo->LastWriteTime = 0x01D4000000000000ull;
    FileInfo->CreationTime = FileInfo->LastAccessTime = FileInfo->ChangeTime = FileInfo->LastWriteTime;
    return STATUS_SUCCESS;
}

static NTSTATUS FsCreate(FSP_FILE_SYSTEM *fs, PWSTR FileName, UINT32 CreateOptions,
    UINT32 GrantedAccess, UINT32 FileAttributes, PSECURITY_DESCRIPTOR SecurityDescriptor,
    UINT64 AllocationSize, PVOID *PFileContext, FSP_FSCTL_FILE_INFO *FileInfo)
{
    (void)fs; (void)FileName; (void)CreateOptions; (void)GrantedAccess;
    (void)FileAttributes; (void)SecurityDescriptor; (void)AllocationSize;
    (void)PFileContext; (void)FileInfo;
    return STATUS_ACCESS_DENIED; // read-only volume
}

// required non-NULL by FspFileSystemOpCreate even on read-only volumes
static NTSTATUS FsOverwrite(FSP_FILE_SYSTEM *fs, PVOID FileContext, UINT32 FileAttributes,
    BOOLEAN ReplaceFileAttributes, UINT64 AllocationSize, FSP_FSCTL_FILE_INFO *FileInfo)
{
    (void)fs; (void)FileContext; (void)FileAttributes; (void)ReplaceFileAttributes;
    (void)AllocationSize; (void)FileInfo;
    return STATUS_ACCESS_DENIED;
}

static VOID FsCleanup(FSP_FILE_SYSTEM *fs, PVOID FileContext, PWSTR FileName, ULONG Flags)
{
    (void)fs; (void)FileContext; (void)FileName; (void)Flags;
}

static VOID FsClose(FSP_FILE_SYSTEM *fs, PVOID FileContext)
{
    (void)fs;
    delete (FileCtx *)FileContext;
}

static NTSTATUS FsRead(FSP_FILE_SYSTEM *fs, PVOID FileContext, PVOID Buffer,
    UINT64 Offset, ULONG Length, PULONG PBytesTransferred)
{
    (void)fs; (void)FileContext;
    *PBytesTransferred = 0;
    if (Offset >= g_originalSize) return STATUS_SUCCESS;
    uint64_t want = (uint64_t)Length;
    if (Offset + want > g_originalSize) want = g_originalSize - Offset;
    if (!want) return STATUS_SUCCESS;

    uint64_t secLo = Offset / ACV_SECTOR_SIZE;
    uint64_t secHi = (Offset + want - 1) / ACV_SECTOR_SIZE;

    uint8_t *scratch = (uint8_t *)_aligned_malloc(ACV_SECTOR_SIZE, 16);
    if (!scratch) return STATUS_INSUFFICIENT_RESOURCES;

    NTSTATUS st = STATUS_SUCCESS;
    uint8_t *out = (uint8_t *)Buffer;
    for (uint64_t s = secLo; s <= secHi; s++) {
        if (!StorePread(g_dataOffset + s * ACV_SECTOR_SIZE, scratch, ACV_SECTOR_SIZE)) {
            st = STATUS_IO_DEVICE_ERROR;
            break;
        }
        uint32_t crc;
        if (!StorePread(ACVF_HEADER_SIZE + s * 4, &crc, 4)) { // CRC table follows the header
            st = STATUS_IO_DEVICE_ERROR;
            break;
        }
        if (acv_crc32(0, scratch, ACV_SECTOR_SIZE) != crc) {
            LogLine(L"[vault] sector %llu: CRC mismatch (corrupted store)", (unsigned long long)s);
            st = STATUS_FILE_CORRUPT_ERROR;
            break;
        }
        if (!acv_xts_decrypt(&g_xk, s, scratch, ACV_SECTOR_SIZE)) {
            st = STATUS_IO_DEVICE_ERROR;
            break;
        }
        uint64_t sLo = s * ACV_SECTOR_SIZE;
        uint64_t from = Offset > sLo ? Offset : sLo;
        uint64_t to = (Offset + want) < (sLo + ACV_SECTOR_SIZE) ? (Offset + want) : (sLo + ACV_SECTOR_SIZE);
        memcpy(out + (from - Offset), scratch + (from - sLo), (size_t)(to - from));
    }
    _aligned_free(scratch);
    if (st == STATUS_SUCCESS) *PBytesTransferred = (ULONG)want;
    return st;
}

static NTSTATUS FsGetFileInfo(FSP_FILE_SYSTEM *fs, PVOID FileContext, FSP_FSCTL_FILE_INFO *FileInfo)
{
    (void)fs;
    FileCtx *ctx = (FileCtx *)FileContext;
    memset(FileInfo, 0, sizeof *FileInfo);
    FileInfo->FileAttributes = ctx->isDir ? FILE_ATTRIBUTE_DIRECTORY : FILE_ATTRIBUTE_NORMAL;
    FileInfo->AllocationSize = ctx->isDir ? 0 : g_originalSize;
    FileInfo->FileSize = ctx->isDir ? 0 : g_originalSize;
    FileInfo->LastWriteTime = 0x01D4000000000000ull;
    FileInfo->CreationTime = FileInfo->LastAccessTime = FileInfo->ChangeTime = FileInfo->LastWriteTime;
    return STATUS_SUCCESS;
}

static NTSTATUS FsFlush(FSP_FILE_SYSTEM *fs, PVOID FileContext, FSP_FSCTL_FILE_INFO *FileInfo)
{
    (void)fs;
    if (FileInfo && FileContext && !((FileCtx *)FileContext)->isDir) {
        memset(FileInfo, 0, sizeof *FileInfo);
        FileInfo->FileAttributes = FILE_ATTRIBUTE_NORMAL;
        FileInfo->AllocationSize = FileInfo->FileSize = g_originalSize;
    }
    return STATUS_SUCCESS;
}

static NTSTATUS FsGetSecurity(FSP_FILE_SYSTEM *fs, PVOID FileContext,
    PSECURITY_DESCRIPTOR SecurityDescriptor, SIZE_T *PSecurityDescriptorSize)
{
    (void)fs; (void)FileContext;
    if (*PSecurityDescriptorSize < g_sdSize) {
        *PSecurityDescriptorSize = g_sdSize;
        return STATUS_BUFFER_OVERFLOW;
    }
    memcpy(SecurityDescriptor, g_sd, g_sdSize);
    *PSecurityDescriptorSize = g_sdSize;
    return STATUS_SUCCESS;
}

static NTSTATUS FsReadDirectory(FSP_FILE_SYSTEM *fs, PVOID FileContext, PWSTR Pattern,
    PWSTR Marker, PVOID Buffer, ULONG BufferLength, PULONG PBytesTransferred)
{
    (void)fs; (void)Pattern;
    FileCtx *ctx = (FileCtx *)FileContext;
    if (!ctx->isDir) return STATUS_NOT_A_DIRECTORY;

    *PBytesTransferred = 0;
    struct { const wchar_t *name; uint32_t attr; } entries[] = {
        { L".", FILE_ATTRIBUTE_DIRECTORY },
        { L"..", FILE_ATTRIBUTE_DIRECTORY },
        { g_vname, FILE_ATTRIBUTE_NORMAL },
    };
    for (auto &e : entries) {
        if (Marker && *Marker && wcscmp(e.name, Marker) <= 0) continue;
        FSP_FSCTL_DIR_INFO *di = (FSP_FSCTL_DIR_INFO *)_aligned_malloc(512, 8);
        memset(di, 0, 512);
        di->Size = (UINT16)(sizeof(FSP_FSCTL_DIR_INFO) + wcslen(e.name) * sizeof(WCHAR));
        di->FileInfo.FileAttributes = e.attr;
        di->FileInfo.LastWriteTime = 0x01D4000000000000ull;
        wcscpy(di->FileNameBuf, e.name);
        FspFileSystemAddDirInfo_(di, Buffer, BufferLength, PBytesTransferred);
        _aligned_free(di);
    }
    return STATUS_SUCCESS;
}

static FSP_FILE_SYSTEM_INTERFACE g_iface = {
    FsGetVolumeInfo,
    0,                       // SetVolumeLabel
    FsGetSecurityByName,
    FsCreate,
    FsOpen,
    FsOverwrite,
    FsCleanup,
    FsClose,
    FsRead,
    0,                       // Write
    FsFlush,
    FsGetFileInfo,
    0,                       // SetBasicInfo
    0,                       // SetFileSize
    0,                       // CanDelete
    0,                       // Rename
    FsGetSecurity,
    0,                       // SetSecurity
    FsReadDirectory,
    0,                       // ResolveReparsePoints
    0,                       // GetReparsePoint
    0,                       // SetReparsePoint
    0,                       // DeleteReparsePoint
    0,                       // GetStreamInfo
    0,                       // GetDirInfoByName
    0,                       // Control
    0,                       // SetDelete
};

// ---------------------------------------------------------------- lifecycle
static BOOL WINAPI CtrlHandler(DWORD type)
{
    (void)type;
    if (g_stopEvent) SetEvent(g_stopEvent);
    return TRUE;
}

static bool FindWatchProcess()
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;
    PROCESSENTRY32W pe; pe.dwSize = sizeof pe;
    bool found = false;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (0 == _wcsicmp(pe.szExeFile, g_watchName)) {
                if (TrustedPidCheck(pe.th32ProcessID)) { found = true; break; }
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return found;
}

static DWORD WINAPI WatchdogThread(LPVOID)
{
    DWORD idle = 0;
    for (;;) {
        if (WaitForSingleObject(g_stopEvent, 1000) == WAIT_OBJECT_0) return 0;
        if (!g_allowedPid) {
            // re-scan in case the app (re)appeared; unmount only if we HAD one
            if (FindWatchProcess()) idle = 0;
            else if (g_everAdopted) {
                idle++;
                if (idle >= g_idleExitSec) {
                    LogLine(L"[watch] app gone for %lus -> unmounting", (unsigned long)idle);
                    SetEvent(g_stopEvent);
                    return 0;
                }
            }
            continue;
        }
        if (WaitForSingleObject(g_allowedProcess, 0) != WAIT_TIMEOUT) {
            LogLine(L"[watch] app process exited");
            g_allowedPid = 0;
            CloseHandle(g_allowedProcess);
            g_allowedProcess = 0;
            idle = 1;
        }
    }
}

struct Args {
    wchar_t store[MAX_PATH] = L"vault.bin";
    wchar_t mount[MAX_PATH] = L"";      // directory mount (preferred)
    wchar_t drive[8] = L"";             // drive letter fallback ("Z:")
    wchar_t licFile[MAX_PATH] = L"license.key";
    wchar_t launch[1024] = L"";         // URL or "exe args"
    bool launchIsExe = false;
    DWORD waitAppSec = 120;
    bool verifyStore = false;
};

static void Usage()
{
    wprintf(
        L"ArcVault %s - encrypted container mounted as a virtual read-only file\n"
        L"\n"
        L"Usage:\n"
        L"  arcvault.exe --watch <exe> [options]\n"
        L"\n"
        L"Required:\n"
        L"  --watch <exe>          process allowed to open the virtual file\n"
        L"\n"
        L"Options:\n"
        L"  --store <file>         encrypted container                (vault.bin)\n"
        L"  --mount <dir>          mount point directory; created on start, removed on unmount\n"
        L"  --drive <X:>           mount as a drive letter when --mount is not given\n"
        L"  --name <file>          name of the virtual file           (vault.bin)\n"
        L"  --license <file>       license key file                   (license.key)\n"
        L"  --watch-path <text>    optional substring of the trusted process full path\n"
        L"  --launch <url|cmd>     start the app after mounting (URL via shell, else CreateProcess)\n"
        L"  --wait-app <sec>       how long to wait for the app started via URL (120)\n"
        L"  --idle-exit <sec>      unmount N seconds after the app exits (10)\n"
        L"  --guard <strict|off>   strict: only the watched process; off: no PID check (demo only)\n"
        L"  --verify-store         verify the full ciphertext SHA-256 before mounting\n"
        L"  --trace                write the WinFsp request trace to fsp-trace.log\n"
        L"  --help                 show this text\n",
        L"1.0.0");
}

static int RealMain(int argc, wchar_t **argv)
{
    Args A;
    g_idleExitSec = 10;
    for (int i = 1; i < argc; i++) {
#define NEXT() (++i < argc ? argv[i] : 0)
        if (!wcscmp(argv[i], L"--store") && NEXT()) wcsncpy(A.store, argv[i], MAX_PATH - 1);
        else if (!wcscmp(argv[i], L"--mount") && NEXT()) wcsncpy(A.mount, argv[i], MAX_PATH - 1);
        else if (!wcscmp(argv[i], L"--drive") && NEXT()) wcsncpy(A.drive, argv[i], 7);
        else if (!wcscmp(argv[i], L"--license") && NEXT()) wcsncpy(A.licFile, argv[i], MAX_PATH - 1);
        else if (!wcscmp(argv[i], L"--launch") && NEXT()) { wcsncpy(A.launch, argv[i], 1023); A.launchIsExe = wcsstr(A.launch, L"://") == 0; }
        else if (!wcscmp(argv[i], L"--name") && NEXT()) wcsncpy(g_vname, argv[i], 255);
        else if (!wcscmp(argv[i], L"--watch") && NEXT()) wcsncpy(g_watchName, argv[i], 255);
        else if (!wcscmp(argv[i], L"--watch-path") && NEXT()) wcsncpy(g_watchPath, argv[i], 1023);
        else if (!wcscmp(argv[i], L"--wait-app") && NEXT()) A.waitAppSec = (DWORD)_wtoi(argv[i]);
        else if (!wcscmp(argv[i], L"--idle-exit") && NEXT()) g_idleExitSec = (DWORD)_wtoi(argv[i]);
        else if (!wcscmp(argv[i], L"--guard") && NEXT()) {
            if (!_wcsicmp(argv[i], L"off")) g_access = ACCESS_OFF;
            else if (!_wcsicmp(argv[i], L"strict")) g_access = ACCESS_STRICT;
            else { printf("ERR: unknown guard mode %ls\n", argv[i]); return 2; }
        }
        else if (!wcscmp(argv[i], L"--verify-store")) A.verifyStore = true;
        else if (!wcscmp(argv[i], L"--trace")) g_trace = true;
        else if (!wcscmp(argv[i], L"--help") || !wcscmp(argv[i], L"-h")) { Usage(); return 0; }
        else { printf("ERR: bad arg %ls (try --help)\n", argv[i]); return 2; }
#undef NEXT
    }

    if (g_access == ACCESS_STRICT && !g_watchName[0]) {
        printf("ERR: --watch <exe> is required (or pass --guard off for a demo mount)\n\n");
        Usage();
        return 2;
    }

    setvbuf(stdout, 0, _IONBF, 0);
    LogLine(L"== ArcVault launcher ==");
    LogLine(L"[guard] mode: %s", g_access == ACCESS_OFF ? L"off (no PID check)" : L"strict");

    if (!BindWinFsp()) {
        LogLine(L"ERR: WinFsp not found — install WinFsp (winget install WinFsp.WinFsp)");
        return 1;
    }
    UINT32 vsp = 0;
    FspVersion_(&vsp);
    LogLine(L"[fsp] winfsp-x64.dll loaded, api version %u.%u", vsp / 10000, vsp % 10000);
    LogLine(L"[fsp] SxS ident: '%s'", FspSxsIdent_());

    // 1) license + HWID -> content key
    char lic[64];
    int rc = acv_license_load(A.licFile, lic);
    if (rc != ACV_OK) {
        LogLine(L"ERR: license file %s invalid (rc=%d)", A.licFile, rc);
        return 1;
    }
    char hwid[65];
    if (!acv_hwid(hwid)) { LogLine(L"ERR: hwid"); return 1; }

    // 2) open store + header
    g_store = CreateFileW(A.store, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING,
        FILE_FLAG_OVERLAPPED, 0);
    if (g_store == INVALID_HANDLE_VALUE) {
        LogLine(L"ERR: cannot open store %s (win32 %lu)", A.store, GetLastError());
        return 1;
    }
    {
        OVERLAPPED ov; memset(&ov, 0, sizeof ov);
        DWORD got = 0;
        if (!ReadFile(g_store, &g_hdr, sizeof g_hdr, &got, &ov) &&
            GetLastError() == ERROR_IO_PENDING)
            GetOverlappedResult(g_store, &ov, &got, TRUE);
        if (got != sizeof g_hdr || memcmp(g_hdr.magic, "ACVF", 4) != 0 ||
            g_hdr.version != ACVF_VERSION) {
            LogLine(L"ERR: bad store header");
            return 1;
        }
        if (acv_crc32(0, &g_hdr, 168) != g_hdr.headerCrc) {
            LogLine(L"ERR: store header CRC mismatch");
            return 1;
        }
    }
    g_originalSize = g_hdr.originalSize;
    g_sectorCount = g_hdr.sectorCount;
    g_dataOffset = acv_data_offset(&g_hdr);

    // 3) unwrap content key (fails on wrong license/machine)
    uint8_t wrapKey[64], contentKey[64];
    acv_license_wrap_key(lic, hwid, wrapKey);
    if (!acv_unwrap_key(g_hdr.wrappedKey, wrapKey, contentKey)) {
        LogLine(L"ERR: key unwrap failed");
        return 1;
    }
    if (!acv_xts_init(&g_xk, contentKey)) { LogLine(L"ERR: xts init"); return 1; }
    memset(contentKey, 0, sizeof contentKey);
    LogLine(L"[vault] license OK, HWID OK, key unwrapped (%llu sectors, %llu bytes)",
        (unsigned long long)g_sectorCount, (unsigned long long)g_originalSize);

    // 4) optional full ciphertext verification
    if (A.verifyStore) {
        uint8_t sha[32];
        LogLine(L"[vault] verifying store (this may take a moment)...");
        if (!acv_sha256_stream(g_store, g_dataOffset, g_sectorCount * ACV_SECTOR_SIZE, sha) ||
            memcmp(sha, g_hdr.shaCipher, 32) != 0) {
            LogLine(L"ERR: store ciphertext hash mismatch");
            return 1;
        }
        LogLine(L"[vault] store verified");
    }

    // 5) security descriptor: Everyone FILE_ALL_ACCESS — real gate is our Open guard.
    //    O:/G: required (kernel rejects owner-less SDs); FA (specific rights), not GA —
    //    user-mode AccessCheck does not map generic rights in ACEs.
    {
        PSECURITY_DESCRIPTOR sd = 0;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
                L"O:BAG:BUD:P(A;;FA;;;WD)", SDDL_REVISION_1, &sd, 0)) {
            LogLine(L"ERR: sddl (%lu)", GetLastError());
            return 1;
        }
        g_sd = sd;
        g_sdSize = GetSecurityDescriptorLength(sd);
    }

    // 6) mount
    FSP_FSCTL_VOLUME_PARAMS P;
    memset(&P, 0, sizeof P);
    P.Version = (UINT16)sizeof P;
    P.SectorSize = 512;
    P.SectorsPerAllocationUnit = 8;
    P.VolumeCreationTime = 0x01D4000000000000ull;
    P.VolumeSerialNumber = 0xAC1FAC00u ^ (g_hdr.originalSize & 0xFFFFu);
    P.CasePreservedNames = 1;
    P.CaseSensitiveSearch = 0;
    P.UnicodeOnDisk = 1;
    P.ReadOnlyVolume = 1;
    P.FlushAndPurgeOnCleanup = 1;
    P.PostCleanupWhenModifiedOnly = 1;
    wcscpy(P.FileSystemName, L"ACVF");

    FSP_FILE_SYSTEM *fs = CreateFileSystemManual(&P);
    if (!fs) {
        LogLine(L"ERR: CreateFileSystemManual failed");
        return 1;
    }

    NTSTATUS st;
    wchar_t mountUsed[MAX_PATH] = L"";
    if (A.mount[0]) {
        st = FspFileSystemSetMountPoint_(fs, A.mount);
        if (NT_SUCCESS(st)) wcscpy(mountUsed, A.mount);
    }
    if (!mountUsed[0]) {
        wchar_t drv[8];
        if (A.drive[0]) wcscpy(drv, A.drive);
        else {
            // pick a free drive letter from Z downwards
            wcscpy(drv, L"Z:");
            DWORD mask = GetLogicalDrives();
            while (mask & (1u << (drv[0] - 'A'))) {
                if (drv[0] == 'A') break;
                drv[0]--;
            }
        }
        st = FspFileSystemSetMountPoint_(fs, drv);
        if (NT_SUCCESS(st)) wcscpy(mountUsed, drv);
    }
    if (!mountUsed[0]) {
        LogLine(L"ERR: mount failed 0x%08lX", (unsigned long)st);
        DeleteFileSystemManual(fs);
        return 1;
    }

    st = FspFileSystemStartDispatcher_(fs, 0);
    if (!NT_SUCCESS(st)) {
        LogLine(L"ERR: StartDispatcher 0x%08lX", (unsigned long)st);
        DeleteFileSystemManual(fs);
        return 1;
    }
    LogLine(L"[fsp] mounted at %s  (virtual file: \\%s, %llu bytes)",
        mountUsed, g_vname, (unsigned long long)g_originalSize);

    g_stopEvent = CreateEventW(0, TRUE, FALSE, 0);
    SetConsoleCtrlHandler(CtrlHandler, TRUE);
    HANDLE wd = CreateThread(0, 0, WatchdogThread, 0, 0, 0);

    // 7) launch the app (URL via shell, exe via CreateProcess) or adopt an existing one
    if (A.launch[0]) {
        if (A.launchIsExe) {
            wchar_t cmd[1200];
            wcscpy(cmd, A.launch);
            STARTUPINFOW si; memset(&si, 0, sizeof si); si.cb = sizeof si;
            PROCESS_INFORMATION pi;
            if (CreateProcessW(0, cmd, 0, 0, FALSE, 0, 0, 0, &si, &pi)) {
                CloseHandle(pi.hThread);
                LogLine(L"[launch] started child pid %lu", (unsigned long)pi.dwProcessId);
                TrustedPidCheck(pi.dwProcessId);
                HANDLE old = g_allowedProcess;
                g_allowedProcess = pi.hProcess; // full handle, same process object
                if (old) CloseHandle(old);
            } else {
                LogLine(L"ERR: CreateProcess failed (%lu)", GetLastError());
            }
        } else {
            LogLine(L"[launch] ShellExecute %s", A.launch);
            ShellExecuteW(0, L"open", A.launch, 0, 0, SW_SHOWNORMAL);
        }
    }

    if (!g_allowedPid && A.launch[0] && !A.launchIsExe) {
        LogLine(L"[watch] waiting up to %lus for %s ...", (unsigned long)A.waitAppSec, g_watchName);
        for (DWORD t = 0; t < A.waitAppSec; t++) {
            if (WaitForSingleObject(g_stopEvent, 0) == WAIT_OBJECT_0) break;
            if (FindWatchProcess()) break;
            Sleep(1000);
        }
    } else if (!g_allowedPid) {
        FindWatchProcess();
    }

    if (g_allowedPid)
        LogLine(L"[watch] monitoring pid %lu", (unsigned long)g_allowedPid);
    else
        LogLine(L"[watch] trusted app not running yet — mount is live, guard is active");

    LogLine(L"[watch] Ctrl+C or app exit (idle %lus) -> unmount",
        (unsigned long)g_idleExitSec);

    WaitForSingleObject(g_stopEvent, INFINITE);

    // 8) unmount — manual FS: use field-level cleanup (FspFileSystemDelete_ would
    // try to free our struct with the DLL's allocator)
    LogLine(L"[fsp] stopping dispatcher, unmounting %s", mountUsed);
    FspFileSystemStopDispatcher_(fs);
    FspFileSystemRemoveMountPoint_(fs);
    CloseHandle(fs->VolumeHandle);
    free(fs);
    CloseHandle(g_store);
    CloseHandle(wd);
    LogLine(L"[done] denials this session: %lu", (unsigned long)g_denyCount);
    return 0;
}

// ---------------------------------------------------------------- FS creation
// FspFileSystemCreate fails on this system (its internal FspFsctlCreateVolume device
// open gets rejected), while the identical device open performed directly succeeds.
// So we replicate FspFileSystemCreate using exported APIs only:
//   1. warm up the DLL's TLS init with a failing FspFileSystemCreate call
//   2. open the control device + encoded volume params (byte-level, like fsctl.c)
//   3. query the volume name, fill the public FSP_FILE_SYSTEM struct
static FSP_FILE_SYSTEM *CreateFileSystemManual(const FSP_FSCTL_VOLUME_PARAMS *P)
{
    // 1) warmup: triggers FspFileSystemInitOnce (TlsAlloc) even though it fails
    FSP_FILE_SYSTEM *warm = 0;
    FspFileSystemCreate_((PWSTR)L"WinFsp.Disk", P, &g_iface, &warm);
    if (warm) FspFileSystemDelete_(warm);

    // 2) build the device path byte by byte (no printf: mingw CRT semantics differ)
    wchar_t path[1200];
    wchar_t *w = path;
    for (const wchar_t *s = L"\\\\?\\GLOBALROOT\\Device\\"; *s;) *w++ = *s++;
    for (const wchar_t *s = L"WinFsp.Disk"; *s;) *w++ = *s++;
    if (FspSxsIdent_()[0]) {
        *w++ = L'+';
        for (const wchar_t *s = FspSxsIdent_(); *s;) *w++ = *s++;
    }
    for (const wchar_t *s = L"\\VolumeParams="; *s;) *w++ = *s++;
    for (unsigned i = 0; i < sizeof(FSP_FSCTL_VOLUME_PARAMS); i++)
        *w++ = (wchar_t)(0xF000 | ((const PUINT8)P)[i]);
    *w = 0;

    SetLastError(0);
    HANDLE volHandle = CreateFileW(path, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, 0,
        OPEN_EXISTING, FILE_FLAG_OVERLAPPED, 0);
    if (volHandle == INVALID_HANDLE_VALUE) {
        LogLine(L"ERR: manual control device open failed (win32 %lu)", GetLastError());
        return 0;
    }

    // 3) allocate and fill the FS object (layout is public in winfsp.h)
    FSP_FILE_SYSTEM *fs = (FSP_FILE_SYSTEM *)calloc(1, sizeof(FSP_FILE_SYSTEM));
    if (!fs) { CloseHandle(volHandle); return 0; }

    DWORD bytes = 0;
    if (!DeviceIoControl(volHandle, FSP_FSCTL_VOLUME_NAME, 0, 0,
            fs->VolumeName, FSP_FSCTL_VOLUME_NAME_SIZEMAX, &bytes, 0)) {
        LogLine(L"ERR: VOLUME_NAME ioctl failed (win32 %lu)", GetLastError());
        CloseHandle(volHandle);
        free(fs);
        return 0;
    }
    fs->Version = (UINT16)sizeof(FSP_FILE_SYSTEM);
    fs->VolumeHandle = volHandle;
    fs->Operations[FspFsctlTransactCreateKind] = OpCreate_;
    fs->Operations[FspFsctlTransactOverwriteKind] = OpOverwrite_;
    fs->Operations[FspFsctlTransactCleanupKind] = OpCleanup_;
    fs->Operations[FspFsctlTransactCloseKind] = OpClose_;
    fs->Operations[FspFsctlTransactReadKind] = OpRead_;
    fs->Operations[FspFsctlTransactWriteKind] = OpWrite_;
    fs->Operations[FspFsctlTransactQueryInformationKind] = OpQueryInformation_;
    fs->Operations[FspFsctlTransactSetInformationKind] = OpSetInformation_;
    fs->Operations[FspFsctlTransactQueryVolumeInformationKind] = OpQueryVolumeInformation_;
    fs->Operations[FspFsctlTransactSetVolumeInformationKind] = OpSetVolumeInformation_;
    fs->Operations[FspFsctlTransactQueryDirectoryKind] = OpQueryDirectory_;
    fs->Operations[FspFsctlTransactFileSystemControlKind] = OpFileSystemControl_;
    fs->Operations[FspFsctlTransactDeviceControlKind] = OpDeviceControl_;
    fs->Operations[FspFsctlTransactQuerySecurityKind] = OpQuerySecurity_;
    fs->Operations[FspFsctlTransactSetSecurityKind] = OpSetSecurity_;
    fs->Operations[FspFsctlTransactFlushBuffersKind] = OpFlushBuffers_;
    fs->Operations[FspFsctlTransactQueryStreamInformationKind] = OpQueryStreamInformation_;
    fs->Interface = &g_iface;
    fs->OpGuardStrategy = FSP_FILE_SYSTEM_OPERATION_GUARD_STRATEGY_FINE;
    InitializeSRWLock(&fs->OpGuardLock);
    fs->EnterOperation = OpEnter_;
    fs->LeaveOperation = OpLeave_;
    // optional request/response trace (--trace): goes to fsp-trace.log
    if (g_trace && FspDebugLogSetHandle_) {
        HANDLE trace = CreateFileW(L"fsp-trace.log", GENERIC_WRITE, FILE_SHARE_READ, 0,
            CREATE_ALWAYS, 0, 0);
        if (trace != INVALID_HANDLE_VALUE) {
            FspDebugLogSetHandle_(trace);
            fs->DebugLog = (UINT32)-1;
        }
    }
    return fs;
}

static void DeleteFileSystemManual(FSP_FILE_SYSTEM *fs)
{
    if (!fs) return;
    FspFileSystemStopDispatcher_(fs);
    FspFileSystemRemoveMountPoint_(fs);
    CloseHandle(fs->VolumeHandle);
    free(fs);
}

int wmain(int argc, wchar_t **argv)
{
    return RealMain(argc, argv);
}
