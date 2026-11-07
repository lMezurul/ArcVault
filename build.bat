@echo off
rem ArcVault build script - uses zig c++ (clang, mingw-w64 target).
rem Any C++17 compiler works: MSVC, clang-cl, g++ (see README).
setlocal
set ROOT=%~dp0
set WINFSP_INC=%ROOT%third_party\winfsp\inc
set OUT=%ROOT%bin
if not exist "%OUT%" mkdir "%OUT%"

set ZIG=
where zig >nul 2>&1 && set ZIG=zig
if not defined ZIG if exist "%LOCALAPPDATA%\Microsoft\WinGet\Links\zig.exe" set ZIG=%LOCALAPPDATA%\Microsoft\WinGet\Links\zig.exe
if not defined ZIG for /d %%D in ("%LOCALAPPDATA%\Microsoft\WinGet\Packages\zig.zig_*") do for /d %%E in ("%%~fD\zig-*") do if exist "%%~fE\zig.exe" set ZIG=%%~fE\zig.exe
if not defined ZIG (
    echo ERR: zig not found. Install it with: winget install zig.zig
    exit /b 1
)

set CFLAGS=-std=c++17 -O2 -Wall -Wextra -Wno-unknown-pragmas -Wno-unknown-attributes -Wno-logical-op-parentheses -Wno-missing-field-initializers -target x86_64-windows-gnu -municode -I"%WINFSP_INC%" -DUNICODE -D_UNICODE

echo == building arcvault-encrypt.exe
"%ZIG%" c++ %CFLAGS% -o "%OUT%\arcvault-encrypt.exe" src\encrypt_tool.cpp src\crypto.cpp -lbcrypt -ladvapi32 || exit /b 1

echo == building arcvault.exe
"%ZIG%" c++ %CFLAGS% -o "%OUT%\arcvault.exe" src\arcvault.cpp src\crypto.cpp -lbcrypt -ladvapi32 -lshell32 -luser32 -lole32 || exit /b 1

echo == building demo-app.exe
"%ZIG%" c++ %CFLAGS% -o "%OUT%\demo-app.exe" src\demo_app.cpp src\crypto.cpp -lbcrypt -ladvapi32 || exit /b 1

echo == done
dir /b "%OUT%"
endlocal
