# Contributing

Thanks for taking a look at ArcVault. Bug reports, ideas and pull requests are welcome.

## Build

Requirements: Windows 10/11 and a C++17 compiler. The build script uses
[Zig](https://ziglang.org/) as a self-contained clang + mingw-w64 toolchain:

```bat
winget install zig.zig
build.bat
```

The WinFsp headers are vendored in `third_party/winfsp`, so no SDK installation is needed to
compile. Running the binaries requires [WinFsp](https://winfsp.dev/) 2.x:

```bat
winget install WinFsp.WinFsp
```

## Tests

The end-to-end test builds a container, mounts it and checks the guard, so it needs WinFsp and a
terminal that is allowed to mount a user-mode file system:

```powershell
powershell -ExecutionPolicy Bypass -File test\run_e2e.ps1
```

All checks should pass with `failures: 0`.

## Pull requests

- keep changes focused: one fix or feature per PR;
- do not commit build output (`bin/`, `*.pdb`, test containers);
- describe what changed and how you tested it;
- if you touch the container format or crypto, explain the compatibility impact.

## Code style

- C++17, no exceptions, no third-party runtime dependencies;
- Win32 error handling returns `NTSTATUS` from file-system callbacks;
- comments explain *why*, not *what*.
