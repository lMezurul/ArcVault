# WinFsp headers

`inc/winfsp/winfsp.h` and `inc/winfsp/fsctl.h` are unmodified headers from
[WinFsp 2.x](https://github.com/winfsp/winfsp), Copyright (C) Bill Zissimopoulos,
licensed under GPLv3 with the WinFsp FLOSS exception (see `LICENSE.txt`).

They are included at compile time only. At runtime the WinFsp DLL is loaded
dynamically from the installed SxS directory — ArcVault does not redistribute
the DLL or the driver. The ArcVault sources themselves are MIT licensed.

If the WinFsp SDK is installed system-wide, you can remove this directory and
point `WINFSP_INC` in `build.bat` at `%ProgramFiles(x86)%\WinFsp\inc` instead.
