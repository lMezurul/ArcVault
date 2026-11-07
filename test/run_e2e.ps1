# ArcVault end-to-end test (ASCII only, PowerShell 5.1 compatible)
#
# Generates a random payload, packs it, mounts the container through WinFsp,
# checks that only the trusted process can read it, that the plaintext matches,
# that a tampered container is rejected, and that unmounting is clean.

$ErrorActionPreference = 'SilentlyContinue'
$root = Split-Path -Parent $PSScriptRoot
$bin  = Join-Path $root 'bin'
$work = Join-Path $root 'test\work'
$mnt  = Join-Path $work 'mnt'
$fail = 0

function Check($name, $cond) {
    if ($cond) { Write-Host "[PASS] $name" -ForegroundColor Green }
    else       { Write-Host "[FAIL] $name" -ForegroundColor Red; $script:fail++ }
}

Write-Host "== ArcVault E2E =="
Get-Process arcvault -ErrorAction SilentlyContinue | Stop-Process -Force
if (Test-Path $work) { Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue }
New-Item -ItemType Directory -Force $work | Out-Null

# ---- 1. payload ------------------------------------------------------------
$bytes = New-Object byte[] (4MB)
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$rng.GetBytes($bytes)
$rng.Dispose()
[IO.File]::WriteAllBytes("$work\payload.pak", $bytes)
$refSha = (Get-FileHash "$work\payload.pak" -Algorithm SHA256).Hash.ToLower()
Write-Host "payload sha256: $refSha"

# ---- 2. key, pack, info, verify -------------------------------------------
& "$bin\arcvault-encrypt.exe" genkey "$work\license.key"
if ($LASTEXITCODE -ne 0) { Write-Host "FATAL: genkey failed"; exit 1 }
& "$bin\arcvault-encrypt.exe" pack "$work\payload.pak" "$work\vault.bin" "$work\license.key"
Check 'pack exit code' ($LASTEXITCODE -eq 0)
& "$bin\arcvault-encrypt.exe" info "$work\vault.bin"
Check 'info exit code' ($LASTEXITCODE -eq 0)
& "$bin\arcvault-encrypt.exe" verify "$work\vault.bin" "$work\license.key" | Out-Null
Check 'decrypt-all verify' ($LASTEXITCODE -eq 0)

# wrong key must not decrypt
& "$bin\arcvault-encrypt.exe" verify "$work\vault.bin" "$work\payload.pak" 2>&1 | Out-Null
Check 'wrong license rejected' ($LASTEXITCODE -ne 0)

# tampered ciphertext must not decrypt
Copy-Item "$work\vault.bin" "$work\tampered.bin"
$fs = [IO.File]::Open("$work\tampered.bin", 'Open', 'ReadWrite')
$fs.Position = 4096
$b = $fs.ReadByte()
$fs.Position = 4096
$fs.WriteByte(($b -bxor 0xFF))
$fs.Close()
& "$bin\arcvault-encrypt.exe" verify "$work\tampered.bin" "$work\license.key" 2>&1 | Out-Null
Check 'tampered container rejected' ($LASTEXITCODE -ne 0)

# ---- 3. mount -------------------------------------------------------------
$launch = '"{0}" --out "{1}" "{2}"' -f "$bin\demo-app.exe", "$work\result.txt", "$mnt\vault.bin"
# --launch takes the whole child command line as one argument: escape inner quotes
$escaped = '"' + $launch.Replace('"', '\"') + '"'
$launchArgs = '--store "{0}" --mount "{1}" --license "{2}" --watch demo-app.exe --launch {3} --idle-exit 8 --verify-store' -f "$work\vault.bin", $mnt, "$work\license.key", $escaped

$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = "$bin\arcvault.exe"
$psi.Arguments = $launchArgs
$psi.WorkingDirectory = $work
$psi.UseShellExecute = $false
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$psi.CreateNoWindow = $true
$proc = [System.Diagnostics.Process]::Start($psi)
$outTask = $proc.StandardOutput.ReadToEndAsync()

$deadline = (Get-Date).AddSeconds(25)
while ((Get-Date) -lt $deadline -and -not (Test-Path $mnt)) { Start-Sleep -Milliseconds 200 }
Check 'mount point created' (Test-Path $mnt)

# ---- 4. guard -------------------------------------------------------------
$cmdType = cmd /c type "$mnt\vault.bin" 2>&1 | Out-String
Check 'cmd.exe read denied' ($LASTEXITCODE -ne 0 -and $cmdType -notmatch $refSha)

$psRead = try { [System.IO.File]::ReadAllBytes("$mnt\vault.bin") | Out-Null; 'READ_OK' } catch { "DENIED: $($_.Exception.GetType().Name)" }
Check '.NET read denied' ($psRead -notmatch 'READ_OK')

$dirList = cmd /c dir /b "$mnt" 2>&1 | Out-String
Check 'directory listing denied' ($dirList -notmatch 'vault\.bin')
Write-Host "  denials: type=$($cmdType.Trim()) | .NET=$psRead | dir=$($dirList.Trim())"

# ---- 5. trusted reader ----------------------------------------------------
$deadline = (Get-Date).AddSeconds(10)
while ((Get-Date) -lt $deadline -and -not (Test-Path "$work\result.txt")) { Start-Sleep -Milliseconds 200 }
$result = if (Test-Path "$work\result.txt") { Get-Content "$work\result.txt" -Raw } else { '' }
$demoSha = if ($result -match 'SHA256: ([0-9a-f]{64})') { $Matches[1] } else { '' }
Check 'trusted process read the plaintext' ($demoSha -eq $refSha)

# ---- 6. lifecycle ---------------------------------------------------------
$deadline = (Get-Date).AddSeconds(40)
while ((Get-Date) -lt $deadline -and -not $proc.HasExited) { Start-Sleep -Milliseconds 500 }
Start-Sleep -Seconds 1

$log = ''
try { $log = $outTask.Result } catch {}
if (-not $log) { try { $log = $proc.StandardError.ReadToEnd() } catch {} }
Write-Host '--- launcher log:'
$log -split "`r?`n" | Where-Object { $_.Trim() } | ForEach-Object { Write-Host "  $_" }

Check 'launcher exited cleanly' ($proc.HasExited -and $proc.ExitCode -eq 0)
Check 'mount point removed' (-not (Test-Path $mnt))
Check 'container kept on disk' (Test-Path "$work\vault.bin")
Check 'denials logged' ($log -match '\[guard\] DENIED')

Write-Host "== E2E finished, failures: $fail =="
if ($fail -gt 0) { exit 1 } else { exit 0 }



