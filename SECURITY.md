# Security policy

## Supported versions

| version | supported |
| ------- | --------- |
| 1.0.x   | yes       |

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

Report them privately through
[GitHub Security Advisories](https://github.com/lMezurul/ArcVault/security/advisories/new).
Include the affected version, reproduction steps, impact, and a proof of concept if you have one.

You can expect an initial reply within 72 hours. If the report is valid, a fix and a coordinated
disclosure will follow; credit is given unless you prefer otherwise.

## Scope

ArcVault is a user-mode file system, so the interesting attack surface is:

- the container format and cryptography (`src/crypto.cpp`, `src/vault.h`) — XTS key wrapping,
  header/CRC validation, sector handling;
- the process guard in the WinFsp open callback (`src/arcvault.cpp`) — PID and image path checks;
- license and HWID derivation.

## Out of scope

These are documented limitations, not vulnerabilities:

- an administrator/SYSTEM process reading the memory of the trusted application while plaintext
  is in use;
- code injection into the trusted process (the guard trusts the process, not its integrity);
- screen capture or re-encoding of already displayed content;
- the demo license scheme — it is explicitly a stub, see the README.
