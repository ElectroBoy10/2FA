# 2FA Generator — Project Archive
**Author:** MrBros (https://mrbros1509.bio.link)

This archive contains every meaningful release of the 2FA Generator, from the
original V1 CLI tool through to the current V3 with a full public API.

---

## Install

```bash
pip install pyotp colorama qrcode
```

`qrcode` is optional — everything works without it except QR display.

Run the latest version:

```bash
python 2FA_V3.06.16.py
```

---

## Version History

### V1.02.00 — Original CLI
`2FA_V1.02.00.py`

The first version. Pure command-line tool using `argparse`. No interactive
menu — everything passed as flags. Supports TOTP and HOTP, configurable
algorithm, digits, and period.

```bash
python 2FA_V1.02.00.py --type totp --issuer GitHub
```

---

### V2.02.15 — Interactive Menu
`2FA_V2.02.15.py`

First version with an interactive terminal menu. Introduced Basic and Advanced
generation modes, and the Program Info screen with the version box format that
carried through to V3.

---

### V2.02.17 — Colour Terminal UI
`2FA_V2.02.17.py`

Added `colorama` for coloured terminal output. Same features as V2.02.15 with
a proper colour-coded menu and result screens.

---

### V2.03.18 — Dependency Checker
`2FA_V2.03.18.py`

Final V2 release. Added startup dependency check with a tkinter popup fallback,
`clamp_digits()` for safe digit input, and a `VERSION` constant. The last
version before the V3 rewrite.

---

### V3.00.00 — V3 Launch
`2FA_V3.00.00.py`

Major rewrite. Added QR code export, OTP verification, clipboard copy, solid
input validation on all numeric fields, and defaults on every prompt. First
version to use typed exceptions (`TwoFAError` hierarchy). Later releases walked
back features that didn't work reliably on Android/Termux (QR, clipboard,
verification).

---

### V3.01.01 — Advanced Error Handling
`2FA_V3.01.01.py`

Introduced the full custom exception hierarchy:
- `TwoFAError` — base class
- `InvalidSecretError` — bad base32 caught before pyotp sees it
- `OTPBuildError` — typed TOTP/HOTP construction failures
- `QRSaveError`, `ClipboardError`

Multi-line error messages aligned correctly. `build_totp`/`build_hotp`
simplified to return URI only.

---

### V3.05.09 — Single File
`2FA_V3.05.09.py`

The QR engine (originally a separate `qrcli.py`) was merged directly into the
main script. One file, no dependencies on a second script. Unicode block
rendering for terminal QR display — no Pillow required.

---

### V3.06.10 — Public API / Headless Mode
`2FA_V3.06.10.py`

The file became importable as a library. Added:
- `OTPResult` and `QRResult` dataclasses
- `create_totp()`, `create_hotp()`, `render_qr()`, `generate_secret()` — all
  pure functions with no terminal I/O
- `__all__` defining the stable public surface
- `colorama` made fully optional (stubs to empty strings when absent)
- Dependency gate no longer calls `sys.exit()` at module level

3rd-party usage:
```python
import importlib.util
spec = importlib.util.spec_from_file_location("twofa", "2FA_V3.06.10.py")
twofa = importlib.util.module_from_spec(spec)
spec.loader.exec_module(twofa)

result = twofa.create_totp(issuer="GitHub", account="user@example.com")
print(result.secret)
print(result.uri)

qr = twofa.render_qr(result.uri)
print(qr.rendered)
```

---

### V3.06.15 — QR Rendering Fix
`2FA_V3.06.15.py`

Switched from double-wide block rendering (`██` per module) to half-block
rendering (`▀` `▄` `█` space). The old approach produced a tall rectangle —
the new one produces a proper square, which is what scanners require.

Each character now represents one module. A 37×37 QR renders as 37 chars wide
× 20 lines tall instead of 74×37.

---

### V3.06.16 — Current
`2FA_V3.06.16.py`

OTP verification removed — the feature never worked reliably. Menu renumbered.
This is the recommended version.

**Public API:**
```python
generate_secret()                          → str
validate_secret(secret)                    → None  # raises InvalidSecretError
create_totp(issuer, account, ...)          → OTPResult
create_hotp(issuer, account, ...)          → OTPResult
render_qr(uri, invert, max_modules)        → QRResult
```

**OTPResult fields:** `secret`, `uri`, `issuer`, `account`, `otp_type`,
`algorithm`, `digits`, `period`, `counter`

**QRResult fields:** `rendered`, `modules`, `terminal_width`, `version`,
`ec_level`

---

## Exceptions

All public functions raise subclasses of `TwoFAError`:

| Exception | When |
|---|---|
| `TwoFAError` | Base class — catch this to handle any failure |
| `InvalidSecretError` | Bad base32 secret |
| `OTPBuildError` | pyotp construction failed |
| `QRError` | QR generation or rendering failed |

---

## Notes

- SHA1 is the default algorithm and the only one with universal authenticator
  app support. SHA256/SHA512 are available for compliance requirements only.
- TOTP (time-based) is recommended for most use cases.
- HOTP (counter-based) suits hardware tokens where clock sync isn't possible.
- Keys are generated locally — nothing is sent or stored anywhere.
- The QR module cap defaults to 45 modules (45 chars wide). Codes larger than
  this are difficult to scan in a Termux portrait window. Shorten the issuer
  or account name to reduce URI length if you hit this limit.
