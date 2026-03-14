"""
2FA Generator — V3.06.16
Author : MrBros (https://mrbros1509.bio.link)

═══════════════════════════════════════════════════
  HEADLESS / 3RD-PARTY USAGE
═══════════════════════════════════════════════════

  This file is both a standalone interactive tool AND
  a fully importable library. All core features are
  accessible without touching the CLI.

  Quick start:

      import importlib.util, sys
      spec = importlib.util.spec_from_file_location("twofa", "/path/to/2FA_V3.06.12.py")
      twofa = importlib.util.module_from_spec(spec)
      spec.loader.exec_module(twofa)

      # Generate a TOTP setup
      result = twofa.create_totp(issuer="GitHub", account="user@example.com")
      print(result.secret)   # → base32 secret key
      print(result.uri)      # → otpauth://totp/... URI

      # Render QR to terminal string
      qr = twofa.render_qr(result.uri)
      print(qr.rendered)     # → Unicode block art — just print this

  Public API (see __all__ for the full list):
      generate_secret()              → str
      validate_secret(secret)        → None  (raises InvalidSecretError)
      create_totp(...)               → OTPResult
      create_hotp(...)               → OTPResult
      render_qr(uri, ...)            → QRResult

  All public functions are pure — no terminal I/O, no sys.exit().
  They raise typed TwoFAError subclasses on failure.

═══════════════════════════════════════════════════
  CHANGELOG
═══════════════════════════════════════════════════

  V3.06.16 — OTP verification removed
    - verify_totp() and verify_hotp() removed from public API
    - _verify_otp_interactive() and menu option [3] removed
    ! Feature never worked reliably — may revisit in a future version

  V3.06.15 — QR rendering fix
    ~ Switched from double-wide block (██) to half-block rendering
      (▀ ▄ █ space) — packs two module rows per terminal line so the
      QR is square instead of a tall rectangle. Scanners require square.

  V3.06.14 — Code revision
    ~ qrcode now shown in the missing dependency message alongside pyotp
      and colorama — one combined install command for everything

  V3.06.13 — Code revision
    ~ qrcode added to dependency checker — listed as optional so missing
      it shows a install hint but does not block startup

  V3.06.12 — Bug hunt fixes
    ~ NameError: create_totp/create_hotp now guard _PYOTP_AVAILABLE before
      calling pyotp — previously crashed when existing secret provided + no pyotp
    ~ NameError: verify_totp/verify_hotp now guard _PYOTP_AVAILABLE
    ~ SyntaxError on Python <3.12: nested quotes in f-string in _show_info
      replaced with pre-built strings — fixes crash on Termux (Python 3.11)
    ~ ERROR_CORRECT_L import moved inside render_qr() — no longer a module-level
      landmine when qrcode is absent
    ~ Dead function _can_import_silently removed
    ~ Docstring filename corrected

  V3.06.11 — Bug fix
    ~ pyotp import no longer raises at module level — now uses the same
      try/except + flag pattern as qrcode/colorama so _check_cli_dependencies()
      always runs and shows the friendly install message instead of a traceback

  V3.06.10 — 3rd-party API + headless mode
    + OTPResult dataclass — one object carries everything from a generation call
    + QRResult dataclass  — rendered QR string + metadata in one object
    + create_totp() / create_hotp() — clean public generation functions
    + render_qr()  — public QR renderer, returns QRResult (no side effects)
    + __all__ — explicit public surface so importers know what's stable
    ~ Dependency gate now raises ImportError on import instead of sys.exit()
      so importing this file as a library never kills the host process
    ~ colorama made optional — headless callers don't need terminal colours;
      colour codes silently become empty strings when colorama is absent
    ~ clamp_digits() no longer prints warnings — returns clamped value cleanly
      so API callers don't get unexpected terminal output
    ~ Core functions fully decoupled from terminal I/O

  V3.05.09 — QR engine merged into single file
    ~ qrcli.py integrated directly — no second file needed
    ~ Subprocess + JSON round-trip replaced with direct function calls

  V3.04.08 — QR code display (via qrcli.py)
    + QR code shown in terminal after key generation (Y/N prompt)
    + Dedicated QR screen: clears display, shows resolution info + code
    + Size guard: refuses QR codes too wide for terminal windows

  V3.03.07 — Clipboard removed
    - Clipboard functionality removed (pyperclip)
    ! Does not work on Android/Termux

  V3.03.06 — QR code removed
    - QR code export removed (qrcode + Pillow)
    ! Could not get working on Android/Termux — fixed in V3.04.08 via segno-free
      Unicode block rendering

  V3.01.04 — Code revision
    ~ print_error/warning/success handle multi-line messages cleanly

  V3.01.01 — Advanced error handling
    + Custom exception hierarchy (TwoFAError and subclasses)
    + Secret validation before pyotp sees it
    + Typed error handling throughout

  V3.00.00 — Initial V3 release
    + QR code export, OTP verification, clipboard copy
    + Solid input validation, defaults on all prompts

  FUTURE (not yet implemented):
    - segno: more modern QR library — zero image deps, better terminal output.
      Worth swapping if qrcode causes issues on a new platform.
    - Proper package structure (setup.py / pyproject.toml) once the API
      has stabilised across a few versions.
"""

import sys
import os
import hashlib
import binascii
import base64
from dataclasses import dataclass
from typing import Optional

# ── Version ────────────────────────────────────────────────────────────────────

VERSION = "3.06.16"

# ── Constants — exported so 3rd-party callers can reference them ───────────────

MIN_DIGITS      = 6
MAX_DIGITS      = 8
DEFAULT_DIGITS  = 6
DEFAULT_PERIOD  = 30    # seconds — the near-universal TOTP refresh window
DEFAULT_COUNTER = 0

# SHA1 is the only algorithm with universal authenticator app support.
# SHA256/SHA512 are available for compliance requirements only.
VALID_ALGORITHMS = ["SHA1", "SHA256", "SHA512"]

# Hard cap on QR matrix size.
# 45 modules = 90 chars wide — about the maximum that fits in a Termux
# portrait window without horizontal scrolling. Beyond this, the code
# becomes practically unscannable on a phone terminal.
QR_MAX_MODULES  = 45

# ── Dataclasses — the integration contract for 3rd-party callers ──────────────

@dataclass
class OTPResult:
    """
    Everything produced by a single create_totp() or create_hotp() call.
    Callers can use any field they need without parsing a URI string.
    """
    secret:    str            # Base32 secret key
    uri:       str            # Full otpauth:// provisioning URI
    issuer:    str
    account:   str
    otp_type:  str            # "totp" or "hotp"
    algorithm: str            # "SHA1" / "SHA256" / "SHA512"
    digits:    int
    period:    Optional[int]  # TOTP only — None for HOTP
    counter:   Optional[int]  # HOTP only — None for TOTP


@dataclass
class QRResult:
    """
    Everything produced by a render_qr() call.
    `rendered` is the complete Unicode block string — just print() it.
    """
    rendered:       str   # Multi-line Unicode block art — print this
    modules:        int   # QR matrix dimension (modules × modules)
    terminal_width: int   # Character width of the rendered output (modules * 2)
    version:        int   # QR version used (1–40)
    ec_level:       str   # Error correction level used


# ── Public API surface ─────────────────────────────────────────────────────────
# Everything listed here is stable and safe for 3rd-party callers to import.

__all__ = [
    # Version
    "VERSION",
    # Constants
    "MIN_DIGITS", "MAX_DIGITS", "DEFAULT_DIGITS",
    "DEFAULT_PERIOD", "DEFAULT_COUNTER",
    "VALID_ALGORITHMS", "QR_MAX_MODULES",
    # Dataclasses
    "OTPResult", "QRResult",
    # Exceptions
    "TwoFAError", "InvalidSecretError", "OTPBuildError", "QRError",
    # Core API — all pure, no terminal I/O
    "generate_secret",
    "validate_secret",
    "create_totp",
    "create_hotp",
    "render_qr",
]


# ── Dependency loading ─────────────────────────────────────────────────────────
# When imported as a library, missing deps raise ImportError so the host
# process can handle them. When run as __main__, the interactive checker
# runs instead and prints a clear install command.
#
# colorama is fully optional — when absent, colour codes become empty strings
# so all core (non-terminal) functions work without any modification.

try:
    import pyotp
    _PYOTP_AVAILABLE = True
except ImportError:
    _PYOTP_AVAILABLE = False

try:
    import qrcode
    _QRCODE_AVAILABLE = True
except ImportError:
    _QRCODE_AVAILABLE = False

try:
    from colorama import Fore, Style, init as _colorama_init
    _colorama_init(autoreset=True)
    _COLORAMA_AVAILABLE = True
except ImportError:
    # Headless callers don't need colours — stub out so nothing else breaks
    class _ColourStub:
        """Returns empty string for every attribute access."""
        def __getattr__(self, _: str) -> str:
            return ""
    Fore  = _ColourStub()   # type: ignore[assignment]
    Style = _ColourStub()   # type: ignore[assignment]
    _COLORAMA_AVAILABLE = False


# ── Custom exceptions ──────────────────────────────────────────────────────────

class TwoFAError(Exception):
    """Base class for all 2FA Generator errors. Catch this to handle any failure."""


class InvalidSecretError(TwoFAError):
    """Raised when a secret key fails base32 validation."""


class OTPBuildError(TwoFAError):
    """Raised when TOTP/HOTP object construction fails."""


class QRError(TwoFAError):
    """Raised when QR matrix generation or rendering fails."""


# ══════════════════════════════════════════════════════════════════════════════
#  PUBLIC API — pure functions, no terminal I/O, no sys.exit()
#  Safe to call from any context: CLI, web server, script, test suite.
# ══════════════════════════════════════════════════════════════════════════════

def generate_secret() -> str:
    """
    Generate a cryptographically random base32 secret key (160 bits).

    Returns:
        A 32-character base32 string suitable for TOTP/HOTP setup.

    Raises:
        TwoFAError: if pyotp is not installed.
    """
    if not _PYOTP_AVAILABLE:
        raise TwoFAError("pyotp is required.  Install with:  pip install pyotp")
    return pyotp.random_base32()


def validate_secret(secret: str) -> None:
    """
    Validate a base32 secret key.

    Checks character set, minimum length, and structural padding before
    pyotp sees it — prevents cryptic errors deep inside hashlib.

    Raises:
        InvalidSecretError: if the secret is empty, contains invalid
                            characters, is too short, or fails base32 decode.
    """
    if not secret:
        raise InvalidSecretError("Secret key cannot be empty.")

    # RFC 4648 base32: A–Z and 2–7 only (plus optional = padding)
    allowed   = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=")
    bad_chars = set(secret.upper()) - allowed
    if bad_chars:
        raise InvalidSecretError(
            f"Secret contains invalid characters: {', '.join(sorted(bad_chars))}. "
            f"Base32 uses only A–Z and 2–7."
        )

    # pyotp requires at least 16 base32 characters (80 bits minimum)
    if len(secret.replace("=", "")) < 16:
        raise InvalidSecretError(
            f"Secret is too short ({len(secret)} chars). "
            f"Minimum is 16 base32 characters."
        )

    # Attempt a real decode to catch structurally invalid padding
    try:
        padded = secret.upper() + "=" * ((-len(secret)) % 8)
        base64.b32decode(padded)
    except binascii.Error as e:
        raise InvalidSecretError(f"Secret failed base32 decode: {e}") from e


def create_totp(
    issuer:    str            = "MyApp",
    account:   str            = "user@example.com",
    algorithm: str            = "SHA1",
    digits:    int            = DEFAULT_DIGITS,
    period:    int            = DEFAULT_PERIOD,
    secret:    Optional[str]  = None,
) -> OTPResult:
    """
    Generate a complete TOTP setup.

    Args:
        issuer:    Service name shown in the authenticator app.
        account:   User identifier (typically an email address).
        algorithm: Hash algorithm — "SHA1" (default), "SHA256", or "SHA512".
                   SHA1 is the only algorithm with universal app support.
        digits:    OTP code length — 6 (default) or 8. Auto-clamped.
        period:    Code refresh interval in seconds (default: 30).
        secret:    Provide an existing secret to build a URI for it, or
                   omit to generate a new one automatically.

    Returns:
        OTPResult with secret, URI, and all parameters.

    Raises:
        InvalidSecretError: if a provided secret fails validation.
        OTPBuildError:      if pyotp construction fails.
    """
    digits = max(MIN_DIGITS, min(MAX_DIGITS, digits))   # clamp silently

    if not _PYOTP_AVAILABLE:
        raise TwoFAError("pyotp is required.  Install with:  pip install pyotp")

    if secret is None:
        secret = generate_secret()
    else:
        validate_secret(secret)

    try:
        digest = getattr(hashlib, algorithm.lower())
        totp   = pyotp.TOTP(
            secret,
            issuer   = issuer,
            digest   = digest,
            digits   = digits,
            interval = period,
        )
        uri = totp.provisioning_uri(name=account, issuer_name=issuer)
    except AttributeError as e:
        raise OTPBuildError(f"Unknown algorithm '{algorithm}': {e}") from e
    except ValueError as e:
        raise OTPBuildError(f"Invalid TOTP parameter: {e}") from e

    return OTPResult(
        secret    = secret,
        uri       = uri,
        issuer    = issuer,
        account   = account,
        otp_type  = "totp",
        algorithm = algorithm,
        digits    = digits,
        period    = period,
        counter   = None,
    )


def create_hotp(
    issuer:    str            = "MyApp",
    account:   str            = "user@example.com",
    algorithm: str            = "SHA1",
    digits:    int            = DEFAULT_DIGITS,
    counter:   int            = DEFAULT_COUNTER,
    secret:    Optional[str]  = None,
) -> OTPResult:
    """
    Generate a complete HOTP setup.

    Args:
        issuer:    Service name shown in the authenticator app.
        account:   User identifier.
        algorithm: Hash algorithm — "SHA1" (default), "SHA256", or "SHA512".
        digits:    OTP code length — 6 or 8. Auto-clamped.
        counter:   Initial counter value (default: 0).
        secret:    Provide an existing secret, or omit to generate one.

    Returns:
        OTPResult with secret, URI, and all parameters.

    Raises:
        InvalidSecretError: if a provided secret fails validation.
        OTPBuildError:      if pyotp construction fails.
    """
    digits = max(MIN_DIGITS, min(MAX_DIGITS, digits))

    if not _PYOTP_AVAILABLE:
        raise TwoFAError("pyotp is required.  Install with:  pip install pyotp")

    if secret is None:
        secret = generate_secret()
    else:
        validate_secret(secret)

    try:
        digest = getattr(hashlib, algorithm.lower())
        hotp   = pyotp.HOTP(
            secret,
            issuer = issuer,
            digest = digest,
            digits = digits,
        )
        uri = hotp.provisioning_uri(
            name          = account,
            issuer_name   = issuer,
            initial_count = counter,
        )
    except AttributeError as e:
        raise OTPBuildError(f"Unknown algorithm '{algorithm}': {e}") from e
    except ValueError as e:
        raise OTPBuildError(f"Invalid HOTP parameter: {e}") from e

    return OTPResult(
        secret    = secret,
        uri       = uri,
        issuer    = issuer,
        account   = account,
        otp_type  = "hotp",
        algorithm = algorithm,
        digits    = digits,
        period    = None,
        counter   = counter,
    )


def render_qr(
    uri:         str,
    invert:      bool = True,
    max_modules: int  = QR_MAX_MODULES,
) -> QRResult:
    """
    Render an otpauth URI as a Unicode block QR code string.

    The returned QRResult.rendered is a multi-line string —
    just print() it to display the QR code in the terminal.

    Args:
        uri:         The otpauth:// URI to encode (from OTPResult.uri).
        invert:      True = dark-on-light rendering (correct for dark terminal
                     backgrounds, which is the standard on phones). Default: True.
        max_modules: Refuse codes wider than this module count. Default: 45.
                     Each module = 2 terminal chars, so 45 → 90 chars wide.

    Returns:
        QRResult with rendered string and QR metadata.

    Raises:
        QRError: if qrcode is not installed, the URI is empty,
                 the resulting QR exceeds max_modules, or encoding fails.
    """
    if not _QRCODE_AVAILABLE:
        raise QRError(
            "qrcode is not installed.  Install with:  pip install qrcode"
        )

    if not uri or not uri.strip():
        raise QRError("URI cannot be empty.")

    # Import here — only reachable when _QRCODE_AVAILABLE is True
    from qrcode.constants import ERROR_CORRECT_L

    qr = qrcode.QRCode(
        version          = None,         # auto-select smallest fitting version
        error_correction = ERROR_CORRECT_L,
        box_size         = 10,
        border           = 1,            # 1-module quiet zone — saves screen space
    )

    try:
        qr.add_data(uri)
        qr.make(fit=True)
    except Exception as e:
        raise QRError(f"QR encoding failed: {e}") from e

    # Version is only resolved after make() — check size now
    actual_modules = qr.version * 4 + 17
    if actual_modules > max_modules:
        raise QRError(
            f"QR would be {actual_modules}\u00d7{actual_modules} modules "
            f"({actual_modules * 2} chars wide) \u2014 exceeds the "
            f"{max_modules}-module limit.\n"
            f"Shorten your issuer or account name to reduce URI length."
        )

    # Half-block rendering — packs two module rows into one terminal line.
    #
    # Terminal characters are ~2x taller than wide, so the naive approach of
    # rendering each module as two chars (██) produces a tall rectangle that
    # scanners reject. Half-blocks fix the aspect ratio:
    #
    #   top dark,  bottom dark  → █  (U+2588 FULL BLOCK)
    #   top dark,  bottom light → ▀  (U+2580 UPPER HALF BLOCK)
    #   top light, bottom dark  → ▄  (U+2584 LOWER HALF BLOCK)
    #   top light, bottom light → (space)
    #
    # Each character cell now represents one module square — correct 1:1 ratio.
    _BOTH_DARK   = "\u2588"   # █
    _TOP_DARK    = "\u2580"   # ▀
    _BOT_DARK    = "\u2584"   # ▄
    _BOTH_LIGHT  = " "

    matrix = qr.get_matrix()    # 2D list of booleans: True = dark module
    lines  = []

    # Step two rows at a time — if the module count is odd, pad a light row
    rows = list(matrix)
    if len(rows) % 2 != 0:
        rows.append([False] * len(rows[0]))

    for i in range(0, len(rows), 2):
        top_row = rows[i]
        bot_row = rows[i + 1]
        line = ""
        for top, bot in zip(top_row, bot_row):
            # Apply invert to both cells before choosing the character
            t = top ^ invert
            b = bot ^ invert
            if t and b:
                line += _BOTH_DARK
            elif t and not b:
                line += _TOP_DARK
            elif not t and b:
                line += _BOT_DARK
            else:
                line += _BOTH_LIGHT
        lines.append(line)

    rendered = "\n".join(lines)

    return QRResult(
        rendered       = rendered,
        modules        = actual_modules,
        terminal_width = actual_modules,   # each module = 1 char wide now
        version        = qr.version,
        ec_level       = "L",
    )




# ══════════════════════════════════════════════════════════════════════════════
#  INTERACTIVE CLI — everything below is terminal-only code.
#  None of this runs when the file is imported as a library.
# ══════════════════════════════════════════════════════════════════════════════

def _check_cli_dependencies() -> None:
    """
    Interactive dependency check for CLI mode only.

    Required packages (pyotp, colorama) — missing ones print a combined
    install command and exit. The program cannot run without these.

    Optional packages (qrcode) — missing ones print a non-fatal hint
    and continue. Features that need them are silently disabled.
    """
    # Use the flags set at import time — avoids a second import attempt
    required_missing = []
    if not _PYOTP_AVAILABLE:    required_missing.append("pyotp")
    if not _COLORAMA_AVAILABLE: required_missing.append("colorama")

    optional_missing = []
    if not _QRCODE_AVAILABLE:   optional_missing.append("qrcode")

    # If anything is missing at all — show one combined message
    all_missing = required_missing + optional_missing
    if all_missing:
        install_cmd = "pip install " + " ".join(all_missing)
        lines = []
        for pkg in required_missing:
            lines.append(f"  \u2022 {pkg}  \u2014 required")
        for pkg in optional_missing:
            if pkg == "qrcode":
                lines.append(f"  \u2022 {pkg}  \u2014 optional (QR code display)")

        message = (
            "Missing dependencies:\n\n"
            + "\n".join(lines)
            + f"\n\nInstall with:\n  {install_cmd}"
        )
        try:
            import tkinter as tk
            from tkinter import messagebox
            root = tk.Tk()
            root.withdraw()
            messagebox.showinfo("2FA Generator \u2014 Dependency Check", message)
            root.destroy()
        except ImportError:
            print("\n" + "=" * 50)
            print(message)
            print("=" * 50)

    # Only block startup for required packages
    if required_missing:
        sys.exit(1)



# ── Terminal helpers ───────────────────────────────────────────────────────────

def _clear_screen() -> None:
    os.system("cls" if os.name == "nt" else "clear")


def _pause(msg: str = "Press Enter to continue...") -> None:
    input(f"\n{Fore.YELLOW}{msg}")


def _banner(title: str) -> None:
    print(f"\n{Fore.CYAN}=== {title} ===")


def _print_prefixed(color: str, symbol: str, msg: str) -> None:
    """
    Print a prefixed status line. Multi-line messages are indented so
    every line aligns under the first — not left-flushed to the terminal edge.
    """
    prefix = f"{color}  {symbol}  "
    indent = " " * (len(symbol) + 4)
    lines  = msg.splitlines()
    print(prefix + lines[0])
    for line in lines[1:]:
        print(f"{color}{indent}{line}")


def _print_error(msg: str) -> None:
    _print_prefixed(Fore.RED, "\u2718", msg)


def _print_warning(msg: str) -> None:
    _print_prefixed(Fore.YELLOW, "\u26a0", msg)


def _print_success(msg: str) -> None:
    _print_prefixed(Fore.GREEN, "\u2714", msg)


# ── CLI input helpers ──────────────────────────────────────────────────────────

def _prompt_int(label: str, default: int, min_val: Optional[int] = None) -> int:
    """Prompt for an integer, looping until valid input is received."""
    while True:
        raw = input(
            f"{Fore.YELLOW}{label} (default {default}): {Style.RESET_ALL}"
        ).strip()
        if not raw:
            return default
        try:
            value = int(raw)
            if min_val is not None and value < min_val:
                _print_error(f"Value must be \u2265 {min_val}. Try again.")
                continue
            return value
        except ValueError:
            _print_error("Not a valid number. Try again.")


def _prompt_digits() -> int:
    """Prompt for OTP digit count with clamping applied on the result."""
    while True:
        raw = input(
            f"{Fore.YELLOW}Digits [{MIN_DIGITS}\u2013{MAX_DIGITS}] "
            f"(default {DEFAULT_DIGITS}): {Style.RESET_ALL}"
        ).strip()
        if not raw:
            return DEFAULT_DIGITS
        try:
            value = int(raw)
            clamped = max(MIN_DIGITS, min(MAX_DIGITS, value))
            if clamped != value:
                _print_warning(
                    f"Value outside {MIN_DIGITS}\u2013{MAX_DIGITS} "
                    f"\u2014 using {clamped}"
                )
            return clamped
        except ValueError:
            _print_error(f"Enter a number between {MIN_DIGITS} and {MAX_DIGITS}.")


def _prompt_algorithm() -> str:
    """Present the algorithm menu and return the chosen name."""
    print(f"\n{Fore.CYAN}Algorithm:")
    for i, algo in enumerate(VALID_ALGORITHMS, 1):
        tag = "  (default)" if algo == "SHA1" else ""
        print(f"  {Fore.GREEN}[{i}] {algo}{tag}")

    raw = input(
        f"{Fore.YELLOW}Select (1\u2013{len(VALID_ALGORITHMS)}, default 1): "
        f"{Style.RESET_ALL}"
    ).strip()

    if raw in ("1", "2", "3"):
        return VALID_ALGORITHMS[int(raw) - 1]

    _print_warning("Unrecognised selection \u2014 defaulting to SHA1.")
    return "SHA1"


def _pick_otp_type() -> Optional[str]:
    """Shared TOTP / HOTP picker used by both generator flows."""
    print(f"\n{Fore.GREEN}[1] Time-based (TOTP)")
    print(f"{Fore.GREEN}[2] Counter-based (HOTP)")
    print(f"{Fore.RED}[0] Back")
    choice = input(f"\n{Fore.YELLOW}Choose type: {Style.RESET_ALL}").strip()

    if choice == "0":
        return None
    if choice not in ("1", "2"):
        _print_error("Invalid choice.")
        _pause()
        return None
    return choice


# ── QR display screen ──────────────────────────────────────────────────────────

def _show_qr_screen(uri: str, secret: str) -> None:
    """
    Dedicated QR display screen.

    Flow: clear → size info → QR code → Press Enter → redisplay result screen.
    Showing module count and char width gives a concrete terminal resize target.
    """
    try:
        qr_result = render_qr(uri, invert=True)
    except QRError as e:
        _print_error(str(e))
        return

    _clear_screen()
    _banner("QR Code")

    # Info line — tells the user how wide to drag the terminal window
    print(
        f"{Fore.CYAN}  Size    : {Fore.WHITE}"
        f"{qr_result.modules}\u00d7{qr_result.modules} modules  "
        f"({Fore.YELLOW}{qr_result.terminal_width} chars wide  "
        f"\u2014 half-block rendering{Fore.WHITE})"
    )
    print(
        f"{Fore.CYAN}  EC      : {Fore.WHITE}{qr_result.ec_level}  "
        f"  {Fore.CYAN}Version : {Fore.WHITE}{qr_result.version}"
    )
    print(
        f"{Fore.WHITE}  Resize your terminal until the QR fills cleanly, "
        f"then scan.\n"
    )

    print(qr_result.rendered)

    # Secret stays visible below the QR as a manual-entry fallback
    print(f"\n{Fore.MAGENTA}  Secret : {Style.BRIGHT}{secret}")
    _pause("Press Enter to return...")

    # Restore the result screen so nothing is lost after closing QR view
    _clear_screen()
    _banner("2FA Key Generated")
    print(f"{Fore.MAGENTA}Secret Key : {Style.BRIGHT}{secret}")
    print(f"{Fore.YELLOW}OTP URI    : {Style.BRIGHT}{uri}")


def _show_result(result: OTPResult) -> None:
    """Display generated credentials and offer QR code display."""
    _banner("2FA Key Generated")
    print(f"{Fore.MAGENTA}Secret Key : {Style.BRIGHT}{result.secret}")
    print(f"{Fore.YELLOW}OTP URI    : {Style.BRIGHT}{result.uri}")
    print()

    if _QRCODE_AVAILABLE:
        choice = input(
            f"{Fore.YELLOW}Show QR code? [y/N]: {Style.RESET_ALL}"
        ).strip().lower()
        if choice == "y":
            _show_qr_screen(result.uri, result.secret)
    else:
        _print_warning(
            "QR display unavailable.  Install qrcode:  pip install qrcode"
        )



# ── CLI generator flows ────────────────────────────────────────────────────────

def _basic_generator() -> None:
    """
    Quick generation with sensible defaults.
    Exposes issuer, account, and digit count only.
    """
    _clear_screen()
    _banner("Basic 2FA Generation")
    choice = _pick_otp_type()
    if choice is None:
        return

    _clear_screen()
    issuer  = input(
        f"{Fore.YELLOW}Issuer  (default: MyApp): {Style.RESET_ALL}"
    ).strip() or "MyApp"
    account = input(
        f"{Fore.YELLOW}Account (default: user@example.com): {Style.RESET_ALL}"
    ).strip() or "user@example.com"
    digits  = _prompt_digits()

    try:
        if choice == "1":
            result = create_totp(issuer=issuer, account=account, digits=digits)
        else:
            result = create_hotp(issuer=issuer, account=account, digits=digits)
        _show_result(result)
    except (InvalidSecretError, OTPBuildError) as e:
        _print_error(f"Generation failed: {e}")

    _pause()


def _advanced_generator() -> None:
    """
    Full parameter control — exposes every configurable OTP option.
    Intended for non-default setups: custom algorithm, 8-digit codes,
    non-standard TOTP period, or a specific HOTP starting counter.
    """
    _clear_screen()
    _banner("Advanced 2FA Generation")
    choice = _pick_otp_type()
    if choice is None:
        return

    _clear_screen()
    print(f"{Fore.BLUE}Enter Parameters:\n")
    issuer    = input(
        f"{Fore.YELLOW}Issuer  (e.g. MyApp): {Style.RESET_ALL}"
    ).strip() or "MyApp"
    account   = input(
        f"{Fore.YELLOW}Account (e.g. user@email.com): {Style.RESET_ALL}"
    ).strip() or "user@example.com"
    algorithm = _prompt_algorithm()
    digits    = _prompt_digits()

    try:
        if choice == "1":
            period = _prompt_int(
                "TOTP period (seconds)", default=DEFAULT_PERIOD, min_val=1
            )
            result = create_totp(
                issuer=issuer, account=account,
                algorithm=algorithm, digits=digits, period=period,
            )
        else:
            counter = _prompt_int(
                "Initial HOTP counter", default=DEFAULT_COUNTER, min_val=0
            )
            result = create_hotp(
                issuer=issuer, account=account,
                algorithm=algorithm, digits=digits, counter=counter,
            )
        _show_result(result)
    except (InvalidSecretError, OTPBuildError) as e:
        _print_error(f"Generation failed: {e}")

    _pause()


# ── Info screen ────────────────────────────────────────────────────────────────

def _show_info() -> None:
    _clear_screen()
    _banner("Program Information")
    print(f"{Fore.MAGENTA}Version: {VERSION}")
    major, feature, revision = VERSION.split(".")
    # Pre-build status strings — avoids nested quotes inside an f-string,
    # which causes SyntaxError on Python < 3.12 (Termux ships Python 3.11).
    if _COLORAMA_AVAILABLE:
        colorama_status = Fore.GREEN + "available"
    else:
        colorama_status = Fore.RED + "not installed (pip install colorama)"

    if _QRCODE_AVAILABLE:
        qr_status = Fore.GREEN + "available"
    else:
        qr_status = Fore.RED + "not installed (pip install qrcode)"

    print(f"""
{Fore.BLUE}\u250c\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2510
{Fore.BLUE}\u2502  {Fore.CYAN}{major}  \u2192 Major Version       {Fore.BLUE}\u2502
{Fore.BLUE}\u2502  {Fore.GREEN}{feature} \u2192 Feature Set         {Fore.BLUE}\u2502
{Fore.BLUE}\u2502  {Fore.YELLOW}{revision} \u2192 Code Revision       {Fore.BLUE}\u2502
{Fore.BLUE}\u2514\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2518

{Fore.CYAN}=== RUNTIME STATUS ==={Fore.WHITE}
  colorama : {colorama_status}
  qrcode   : {qr_status}

{Fore.CYAN}=== INSTRUCTION MANUAL ===

{Fore.BLUE}[Basic Mode]
{Fore.WHITE}  Fast generation using SHA1 / 30s defaults.
  Prompts for issuer, account, and digit count only.

{Fore.BLUE}[Advanced Mode]
{Fore.WHITE}  Full control: issuer, account, algorithm, digits, period / counter.


{Fore.BLUE}[3rd-Party / Headless Usage]
{Fore.WHITE}  Import this file via importlib and call the public API directly.
  See the module docstring at the top of the file for examples.
  Public functions: create_totp, create_hotp, render_qr, generate_secret

{Fore.CYAN}=== TECHNICAL GUIDE ===

{Fore.BLUE}[OTP Auth URI Format]
{Fore.YELLOW}  otpauth://TYPE/ISSUER:ACCOUNT?PARAMETERS
{Fore.WHITE}  TYPE       \u2192 totp / hotp
{Fore.WHITE}  ISSUER     \u2192 your service name  (e.g. "GitHub")
{Fore.WHITE}  PARAMETERS \u2192 secret, digits, algorithm, period / counter

{Fore.BLUE}[Key Components]
{Fore.GREEN}  1. Secret    {Fore.WHITE}Base32-encoded 160-bit random value
{Fore.GREEN}  2. Algorithm {Fore.WHITE}SHA1 / SHA256 / SHA512
{Fore.GREEN}  3. Digits    {Fore.WHITE}6\u20138 (auto-clamped)
{Fore.GREEN}  4. Period    {Fore.WHITE}TOTP refresh window \u2014 30s standard
{Fore.GREEN}  5. Counter   {Fore.WHITE}HOTP increments on each use

{Fore.RED}=== SECURITY NOTES ==={Fore.WHITE}
  \u2022 Keys generated locally \u2014 nothing is sent or stored
  \u2022 Store your secret like a password (use a password manager)
  \u2022 TOTP preferred for most cases (stateless, no counter sync needed)
  \u2022 HOTP suits hardware tokens where clock sync isn\u2019t possible

{Fore.CYAN}Created by: MrBros
{Fore.WHITE}Visit: https://mrbros1509.bio.link""")

    _pause("Press Enter to return to main menu...")


# ── Menu & main loop ───────────────────────────────────────────────────────────

def _show_menu() -> str:
    _clear_screen()
    print(f"\n{Fore.CYAN}=== 2FA Generator  v{VERSION} ===")
    print(f"{Fore.GREEN}[1] Generate 2FA \u2014 Basic")
    print(f"{Fore.GREEN}[2] Generate 2FA \u2014 Advanced")
    print(f"{Fore.BLUE}[4] Program Info")
    print(f"{Fore.RED}[0] Exit")
    return input(f"\n{Fore.YELLOW}Select an option: {Style.RESET_ALL}").strip()


def main() -> None:
    """Interactive CLI entry point. Only runs when executed directly."""
    _check_cli_dependencies()

    while True:
        choice = _show_menu()
        try:
            if choice == "1":
                _basic_generator()
            elif choice == "2":
                _advanced_generator()
            elif choice == "4":
                _show_info()
            elif choice == "0":
                _clear_screen()
                print(f"\n{Fore.CYAN}Created by: MrBros")
                print(f"{Fore.WHITE}Visit: https://mrbros1509.bio.link")
                print(f"\n{Fore.RED}Exiting...")
                break
            else:
                _print_error("Invalid option.")
                _pause()

        except KeyboardInterrupt:
            # Ctrl+C inside a sub-menu returns gracefully to the main menu
            print(f"\n{Fore.YELLOW}  (Ctrl+C \u2014 returning to menu)")

        except TwoFAError as e:
            # Any unhandled typed error from the public API surfaces here
            _print_error(f"{type(e).__name__}: {e}")
            _pause()

        except Exception as e:
            # Last-resort — names the exception type without a raw traceback
            _print_error(f"Unexpected error ({type(e).__name__}): {e}")
            _pause()


if __name__ == "__main__":
    main()
