"""
2FA Generator — V3.01.01
Author : MrBros (https://mrbros1509.bio.link)

Changelog:
  V3.00.00 — Initial V3 release
    + QR code export, OTP verification, clipboard copy
    + Solid numeric input validation, defaults on all prompts

  V3.01.01 — Advanced error handling + code revision
    + Custom exception hierarchy (TwoFAError and subclasses)
    + Secret validation before pyotp touches it (catches bad base32 early)
    + Typed error handling in build_totp / build_hotp
    + QR save errors split by cause (permissions, disk full, bad path)
    + Clipboard errors split by cause (no daemon vs unexpected failure)
    ~ build_totp / build_hotp simplified to return URI only (callers never used the object)
    ~ Version constant drives the info screen — no more manual sync
    ~ Minor formatting consistency pass throughout

  FUTURE (not yet implemented):
    - Importable module mode: allow other scripts to call generate_secret(),
      build_totp(), and build_hotp() directly without launching the interactive
      menu. Requires separating the CLI layer from the core logic layer cleanly.
"""

import sys
import os
import hashlib
import binascii
import base64
from typing import Optional

VERSION = "3.01.01"

# ── Dependency gate ────────────────────────────────────────────────────────────
# Checked up front so the user gets one clear install command instead of a
# confusing ImportError mid-session.

REQUIRED_PACKAGES = {
    "pyotp":      "pyotp",
    "colorama":   "colorama",
    "qrcode":     "qrcode",
    "pyperclip":  "pyperclip",
}


def _can_import(module_name: str) -> bool:
    try:
        __import__(module_name)
        return True
    except ImportError:
        return False


def check_dependencies() -> list:
    return [pkg for pkg, mod in REQUIRED_PACKAGES.items() if not _can_import(mod)]


def alert_missing(missing: list) -> None:
    """Try a GUI popup first; fall back to plain terminal output."""
    install_cmd = "pip install " + " ".join(missing)
    message = (
        "Missing dependencies:\n\n"
        + "\n".join(f"  • {pkg}" for pkg in missing)
        + f"\n\nInstall with:\n  {install_cmd}"
    )
    try:
        import tkinter as tk
        from tkinter import messagebox
        root = tk.Tk()
        root.withdraw()
        messagebox.showinfo("2FA Generator — Dependency Check", message)
        root.destroy()
    except ImportError:
        # tkinter is absent in some minimal Python installs (e.g. headless Linux)
        print("\n" + "=" * 50)
        print(message)
        print("=" * 50)


missing_deps = check_dependencies()
if missing_deps:
    alert_missing(missing_deps)
    sys.exit(1)

# ── Third-party imports are safe past this point ───────────────────────────────

import pyotp
import qrcode
import pyperclip
from colorama import Fore, Style, init

init(autoreset=True)

# ── Constants ──────────────────────────────────────────────────────────────────

MIN_DIGITS      = 6
MAX_DIGITS      = 8
DEFAULT_DIGITS  = 6
DEFAULT_PERIOD  = 30   # seconds — the near-universal TOTP window
DEFAULT_COUNTER = 0

# SHA1 is the only algorithm with universal authenticator app support.
# SHA256/SHA512 are available for compliance requirements only.
VALID_ALGORITHMS = ["SHA1", "SHA256", "SHA512"]


# ── Custom exceptions ──────────────────────────────────────────────────────────
# Typed exceptions let callers catch exactly what they care about
# instead of fishing through a generic Exception blob.

class TwoFAError(Exception):
    """Base class for all 2FA Generator errors."""


class InvalidSecretError(TwoFAError):
    """Raised when a secret key fails base32 validation."""


class OTPBuildError(TwoFAError):
    """Raised when TOTP/HOTP object construction fails."""


class QRSaveError(TwoFAError):
    """Raised when a QR code cannot be written to disk."""


class ClipboardError(TwoFAError):
    """Raised when the clipboard operation fails."""


# ── Terminal helpers ───────────────────────────────────────────────────────────

def clear_screen() -> None:
    os.system("cls" if os.name == "nt" else "clear")


def pause(msg: str = "Press Enter to continue...") -> None:
    input(f"\n{Fore.YELLOW}{msg}")


def banner(title: str) -> None:
    print(f"\n{Fore.CYAN}=== {title} ===")


def print_error(msg: str) -> None:
    """Uniform error line — keeps the red-text style consistent everywhere."""
    print(f"{Fore.RED}  ✘  {msg}")


def print_warning(msg: str) -> None:
    """Uniform warning line."""
    print(f"{Fore.YELLOW}  ⚠  {msg}")


def print_success(msg: str) -> None:
    """Uniform success line."""
    print(f"{Fore.GREEN}  ✔  {msg}")


# ── Secret validation ──────────────────────────────────────────────────────────

def validate_secret(secret: str) -> None:
    """
    Validate a base32 secret before passing it to pyotp.

    pyotp's own errors on a bad secret are cryptic (binascii.Error deep
    inside hashlib). Catching it here gives the user an actionable message
    instead of a raw traceback.

    Raises:
        InvalidSecretError: if the secret is empty, too short, or not valid base32.
    """
    if not secret:
        raise InvalidSecretError("Secret key cannot be empty.")

    # RFC 4648 base32 uses A–Z and 2–7 (plus optional = padding).
    allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=")
    bad_chars = set(secret.upper()) - allowed
    if bad_chars:
        raise InvalidSecretError(
            f"Secret contains invalid characters: {', '.join(sorted(bad_chars))}. "
            f"Base32 uses only A–Z and 2–7."
        )

    # pyotp expects at least 16 base32 characters (80 bits).
    if len(secret.replace("=", "")) < 16:
        raise InvalidSecretError(
            f"Secret is too short ({len(secret)} chars). "
            f"A valid secret needs at least 16 base32 characters."
        )

    # Final check: attempt an actual decode to catch structurally invalid padding.
    try:
        # Pad to a multiple of 8 before decoding — base32 requires it.
        padded = secret.upper() + "=" * ((-len(secret)) % 8)
        base64.b32decode(padded)
    except binascii.Error as e:
        raise InvalidSecretError(f"Secret failed base32 decode: {e}") from e


# ── Input helpers ──────────────────────────────────────────────────────────────

def clamp_digits(raw: str) -> int:
    """
    Parse and clamp a digit count into the valid range [MIN_DIGITS, MAX_DIGITS].

    Clamping with a warning is safer than rejecting outright — most authenticator
    apps silently fail to import a URI with digits outside 6–8.
    """
    value = int(raw)
    if value < MIN_DIGITS:
        print_warning(f"Digit count below {MIN_DIGITS} — using {MIN_DIGITS}")
        return MIN_DIGITS
    if value > MAX_DIGITS:
        print_warning(f"Digit count above {MAX_DIGITS} — using {MAX_DIGITS}")
        return MAX_DIGITS
    return value


def prompt_int(label: str, default: int, min_val: Optional[int] = None) -> int:
    """
    Prompt for an integer with a default fallback.
    Loops until the input is a valid integer that satisfies min_val.
    """
    while True:
        raw = input(
            f"{Fore.YELLOW}{label} (default {default}): {Style.RESET_ALL}"
        ).strip()
        if not raw:
            return default
        try:
            value = int(raw)
            if min_val is not None and value < min_val:
                print_error(f"Value must be ≥ {min_val}. Try again.")
                continue
            return value
        except ValueError:
            print_error("Not a valid number. Try again.")


def prompt_digits() -> int:
    """Prompt for OTP digit count and apply clamping on the result."""
    while True:
        raw = input(
            f"{Fore.YELLOW}Digits [{MIN_DIGITS}–{MAX_DIGITS}] "
            f"(default {DEFAULT_DIGITS}): {Style.RESET_ALL}"
        ).strip()
        if not raw:
            return DEFAULT_DIGITS
        try:
            return clamp_digits(raw)
        except ValueError:
            print_error(f"Enter a number between {MIN_DIGITS} and {MAX_DIGITS}.")


def prompt_algorithm() -> str:
    """Present the algorithm menu and return the chosen algorithm name."""
    print(f"\n{Fore.CYAN}Algorithm:")
    for i, algo in enumerate(VALID_ALGORITHMS, 1):
        tag = "  (default)" if algo == "SHA1" else ""
        print(f"  {Fore.GREEN}[{i}] {algo}{tag}")

    raw = input(
        f"{Fore.YELLOW}Select (1–{len(VALID_ALGORITHMS)}, default 1): {Style.RESET_ALL}"
    ).strip()

    if raw in ("1", "2", "3"):
        return VALID_ALGORITHMS[int(raw) - 1]

    # Any unrecognised input falls back to SHA1 — the universal default.
    print_warning("Unrecognised selection — defaulting to SHA1.")
    return "SHA1"


def pick_otp_type() -> Optional[str]:
    """Shared TOTP / HOTP type picker used by both generator flows."""
    print(f"\n{Fore.GREEN}[1] Time-based (TOTP)")
    print(f"{Fore.GREEN}[2] Counter-based (HOTP)")
    print(f"{Fore.RED}[0] Back")
    choice = input(f"\n{Fore.YELLOW}Choose type: {Style.RESET_ALL}").strip()

    if choice == "0":
        return None
    if choice not in ("1", "2"):
        print_error("Invalid choice.")
        pause()
        return None
    return choice


# ── Core OTP generation ────────────────────────────────────────────────────────

def generate_secret() -> str:
    """Produce a cryptographically random base32 secret (160 bits)."""
    return pyotp.random_base32()


def build_totp(
    secret: str,
    issuer: str,
    account: str,
    algorithm: str,
    digits: int,
    period: int,
) -> str:
    """
    Build a TOTP provisioning URI.

    Returns:
        The otpauth:// URI string ready for QR encoding or manual entry.

    Raises:
        InvalidSecretError: if the secret fails validation.
        OTPBuildError: if pyotp construction fails for any other reason.
    """
    validate_secret(secret)
    try:
        digest = getattr(hashlib, algorithm.lower())
        totp = pyotp.TOTP(
            secret,
            issuer=issuer,
            digest=digest,
            digits=digits,
            interval=period,
        )
        return totp.provisioning_uri(name=account, issuer_name=issuer)
    except (AttributeError, ValueError) as e:
        # AttributeError → algorithm name not found in hashlib
        # ValueError      → pyotp rejected a parameter value
        raise OTPBuildError(f"Failed to build TOTP: {e}") from e


def build_hotp(
    secret: str,
    issuer: str,
    account: str,
    algorithm: str,
    digits: int,
    counter: int,
) -> str:
    """
    Build an HOTP provisioning URI.

    Returns:
        The otpauth:// URI string.

    Raises:
        InvalidSecretError: if the secret fails validation.
        OTPBuildError: if pyotp construction fails for any other reason.
    """
    validate_secret(secret)
    try:
        digest = getattr(hashlib, algorithm.lower())
        hotp = pyotp.HOTP(
            secret,
            issuer=issuer,
            digest=digest,
            digits=digits,
        )
        return hotp.provisioning_uri(
            name=account, issuer_name=issuer, initial_count=counter
        )
    except (AttributeError, ValueError) as e:
        raise OTPBuildError(f"Failed to build HOTP: {e}") from e


# ── Post-generation actions ────────────────────────────────────────────────────

def save_qr_code(uri: str, filename: str = "2fa_qr.png") -> str:
    """
    Write the otpauth URI as a scannable QR code PNG.

    Most authenticator apps (Google, Authy, Microsoft, etc.) can scan this
    file directly — no manual secret entry needed.

    Returns:
        Absolute path to the saved file.

    Raises:
        QRSaveError: with a cause-specific message (permissions, disk, bad path).
    """
    try:
        img = qrcode.make(uri)
        path = os.path.abspath(filename)
        img.save(path)
        return path
    except PermissionError:
        raise QRSaveError(
            f"Permission denied writing to '{filename}'. "
            f"Try a different location or run with appropriate permissions."
        )
    except OSError as e:
        # Covers disk full (ENOSPC), invalid path characters, etc.
        raise QRSaveError(f"Could not save QR code to '{filename}': {e}") from e
    except Exception as e:
        # qrcode internal errors (e.g. unsupported image format via Pillow)
        raise QRSaveError(f"QR code generation failed: {e}") from e


def copy_to_clipboard(text: str) -> None:
    """
    Copy text to the system clipboard.

    Raises:
        ClipboardError: with a specific message depending on the failure cause.
    """
    try:
        pyperclip.copy(text)
    except pyperclip.PyperclipException:
        # Common in headless / SSH environments with no clipboard daemon running.
        raise ClipboardError(
            "No clipboard available. In headless/SSH environments, "
            "install xclip or xsel (Linux) or use a local terminal."
        )
    except Exception as e:
        raise ClipboardError(f"Clipboard operation failed: {e}") from e


def offer_qr_code(uri: str) -> None:
    """Offer to save the provisioning URI as a QR code PNG."""
    choice = input(
        f"{Fore.YELLOW}Save QR code as PNG? [y/N]: {Style.RESET_ALL}"
    ).strip().lower()
    if choice != "y":
        return

    filename = (
        input(f"{Fore.YELLOW}Filename (default: 2fa_qr.png): {Style.RESET_ALL}")
        .strip()
        or "2fa_qr.png"
    )

    try:
        path = save_qr_code(uri, filename)
        print_success(f"Saved → {path}")
    except QRSaveError as e:
        print_error(str(e))


def offer_clipboard(secret: str) -> None:
    """Offer to copy the secret key to the system clipboard."""
    choice = input(
        f"{Fore.YELLOW}Copy secret to clipboard? [y/N]: {Style.RESET_ALL}"
    ).strip().lower()
    if choice != "y":
        return

    try:
        copy_to_clipboard(secret)
        print_success("Copied to clipboard.")
    except ClipboardError as e:
        print_error(str(e))


def show_result(secret: str, uri: str) -> None:
    """Display generated credentials then offer optional follow-up actions."""
    banner("2FA Key Generated")
    print(f"{Fore.MAGENTA}Secret Key : {Style.BRIGHT}{secret}")
    print(f"{Fore.YELLOW}OTP URI    : {Style.BRIGHT}{uri}")
    print()
    offer_qr_code(uri)
    offer_clipboard(secret)


# ── OTP Verification ───────────────────────────────────────────────────────────

def verify_otp() -> None:
    """
    Verify a live OTP code against a known secret.

    Use case: after importing a secret into an authenticator app, confirm the
    code matches here before relying on it for a live service. Prevents lockout
    from a silent import failure.
    """
    clear_screen()
    banner("OTP Verification")
    print(
        f"{Fore.WHITE}Paste your secret key and enter the code your "
        f"authenticator shows to confirm they match.\n"
    )

    secret = input(
        f"{Fore.YELLOW}Secret key: {Style.RESET_ALL}"
    ).strip().upper()

    # Validate the secret before doing anything else — gives a clear error
    # instead of a cryptic binascii.Error from deep inside pyotp.
    try:
        validate_secret(secret)
    except InvalidSecretError as e:
        print_error(str(e))
        pause()
        return

    otp_type = (
        input(f"{Fore.YELLOW}Type — [T]OTP or [H]OTP (default T): {Style.RESET_ALL}")
        .strip()
        .upper()
        or "T"
    )

    code = input(f"{Fore.YELLOW}Code from your app: {Style.RESET_ALL}").strip()
    if not code:
        print_error("No code entered.")
        pause()
        return

    try:
        if otp_type == "H":
            counter = prompt_int("Counter value", default=0, min_val=0)
            hotp = pyotp.HOTP(secret)
            is_valid = hotp.verify(code, counter)
        else:
            totp = pyotp.TOTP(secret)
            # valid_window=1 allows ±30 s of clock drift — the same tolerance
            # that authenticator apps themselves apply.
            is_valid = totp.verify(code, valid_window=1)

        if is_valid:
            print_success("Code is VALID.")
        else:
            print(f"\n{Fore.RED}  ✘  Code is INVALID.")
            if otp_type != "H":
                print_warning(
                    "TOTP codes are time-sensitive. "
                    "Check your device clock is correctly synced."
                )

    except InvalidSecretError as e:
        # validate_secret already ran above, but pyotp may surface edge cases it missed.
        print_error(f"Invalid secret: {e}")
        print_warning("Secret must be valid base32 — characters A–Z and 2–7 only.")

    except Exception as e:
        # Catch-all for unexpected pyotp / hashlib internals.
        print_error(f"Verification failed ({type(e).__name__}): {e}")

    pause()


# ── Generator flows ────────────────────────────────────────────────────────────

def basic_generator() -> None:
    """
    Quick generation with sensible defaults.

    Exposes issuer, account, and digit count. Skips algorithm and period
    since those settings rarely need changing for everyday use cases.
    """
    clear_screen()
    banner("Basic 2FA Generation")
    choice = pick_otp_type()
    if choice is None:
        return

    clear_screen()
    issuer  = input(f"{Fore.YELLOW}Issuer  (default: MyApp): {Style.RESET_ALL}").strip() or "MyApp"
    account = input(f"{Fore.YELLOW}Account (default: user@example.com): {Style.RESET_ALL}").strip() or "user@example.com"
    digits  = prompt_digits()

    try:
        secret = generate_secret()
        if choice == "1":
            uri = build_totp(secret, issuer, account, "SHA1", digits, DEFAULT_PERIOD)
        else:
            uri = build_hotp(secret, issuer, account, "SHA1", digits, DEFAULT_COUNTER)
        show_result(secret, uri)
    except (InvalidSecretError, OTPBuildError) as e:
        # These should not be reachable in basic mode (secret is generated internally)
        # but we handle them explicitly in case of a pyotp regression.
        print_error(f"Generation failed: {e}")

    pause()


def advanced_generator() -> None:
    """
    Full parameter control — exposes every configurable OTP option.

    Use this for services with non-standard requirements: SHA256 algorithm,
    8-digit codes, unusual TOTP periods, or a specific HOTP starting counter.
    """
    clear_screen()
    banner("Advanced 2FA Generation")
    choice = pick_otp_type()
    if choice is None:
        return

    clear_screen()
    print(f"{Fore.BLUE}Enter Parameters:\n")
    issuer    = input(f"{Fore.YELLOW}Issuer  (e.g. MyApp): {Style.RESET_ALL}").strip() or "MyApp"
    account   = input(f"{Fore.YELLOW}Account (e.g. user@email.com): {Style.RESET_ALL}").strip() or "user@example.com"
    algorithm = prompt_algorithm()
    digits    = prompt_digits()

    try:
        secret = generate_secret()
        if choice == "1":
            period = prompt_int("TOTP period (seconds)", default=DEFAULT_PERIOD, min_val=1)
            uri = build_totp(secret, issuer, account, algorithm, digits, period)
        else:
            counter = prompt_int("Initial HOTP counter", default=DEFAULT_COUNTER, min_val=0)
            uri = build_hotp(secret, issuer, account, algorithm, digits, counter)
        show_result(secret, uri)
    except (InvalidSecretError, OTPBuildError) as e:
        print_error(f"Generation failed: {e}")

    pause()


# ── Info screen ────────────────────────────────────────────────────────────────

def show_info() -> None:
    clear_screen()
    banner("Program Information")
    print(f"{Fore.MAGENTA}Version: {VERSION}")
    # Parse version segments for the version box display
    major, feature, revision = VERSION.split(".")
    print(f"""
{Fore.BLUE}┌───────────────────────────┐
{Fore.BLUE}│  {Fore.CYAN}{major}  → Major Version       {Fore.BLUE}│
{Fore.BLUE}│  {Fore.GREEN}{feature} → Feature Set         {Fore.BLUE}│
{Fore.BLUE}│  {Fore.YELLOW}{revision} → Code Revision       {Fore.BLUE}│
{Fore.BLUE}└───────────────────────────┘

{Fore.CYAN}=== WHAT'S NEW IN V3.01 ==={Fore.WHITE}
  • Advanced error handling — typed exceptions with cause-specific messages
  • Secret validation — bad base32 caught before pyotp sees it
  • QR / clipboard errors explained by cause, not just reported

{Fore.CYAN}=== INSTRUCTION MANUAL ===

{Fore.BLUE}[Basic Mode]
{Fore.WHITE}  Fast generation using SHA1 / 30s period (universal defaults).
  Prompts for issuer, account, and digit count only.

{Fore.BLUE}[Advanced Mode]
{Fore.WHITE}  Full control: issuer, account, algorithm, digits, period / counter.
  Use for services with non-standard OTP requirements.

{Fore.BLUE}[Verify OTP]
{Fore.WHITE}  Paste a secret and enter the current code from your authenticator.
  Confirms the key was imported correctly before you rely on it.

{Fore.CYAN}=== TECHNICAL GUIDE ===

{Fore.BLUE}[OTP Auth URI Format]
{Fore.YELLOW}  otpauth://TYPE/ISSUER:ACCOUNT?PARAMETERS
{Fore.WHITE}  TYPE       → totp / hotp
{Fore.WHITE}  ISSUER     → your service name  (e.g. "GitHub")
{Fore.WHITE}  PARAMETERS → secret, digits, algorithm, period / counter

{Fore.BLUE}[Key Components]
{Fore.GREEN}  1. Secret    {Fore.WHITE}Base32-encoded 160-bit random value
{Fore.GREEN}  2. Algorithm {Fore.WHITE}SHA1 / SHA256 / SHA512
{Fore.GREEN}  3. Digits    {Fore.WHITE}6–8 (auto-clamped; most apps expect 6)
{Fore.GREEN}  4. Period    {Fore.WHITE}TOTP refresh window — 30s is the standard
{Fore.GREEN}  5. Counter   {Fore.WHITE}HOTP increments on each use

{Fore.RED}=== SECURITY NOTES ==={Fore.WHITE}
  • Keys are generated locally — nothing is sent or stored
  • Treat your secret like a password — store it in a password manager
  • TOTP is preferred for most cases (stateless, no counter sync needed)
  • HOTP suits hardware tokens where clock sync isn't possible
  • SHA256 / SHA512 are available for compliance; no practical advantage
    over SHA1 at these key lengths for standard 2FA use

{Fore.CYAN}Created by: MrBros
{Fore.WHITE}Visit: https://mrbros1509.bio.link""")

    pause("Press Enter to return to main menu...")


# ── Menu & main loop ───────────────────────────────────────────────────────────

def show_menu() -> str:
    clear_screen()
    print(f"\n{Fore.CYAN}=== 2FA Generator  v{VERSION} ===")
    print(f"{Fore.GREEN}[1] Generate 2FA — Basic")
    print(f"{Fore.GREEN}[2] Generate 2FA — Advanced")
    print(f"{Fore.BLUE}[3] Verify OTP Code")
    print(f"{Fore.BLUE}[4] Program Info")
    print(f"{Fore.RED}[0] Exit")
    return input(f"\n{Fore.YELLOW}Select an option: {Style.RESET_ALL}").strip()


def main() -> None:
    while True:
        choice = show_menu()
        try:
            if choice == "1":
                basic_generator()
            elif choice == "2":
                advanced_generator()
            elif choice == "3":
                verify_otp()
            elif choice == "4":
                show_info()
            elif choice == "0":
                clear_screen()
                print(f"\n{Fore.CYAN}Created by: MrBros")
                print(f"{Fore.WHITE}Visit: https://mrbros1509.bio.link")
                print(f"\n{Fore.RED}Exiting...")
                break
            else:
                print_error("Invalid option.")
                pause()

        except KeyboardInterrupt:
            # Ctrl+C inside a sub-menu returns to the main menu gracefully.
            print(f"\n{Fore.YELLOW}  (Ctrl+C — returning to menu)")

        except TwoFAError as e:
            # Any unhandled typed error from this app surfaces here.
            print_error(f"{type(e).__name__}: {e}")
            pause()

        except Exception as e:
            # True last-resort catch — names the exception type to aid debugging
            # without dumping a raw traceback at the end user.
            print_error(f"Unexpected error ({type(e).__name__}): {e}")
            pause()


if __name__ == "__main__":
    main()
