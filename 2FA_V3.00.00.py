"""
2FA Generator — V3.00.00
Author : MrBros (https://mrbros1509.bio.link)

What's new in V3:
  - QR code export  : scan directly into any authenticator app
  - OTP Verification: confirm a code works before committing to a service
  - Clipboard copy  : one keypress to copy the secret
  - Solid input validation on every numeric field (no more crash-on-bad-input)
  - Defaults on every prompt — just press Enter for the standard setup
"""

import sys
import os
import hashlib
from typing import Optional, Tuple

VERSION = "3.00.00"

# ── Dependency gate ────────────────────────────────────────────────────────────
# Check everything up front so the user gets one clear install command
# instead of a confusing ImportError mid-session.

REQUIRED_PACKAGES = {
    "pyotp": "pyotp",
    "colorama": "colorama",
    "qrcode": "qrcode",
    "pyperclip": "pyperclip",
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
        # tkinter isn't available in all Python installs (e.g. minimal Linux images)
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

MIN_DIGITS     = 6
MAX_DIGITS     = 8
DEFAULT_DIGITS = 6
DEFAULT_PERIOD = 30   # seconds — the near-universal TOTP window
DEFAULT_COUNTER = 0

# Algorithms supported by pyotp; SHA1 is the universal default for compatibility
VALID_ALGORITHMS = ["SHA1", "SHA256", "SHA512"]

# ── Terminal helpers ───────────────────────────────────────────────────────────

def clear_screen() -> None:
    os.system("cls" if os.name == "nt" else "clear")


def pause(msg: str = "Press Enter to continue...") -> None:
    input(f"\n{Fore.YELLOW}{msg}")


def banner(title: str) -> None:
    print(f"\n{Fore.CYAN}=== {title} ===")


# ── Input helpers ──────────────────────────────────────────────────────────────

def clamp_digits(raw: str) -> int:
    """
    Coerce digit count into the valid range [MIN_DIGITS, MAX_DIGITS].
    Most authenticator apps silently reject anything outside 6–8,
    so clamping with a warning is safer than crashing or producing
    a URI that fails on import.
    """
    value = int(raw)
    if value < MIN_DIGITS:
        print(f"{Fore.RED}  Digit count below {MIN_DIGITS} — using {MIN_DIGITS}")
        return MIN_DIGITS
    if value > MAX_DIGITS:
        print(f"{Fore.RED}  Digit count above {MAX_DIGITS} — using {MAX_DIGITS}")
        return MAX_DIGITS
    return value


def prompt_int(label: str, default: int, min_val: Optional[int] = None) -> int:
    """
    Prompt for a positive integer with a default fallback.
    Loops until valid input is received — fixes the crash-on-bad-input
    bug that existed in V2 for period and counter fields.
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
                print(f"{Fore.RED}  Must be ≥ {min_val}. Try again.")
                continue
            return value
        except ValueError:
            print(f"{Fore.RED}  Not a valid number. Try again.")


def prompt_digits() -> int:
    """Prompt specifically for OTP digit count, applying clamping on the result."""
    while True:
        raw = input(
            f"{Fore.YELLOW}Digits [{MIN_DIGITS}–{MAX_DIGITS}] (default {DEFAULT_DIGITS}): "
            f"{Style.RESET_ALL}"
        ).strip()
        if not raw:
            return DEFAULT_DIGITS
        try:
            return clamp_digits(raw)
        except ValueError:
            print(f"{Fore.RED}  Enter a number between {MIN_DIGITS} and {MAX_DIGITS}.")


def prompt_algorithm() -> str:
    """Present the algorithm menu and return the chosen name."""
    print(f"\n{Fore.CYAN}Algorithm:")
    for i, algo in enumerate(VALID_ALGORITHMS, 1):
        suffix = "  (default)" if algo == "SHA1" else ""
        print(f"  {Fore.GREEN}[{i}] {algo}{suffix}")

    raw = input(
        f"{Fore.YELLOW}Select (1–3, default 1): {Style.RESET_ALL}"
    ).strip()

    if raw in ("1", "2", "3"):
        return VALID_ALGORITHMS[int(raw) - 1]

    # Anything invalid falls back to SHA1 — the only algorithm with universal
    # support across all major authenticator apps.
    return "SHA1"


def pick_otp_type() -> Optional[str]:
    """Shared TOTP / HOTP picker used by both generator flows."""
    print(f"\n{Fore.GREEN}[1] Time-based (TOTP)")
    print(f"{Fore.GREEN}[2] Counter-based (HOTP)")
    print(f"{Fore.RED}[0] Back")
    choice = input(f"\n{Fore.YELLOW}Choose type: {Style.RESET_ALL}").strip()

    if choice == "0":
        return None
    if choice not in ("1", "2"):
        print(f"{Fore.RED}Invalid choice.")
        pause()
        return None
    return choice


# ── Core OTP generation ────────────────────────────────────────────────────────

def generate_secret() -> str:
    """Produce a cryptographically random base32 secret (160 bits by default)."""
    return pyotp.random_base32()


def build_totp(
    secret: str,
    issuer: str,
    account: str,
    algorithm: str,
    digits: int,
    period: int,
) -> Tuple[str, pyotp.TOTP]:
    """Construct a TOTP object and return its provisioning URI."""
    digest = getattr(hashlib, algorithm.lower())
    totp = pyotp.TOTP(
        secret,
        issuer=issuer,
        digest=digest,
        digits=digits,
        interval=period,
    )
    uri = totp.provisioning_uri(name=account, issuer_name=issuer)
    return uri, totp


def build_hotp(
    secret: str,
    issuer: str,
    account: str,
    algorithm: str,
    digits: int,
    counter: int,
) -> Tuple[str, pyotp.HOTP]:
    """Construct an HOTP object and return its provisioning URI."""
    digest = getattr(hashlib, algorithm.lower())
    hotp = pyotp.HOTP(
        secret,
        issuer=issuer,
        digest=digest,
        digits=digits,
    )
    uri = hotp.provisioning_uri(
        name=account, issuer_name=issuer, initial_count=counter
    )
    return uri, hotp


# ── Post-generation actions ────────────────────────────────────────────────────

def save_qr_code(uri: str, filename: str = "2fa_qr.png") -> Optional[str]:
    """
    Write the otpauth URI as a scannable QR code PNG.
    Returns the absolute save path on success, or None if it fails.
    Most authenticator apps (Google, Authy, Microsoft, etc.) can
    scan this file directly — no manual secret entry required.
    """
    try:
        img = qrcode.make(uri)
        path = os.path.abspath(filename)
        img.save(path)
        return path
    except Exception as e:
        print(f"{Fore.RED}  QR code generation failed: {e}")
        return None


def offer_qr_code(uri: str) -> None:
    """Optionally generate and save a QR code for the provisioning URI."""
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
    path = save_qr_code(uri, filename)
    if path:
        print(f"{Fore.GREEN}  Saved → {path}")


def offer_clipboard(secret: str) -> None:
    """
    Optionally copy the secret key to the system clipboard.
    Avoids the error-prone process of manually selecting terminal text.
    """
    choice = input(
        f"{Fore.YELLOW}Copy secret key to clipboard? [y/N]: {Style.RESET_ALL}"
    ).strip().lower()
    if choice != "y":
        return

    try:
        pyperclip.copy(secret)
        print(f"{Fore.GREEN}  Copied to clipboard.")
    except pyperclip.PyperclipException:
        # Common in headless or SSH environments that have no clipboard daemon
        print(f"{Fore.RED}  Clipboard not available in this environment.")


def show_result(secret: str, uri: str) -> None:
    """Display the generated credentials then offer optional follow-up actions."""
    banner("2FA Key Generated")
    print(f"{Fore.MAGENTA}Secret Key : {Style.BRIGHT}{secret}")
    print(f"{Fore.YELLOW}OTP URI    : {Style.BRIGHT}{uri}")
    print()
    offer_qr_code(uri)
    offer_clipboard(secret)


# ── OTP Verification ───────────────────────────────────────────────────────────

def verify_otp() -> None:
    """
    Verify a code against a known secret.

    The main use case: after scanning a QR code into an authenticator app,
    paste the secret back here and confirm the code matches before adding
    the secret to a live service. Prevents lockout from a bad import.
    """
    clear_screen()
    banner("OTP Verification")
    print(
        f"{Fore.WHITE}Paste your secret and enter the code your authenticator "
        f"app shows to confirm they match.\n"
    )

    secret = input(f"{Fore.YELLOW}Secret key: {Style.RESET_ALL}").strip().upper()
    if not secret:
        print(f"{Fore.RED}No secret entered.")
        pause()
        return

    otp_type = (
        input(f"{Fore.YELLOW}Type — [T]OTP or [H]OTP (default T): {Style.RESET_ALL}")
        .strip()
        .upper()
        or "T"
    )
    code = input(f"{Fore.YELLOW}Code from your app: {Style.RESET_ALL}").strip()

    try:
        if otp_type == "H":
            counter = prompt_int("Counter value", default=0, min_val=0)
            hotp = pyotp.HOTP(secret)
            is_valid = hotp.verify(code, counter)
        else:
            totp = pyotp.TOTP(secret)
            # valid_window=1 allows ±30 seconds of clock drift —
            # the standard tolerance that authenticator apps themselves apply.
            is_valid = totp.verify(code, valid_window=1)

        if is_valid:
            print(f"\n{Fore.GREEN}✔  Code is VALID.")
        else:
            print(f"\n{Fore.RED}✘  Code is INVALID.")
            if otp_type != "H":
                print(
                    f"{Fore.WHITE}  Tip: TOTP is time-sensitive. "
                    f"Check your device clock is correctly synced."
                )

    except Exception as e:
        # A malformed secret produces a cryptic error from pyotp/hmac — surface it clearly.
        print(f"{Fore.RED}  Verification error ({type(e).__name__}): {e}")
        print(f"{Fore.WHITE}  Make sure the secret is valid base32 (A–Z, 2–7, no spaces).")

    pause()


# ── Generator flows ────────────────────────────────────────────────────────────

def basic_generator() -> None:
    """
    Quick generation with sensible defaults.
    Lets the user set issuer, account, and digit count but skips algorithm
    and period — the settings that almost never need changing for everyday use.
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

    secret = generate_secret()
    if choice == "1":
        uri, _ = build_totp(secret, issuer, account, "SHA1", digits, DEFAULT_PERIOD)
    else:
        uri, _ = build_hotp(secret, issuer, account, "SHA1", digits, DEFAULT_COUNTER)

    show_result(secret, uri)
    pause()


def advanced_generator() -> None:
    """
    Full parameter control — exposes every configurable OTP option.
    Intended for non-default setups: services requiring SHA256, 8-digit
    codes, unusual TOTP periods, or a specific HOTP starting counter.
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

    secret = generate_secret()

    if choice == "1":
        period = prompt_int("TOTP period (seconds)", default=DEFAULT_PERIOD, min_val=1)
        uri, _ = build_totp(secret, issuer, account, algorithm, digits, period)
    else:
        counter = prompt_int("Initial HOTP counter", default=DEFAULT_COUNTER, min_val=0)
        uri, _ = build_hotp(secret, issuer, account, algorithm, digits, counter)

    show_result(secret, uri)
    pause()


# ── Info screen ────────────────────────────────────────────────────────────────

def show_info() -> None:
    clear_screen()
    banner("Program Information")
    print(f"{Fore.MAGENTA}Version: {VERSION}")
    print(f"""
{Fore.BLUE}┌───────────────────────────┐
{Fore.BLUE}│  {Fore.CYAN}3  → Major Version       {Fore.BLUE}│
{Fore.BLUE}│  {Fore.GREEN}00 → Feature Set         {Fore.BLUE}│
{Fore.BLUE}│  {Fore.YELLOW}00 → Code Revision       {Fore.BLUE}│
{Fore.BLUE}└───────────────────────────┘

{Fore.CYAN}=== WHAT'S NEW IN V3 ==={Fore.WHITE}
  • QR code export  — scan directly into any authenticator app
  • OTP Verification — confirm codes work before locking in a secret
  • Clipboard copy  — one keypress to copy the secret key
  • Solid validation — no more crashes on bad numeric input
  • Defaults everywhere — just press Enter for the standard setup

{Fore.CYAN}=== INSTRUCTION MANUAL ===

{Fore.BLUE}[Basic Mode]
{Fore.WHITE}  Fast generation using SHA1 / 30s period (universal defaults).
  Prompts for issuer, account, and digit count only.

{Fore.BLUE}[Advanced Mode]
{Fore.WHITE}  Full control: issuer, account, algorithm, digits, period / counter.
  Use this for services with non-standard OTP requirements.

{Fore.BLUE}[Verify OTP]
{Fore.WHITE}  Paste a secret and enter the current code from your app.
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
  • Treat your secret key like a password — store it in a password manager
  • TOTP is preferred for most use cases (stateless, no sync required)
  • HOTP suits hardware tokens where clock sync isn't possible
  • SHA256 / SHA512 offer no practical security advantage over SHA1
    at these key lengths but are available for compliance requirements

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
                print(f"\n{Fore.RED}Invalid option.")
                pause()

        except KeyboardInterrupt:
            # Ctrl+C in a sub-menu returns to the main menu instead of crashing.
            print(f"\n{Fore.YELLOW}  (Ctrl+C — returning to menu)")

        except Exception as e:
            # Last-resort catch — prints the exception type to aid debugging
            # without exposing a full traceback to the end user.
            print(f"\n{Fore.RED}Unexpected error ({type(e).__name__}): {e}")
            pause()


if __name__ == "__main__":
    main()
