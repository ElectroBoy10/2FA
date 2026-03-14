import sys
import os
from typing import Union

def check_dependencies():
    required = {'pyotp': 'pyotp', 'colorama': 'colorama'}
    missing = []
    for pkg, import_name in required.items():
        try:
            __import__(import_name)
        except ImportError:
            missing.append(pkg)
    return missing

def show_alert(message):
    try:
        import tkinter as tk
        from tkinter import messagebox
        root = tk.Tk()
        root.withdraw()
        messagebox.showinfo("Dependency Check", message)
        root.destroy()
    except ImportError:
        print("\n" + "="*50)
        print(message)
        print("="*50)

missing = check_dependencies()
if missing:
    msg = "Missing dependencies:\n\n" + "\n".join(f"• {pkg}" for pkg in missing) + "\n\nInstall with:\npip install " + " ".join(missing)
    show_alert(msg)
    sys.exit(1)

import pyotp
import hashlib
from colorama import Fore, Style, init

init(autoreset=True)
VERSION = "2.03.18"

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def clamp_digits(value: Union[int, str]) -> int:
    num = int(value)
    if num < 6:
        print(f"{Fore.RED}Value <6 - defaulting to 6")
        return 6
    elif num > 8:
        print(f"{Fore.RED}Value >8 - defaulting to 8")
        return 8
    return num

def show_menu():
    clear_screen()
    print(f"\n{Fore.CYAN}=== 2FA Generator Menu ===")
    print(f"{Fore.GREEN}[1] Generate New 2FA (Basic)")
    print(f"{Fore.GREEN}[2] Generate New 2FA (Advanced)")
    print(f"{Fore.BLUE}[3] Program Info")
    print(f"{Fore.RED}[0] Exit")
    return input(f"\n{Fore.YELLOW}Select an option: {Style.RESET_ALL}").strip()

def generate_secret_key() -> str:
    return pyotp.random_base32()

def generate_totp(issuer, account, algorithm, digits, period):
    secret = generate_secret_key()
    totp = pyotp.TOTP(secret,issuer=issuer,digest=getattr(hashlib, algorithm.lower()),digits=digits,interval=period)
    return secret, totp.provisioning_uri(name=account, issuer_name=issuer)

def generate_hotp(issuer, account, algorithm, digits, counter):
    secret = generate_secret_key()
    hotp = pyotp.HOTP(secret,issuer=issuer,digest=getattr(hashlib, algorithm.lower()),digits=digits)
    return secret, hotp.provisioning_uri(name=account, issuer_name=issuer, initial_count=counter)

def basic_generator():
    clear_screen()
    print(f"\n{Fore.CYAN}=== Basic 2FA Generation ===")
    print(f"{Fore.GREEN}[1] Time-based (TOTP)")
    print(f"{Fore.GREEN}[2] Counter-based (HOTP)")
    print(f"{Fore.RED}[0] Back")
    choice = input(f"\n{Fore.YELLOW}Choose type: {Style.RESET_ALL}").strip()
    
    if choice == "0": return
    elif choice not in ["1", "2"]:
        print(f"{Fore.RED}Invalid choice!")
        input(f"{Fore.YELLOW}Press Enter to continue...")
        return
    
    clear_screen()
    issuer = input(f"{Fore.YELLOW}Issuer (e.g., MyApp): {Style.RESET_ALL}").strip() or "MyApp"
    account = input(f"{Fore.YELLOW}Account (e.g., user@email.com): {Style.RESET_ALL}").strip() or "user@example.com"
    
    while True:
        try:
            digits_input = input(f"{Fore.YELLOW}Digits [6-8] (Default 6): {Style.RESET_ALL}").strip() or "6"
            digits = clamp_digits(digits_input)
            break
        except ValueError:
            print(f"{Fore.RED}Invalid number! Please enter 6-8")

    if choice == "1":
        secret, uri = generate_totp(issuer, account, "SHA1", digits, 30)
    else:
        secret, uri = generate_hotp(issuer, account, "SHA1", digits, 0)
    
    print(f"\n{Fore.CYAN}=== 2FA Key Generated ===")
    print(f"{Fore.MAGENTA}Secret Key: {Style.BRIGHT}{secret}")
    print(f"{Fore.YELLOW}OTP Auth URI: {Style.BRIGHT}{uri}")
    input(f"\n{Fore.YELLOW}Press Enter to continue...")

def advanced_generator():
    clear_screen()
    print(f"\n{Fore.CYAN}=== Advanced 2FA Generation ===")
    print(f"{Fore.GREEN}[1] Time-based (TOTP)")
    print(f"{Fore.GREEN}[2] Counter-based (HOTP)")
    print(f"{Fore.RED}[0] Back")
    choice = input(f"\n{Fore.YELLOW}Choose type: {Style.RESET_ALL}").strip()
    
    if choice == "0": return
    elif choice not in ["1", "2"]:
        print(f"{Fore.RED}Invalid choice!")
        input(f"{Fore.YELLOW}Press Enter to continue...")
        return
    
    clear_screen()
    print(f"\n{Fore.BLUE}Enter Parameters:")
    issuer = input(f"{Fore.YELLOW}Issuer (e.g., MyApp): {Style.RESET_ALL}").strip()
    account = input(f"{Fore.YELLOW}Account (e.g., user@email.com): {Style.RESET_ALL}").strip()
    
    print(f"\n{Fore.CYAN}Algorithm Options:")
    print(f"{Fore.GREEN}1. SHA1 (Default)")
    print(f"{Fore.GREEN}2. SHA256")
    print(f"{Fore.GREEN}3. SHA512")
    algorithm_choice = input(f"{Fore.YELLOW}Select (1-3): {Style.RESET_ALL}").strip()
    algorithm = ["SHA1", "SHA256", "SHA512"][int(algorithm_choice)-1] if algorithm_choice in ["1","2","3"] else "SHA1"
    
    while True:
        try:
            digits_input = input(f"{Fore.YELLOW}Digits (6 or 8): {Style.RESET_ALL}").strip()
            digits = clamp_digits(digits_input)
            break
        except ValueError:
            print(f"{Fore.RED}Invalid input! Using default 6")
            digits = 6
            break
    
    if choice == "1":
        period = int(input(f"{Fore.YELLOW}Period (seconds): {Style.RESET_ALL}").strip())
        secret, uri = generate_totp(issuer, account, algorithm, digits, period)
    else:
        counter = int(input(f"{Fore.YELLOW}Initial Counter: {Style.RESET_ALL}").strip())
        secret, uri = generate_hotp(issuer, account, algorithm, digits, counter)
    
    clear_screen()
    print(f"\n{Fore.CYAN}=== 2FA Key Generated ===")
    print(f"{Fore.MAGENTA}Secret Key: {Style.BRIGHT}{secret}")
    print(f"{Fore.YELLOW}OTP Auth URI: {Style.BRIGHT}{uri}")
    print(f"\n{Fore.BLUE}Add to authenticator app using:")
    print(f"{Fore.GREEN}1. Secret key: {secret}")
    print(f"{Fore.GREEN}2. Scan QR code (if supported)")
    input(f"\n{Fore.YELLOW}Press Enter to continue...")

def show_info():
    clear_screen()
    print(f"\n{Fore.CYAN}=== Program Information ===")
    print(f"{Fore.MAGENTA}Version: {VERSION}")
    print(f"{Fore.BLUE}┌───────────────────────────┐")
    print(f"{Fore.BLUE}│  {Fore.CYAN}2  → Major Version       {Fore.BLUE}│")
    print(f"{Fore.BLUE}│  {Fore.GREEN}03 → Basic+Advanced Modes{Fore.BLUE}│")
    print(f"{Fore.BLUE}│  {Fore.YELLOW}18 → Code Refinements    {Fore.BLUE}│")
    print(f"{Fore.BLUE}└───────────────────────────┘")
    print(f"\n{Fore.CYAN}=== INSTRUCTION MANUAL ===")
    print(f"\n{Fore.BLUE}[Basic Mode]")
    print(f"{Fore.WHITE}- Generates TOTP/HOTP with default settings")
    print(f"{Fore.WHITE}- Fast generation for common use cases")
    print(f"\n{Fore.BLUE}[Advanced Mode]")
    print(f"{Fore.WHITE}- Customize: Issuer, Account, Algorithm")
    print(f"{Fore.WHITE}- TOTP: Set time period (default 30s)")
    print(f"{Fore.WHITE}- HOTP: Set initial counter (default 0)")
    print(f"\n{Fore.CYAN}=== TECHNICAL GUIDE ===")
    print(f"\n{Fore.BLUE}[OTP Auth URI Format]")
    print(f"{Fore.YELLOW}otpauth://TYPE/ISSUER:ACCOUNT?PARAMETERS")
    print(f"{Fore.WHITE}- TYPE: totp/hotp")
    print(f"{Fore.WHITE}- ISSUER: Service name (e.g., 'MyApp')")
    print(f"{Fore.WHITE}- PARAMETERS: secret, digits, algorithm, etc.")
    print(f"\n{Fore.BLUE}[Key Components]")
    print(f"{Fore.GREEN}1. Secret Key: {Fore.WHITE}Base32-encoded 160-bit random value")
    print(f"{Fore.GREEN}2. Algorithm: {Fore.WHITE}SHA1/SHA256/SHA512 (hash function)")
    print(f"{Fore.GREEN}3. Digits: {Fore.WHITE}6-8 digit codes (auto-clamped)")
    print(f"{Fore.GREEN}4. Period (TOTP): {Fore.WHITE}Refresh interval (usually 30s)")
    print(f"{Fore.GREEN}5. Counter (HOTP): {Fore.WHITE}Increments after each use")
    print(f"\n{Fore.RED}=== SECURITY NOTES ===")
    print(f"{Fore.WHITE}- This tool DOES NOT store generated keys")
    print(f"\n{Fore.CYAN}Created by: MrBros")
    print(f"\n{Fore.WHITE}Visit: https://mrbros1509.bio.link")
    input(f"\n{Fore.YELLOW}Press Enter to return to main menu...")

def main():
    while True:
        try:
            choice = show_menu()
            if choice == "1":
                basic_generator()
            elif choice == "2":
                advanced_generator()
            elif choice == "3":
                show_info()
            elif choice == "0":
                clear_screen()
                print(f"\n{Fore.CYAN}Created by: MrBros")
                print(f"{Fore.WHITE}Visit: https://mrbros1509.bio.link")
                print(f"\n{Fore.RED}Exiting program...")
                break
            else:
                print(f"\n{Fore.RED}Invalid option!")
                input(f"{Fore.YELLOW}Press Enter to continue...")
        except Exception as e:
            print(f"\n{Fore.RED}Error: {str(e)}")
            input(f"{Fore.YELLOW}Press Enter to continue...")

if __name__ == "__main__":
    main()
