import pyotp
import os
import hashlib

def clear_screen():
    """Clear terminal screen"""
    os.system('cls' if os.name == 'nt' else 'clear')

def show_menu():
    clear_screen()
    print("\n=== 2FA Generator Menu ===")
    print("[1] Generate New 2FA (Basic)")
    print("[2] Generate New 2FA (Advanced)")
    print("[3] Program Info")
    print("[0] Exit")
    return input("\nSelect an option: ").strip()

def generate_secret_key() -> str:
    """Generate base32 secret key"""
    return pyotp.random_base32()

def generate_totp(issuer, account, algorithm, digits, period):
    secret = generate_secret_key()
    totp = pyotp.TOTP(
        secret,
        issuer=issuer,
        digest=getattr(hashlib, algorithm.lower()),
        digits=digits,
        interval=period
    )
    return secret, totp.provisioning_uri(name=account, issuer_name=issuer)

def generate_hotp(issuer, account, algorithm, digits, counter):
    secret = generate_secret_key()
    hotp = pyotp.HOTP(
        secret,
        issuer=issuer,
        digest=getattr(hashlib, algorithm.lower()),
        digits=digits
    )
    return secret, hotp.provisioning_uri(name=account, issuer_name=issuer, initial_count=counter)

def basic_generator():
    clear_screen()
    print("\n=== Basic 2FA Generation ===")
    print("[1] Time-based (TOTP)")
    print("[2] Counter-based (HOTP)")
    print("[0] Back")
    choice = input("\nChoose type: ").strip()
    
    if choice == "0":
        return
    elif choice not in ["1", "2"]:
        print("Invalid choice!")
        input("Press Enter to continue...")
        return
    
    clear_screen()
    if choice == "1":
        secret, uri = generate_totp("MyApp", "user@example.com", "SHA1", 6, 30)
    else:
        secret, uri = generate_hotp("MyApp", "user@example.com", "SHA1", 6, 0)
    
    print("\n=== 2FA Key Generated ===")
    print(f"Secret Key: {secret}")
    print(f"OTP Auth URI: {uri}")
    input("\nPress Enter to continue...")

def advanced_generator():
    clear_screen()
    print("\n=== Advanced 2FA Generation ===")
    print("[1] Time-based (TOTP)")
    print("[2] Counter-based (HOTP)")
    print("[0] Back")
    choice = input("\nChoose type: ").strip()
    
    if choice == "0":
        return
    elif choice not in ["1", "2"]:
        print("Invalid choice!")
        input("Press Enter to continue...")
        return
    
    clear_screen()
    print("\nEnter Parameters:")
    issuer = input("Issuer (e.g., MyApp): ").strip()
    account = input("Account (e.g., user@email.com): ").strip()
    
    print("\nAlgorithm Options:")
    print("1. SHA1 (Default)")
    print("2. SHA256")
    print("3. SHA512")
    algorithm_choice = input("Select (1-3): ").strip()
    algorithm = ["SHA1", "SHA256", "SHA512"][int(algorithm_choice)-1] if algorithm_choice in ["1","2","3"] else "SHA1"
    
    digits = int(input("Digits (6 or 8): ").strip())
    
    if choice == "1":
        period = int(input("Period (seconds): ").strip())
        secret, uri = generate_totp(issuer, account, algorithm, digits, period)
    else:
        counter = int(input("Initial Counter: ").strip())
        secret, uri = generate_hotp(issuer, account, algorithm, digits, counter)
    
    clear_screen()
    print("\n=== 2FA Key Generated ===")
    print(f"Secret Key: {secret}")
    print(f"OTP Auth URI: {uri}")
    print("\nAdd to authenticator app using:")
    print(f"1. Secret key: {secret}")
    print(f"2. Scan QR code (if supported)")
    input("\nPress Enter to continue...")

def show_info():
    clear_screen()
    print("\n=== Program Information ===")
    print("Version: 2.02.15")
    print("┌───────────────────────────┐")
    print("│  2  → Major Version       │")
    print("│  02 → Basic+Advanced Modes│")
    print("│  15 → Code Refinements    │")
    print("└───────────────────────────┘")
    print("\n=== INSTRUCTION MANUAL ===")
    print("\n[Basic Mode]")
    print("- Generates TOTP/HOTP with default settings")
    print("- Fast generation for common use cases")
    
    print("\n[Advanced Mode]")
    print("- Customize: Issuer, Account, Algorithm")
    print("- TOTP: Set time period (default 30s)")
    print("- HOTP: Set initial counter (default 0)")
    
    print("\n=== TECHNICAL GUIDE ===")
    print("\n[OTP Auth URI Format]")
    print("otpauth://TYPE/ISSUER:ACCOUNT?PARAMETERS")
    print("- TYPE: totp/hotp")
    print("- ISSUER: Service name (e.g., 'MyApp')")
    print("- PARAMETERS: secret, digits, algorithm, etc.")
    
    print("\n[Key Components]")
    print("1. Secret Key: Base32-encoded 160-bit random value")
    print("2. Algorithm: SHA1/SHA256/SHA512 (hash function)")
    print("3. Digits: 6-8 digit codes")
    print("4. Period (TOTP): Refresh interval (usually 30s)")
    print("5. Counter (HOTP): Increments after each use")
    
    print("\n=== SECURITY NOTES ===")
    print("- This tool DOES NOT store generated keys")
    print("- Always save secrets securely")
    print("- Prefer TOTP for most use cases")
    print("- Use HOTP for event-based authentication")
    
    print("\nCreated by: MrBros")
    input("\nPress Enter to return to main menu...")

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
                print("\nExiting program...")
                break
            else:
                print("\nInvalid option!")
                input("Press Enter to continue...")
        except Exception as e:
            print(f"\nError: {str(e)}")
            input("Press Enter to continue...")

if __name__ == "__main__":
    main()