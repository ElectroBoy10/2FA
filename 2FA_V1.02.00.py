import argparse
import pyotp

def generate_secret_key() -> str:
    """Generate a base32 encoded secret key (160 bits)"""
    return pyotp.random_base32()

def generate_totp_uri(
    secret: str,
    issuer: str = "MyApp",
    account_name: str = "user@example.com",
    algorithm: str = "SHA1",
    digits: int = 6,
    period: int = 30
) -> str:
    """Generate TOTP URI"""
    totp = pyotp.TOTP(
        secret,
        digest=getattr(__import__('hashlib'), algorithm.lower()),
        digits=digits,
        interval=period
    )
    return totp.provisioning_uri(name=account_name, issuer_name=issuer)

def generate_hotp_uri(
    secret: str,
    issuer: str = "MyApp",
    account_name: str = "user@example.com",
    algorithm: str = "SHA1",
    digits: int = 6,
    counter: int = 0
) -> str:
    """Generate HOTP URI"""
    hotp = pyotp.HOTP(
        secret,
        digest=getattr(__import__('hashlib'), algorithm.lower()),
        digits=digits
    )
    return hotp.provisioning_uri(name=account_name, issuer_name=issuer, initial_count=counter)

def main():
    parser = argparse.ArgumentParser(description="2FA Key Generator")
    parser.add_argument("-t", "--type", choices=["totp", "hotp"], default="totp",
                      help="2FA type (default: totp)")
    parser.add_argument("-i", "--issuer", default="MyApp",
                      help="Issuer name (default: MyApp)")
    parser.add_argument("-a", "--algorithm", default="SHA1",
                      choices=["SHA1", "SHA256", "SHA512"],
                      help="Hashing algorithm (default: SHA1)")
    parser.add_argument("-d", "--digits", type=int, default=6,
                      choices=[6, 8], help="Number of digits (default: 6)")
    parser.add_argument("-p", "--period", type=int, default=30,
                      help="Time period for TOTP (default: 30)")
    parser.add_argument("-c", "--counter", type=int, default=0,
                      help="Initial counter for HOTP (default: 0)")

    args = parser.parse_args()


    secret = generate_secret_key()
    print(f"Generated Secret Key: {secret}")


    if args.type == "totp":
        uri = generate_totp_uri(
            secret,
            issuer=args.issuer,
            algorithm=args.algorithm,
            digits=args.digits,
            period=args.period
        )
    else:
        uri = generate_hotp_uri(
            secret,
            issuer=args.issuer,
            algorithm=args.algorithm,
            digits=args.digits,
            counter=args.counter
        )
    
    print(f"OTP Auth URI: {uri}")

    print("\nAdd to authenticator app using:")
    print(f"1. Secret key: {secret}")
    print(f"2. Manual entry with these details:")
    print(f"   - Type: {args.type.upper()}")
    print(f"   - Issuer: {args.issuer}")
    print(f"   - Algorithm: {args.algorithm}")
    print(f"   - Digits: {args.digits}")
    if args.type == "totp":
        print(f"   - Period: {args.period} seconds")
    else:
        print(f"   - Initial Counter: {args.counter}")

if __name__ == "__main__":
    main()