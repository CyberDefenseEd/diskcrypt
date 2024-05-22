import os
import argparse
from encryption import Encryption

def get_arguments():
    """
    Parse and return command-line arguments.
    """
    parser = argparse.ArgumentParser(description="Encrypt files recursively with a given password and salt.")
    parser.add_argument("-q", "--quiet", action="store_true", help="Run quietly without output")
    parser.add_argument("-p", "--password", required=True, help="Encryption password")
    parser.add_argument("-s", "--salt", required=True, help="Encryption salt")
    return parser.parse_args()

def check_privileges(system_type, quiet):
    """
    Check if the script is run with sufficient privileges.
    """
    if system_type not in ["win", "invalid"] and os.geteuid() != 0:
        if not quiet:
            print("This script must be run with sudo/as root to encrypt files recursively!")
        exit(1)

    if system_type == "win" and not Encryption.is_admin():
        if not quiet:
            print("This script must be run with sudo/as root to encrypt files recursively!")
        exit(1)

def main():
    """
    Main function to handle the encryption process or just destroy a PC by accident
    """
    args = get_arguments()
    password = args.password.encode()
    salt = args.salt.encode()
    system_type = Encryption.get_system()

    check_privileges(system_type, args.quiet)

    if system_type == "lin":
        user_home_path = f"/home/{os.getlogin()}"
    elif system_type == "mac":
        user_home_path = f"/Users/{os.getlogin()}"
    elif system_type == "win":
        user_home_path = f"C:\\Users\\{os.getlogin()}"
    else:
        print(f"Unknown OS: {system_type}")
        return

    Encryption.encrypt(user_home_path, password, salt, args)

if __name__ == "__main__":
    main()
