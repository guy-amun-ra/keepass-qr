import sys
import argparse
import getpass
import qrcode
import os
import hashlib
import time
from pykeepass import PyKeePass
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from base64 import urlsafe_b64encode, urlsafe_b64decode
import getpass
import getpass
import subprocess
from datetime import datetime, timedelta

# Constants
CACHE_FILE = 'password_cache.txt'
TTL = 1  # 24 hours in minutes

# Get the username of the current user
username = getpass.getuser()

# Calculate the time when the TTL will expire
expiration_time = datetime.now() + timedelta(minutes=TTL)

# Format the expiration time in the format expected by the 'at' command
expiration_time_str = expiration_time.strftime('%H:%M %m/%d/%Y')

# Create a shell command to delete the cache file
command = f'echo rm {CACHE_FILE} | at {expiration_time_str} 2> /dev/null'

# Use subprocess to execute the command
subprocess.run(command, shell=True)


# Get the path of the script
script_path = os.path.realpath(__file__)

# Read the content of the script
with open(script_path, 'r') as f:
    script_content = f.read()

# Compute a hash of the script content
script_hash = hashlib.sha256(script_content.encode()).hexdigest()

# Combine the script path and the hash to form a unique identifier
unique_id = script_path + script_hash

# Function to encrypt the password
def encrypt_password(password, key):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=b'', iterations=100000, backend=default_backend())
    derived_key = urlsafe_b64encode(kdf.derive(key.encode()))
    cipher_suite = Fernet(derived_key)
    cipher_text = cipher_suite.encrypt(password.encode())
    return cipher_text

# Function to decrypt the password
def decrypt_password(cipher_text, key):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=b'', iterations=100000, backend=default_backend())
    derived_key = urlsafe_b64encode(kdf.derive(key.encode()))
    cipher_suite = Fernet(derived_key)
    password = cipher_suite.decrypt(cipher_text).decode()
    return password

def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Generate QR code from Keepass entry.')
    parser.add_argument('-k', '--keepass', required=True, help='Path to the Keepass file')
    parser.add_argument('-s', '--search', required=True, help='Name of the entry to search for')
    parser.add_argument('-n', '--entry_number', type=int, help='Number of the entry to use (if multiple entries are found)')
    parser.add_argument('-p', '--password', help='Password for the Keepass file')
    parser.add_argument('-f', '--fullpath', help='Full path to the entry')
    args = parser.parse_args()

    # Get the file path from the command line arguments or the cache file
    file_path = args.keepass
    if not file_path and os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, 'r') as f:
            cache = f.read().split(':')
            file_path = cache[3] if len(cache) > 3 else ''
    if not file_path:
        print('Error: No file path provided and no file path found in the cache file.')
        sys.exit(1)

    # Combine the unique identifier and the file path to form the encryption key
    encryption_key = unique_id + file_path

    # Check if a cached password exists
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, 'r') as f:
            cache = f.read().split(':')
            cached_unique_id = cache[0]
            cached_password = urlsafe_b64decode(cache[1])
            timestamp = float(cache[2])

        # If the unique identifier matches and the TTL has not expired, decrypt and use the cached password
        if cached_unique_id == unique_id and time.time() - timestamp < (TTL * 60):
            try:
                args.password = decrypt_password(cached_password, encryption_key)
            except:
                args.password = getpass.getpass('Enter password: ')
        else:
            args.password = getpass.getpass('Enter password: ')
    else:
        args.password = getpass.getpass('Enter password: ')

    # Encrypt and cache the password
    cipher_text = encrypt_password(args.password, encryption_key)
    with open(CACHE_FILE, 'w') as f:
        f.write(f'{unique_id}:{urlsafe_b64encode(cipher_text).decode()}:{time.time()}:{file_path}')

    # Open the Keepass file
    try:
        kp = PyKeePass(args.keepass, password=args.password)
    except Exception as e:
        print(f"Error opening Keepass file: {e}")
        os.remove(CACHE_FILE)
        sys.exit(1)

    # Search for entries that contain the search string in their title or path
    entries = [entry for entry in kp.entries if entry.title and args.search.lower() in entry.title.lower() or args.search.lower() in '/'.join(filter(None, entry.path)).lower()]

    if not entries:
        print(f"No entries found with name containing '{args.search}'")
        sys.exit(1)

    # If a full path is provided, find the entry with that path
    if args.fullpath is not None:
        entries = [entry for entry in entries if '/'.join(filter(None, entry.path)) == args.fullpath]
        if not entries:
            print(f"No entry found with path '{args.fullpath}'")
            sys.exit(1)

    # If multiple entries are found, print a list
    if len(entries) > 1 and args.entry_number is None:
        for i, entry in enumerate(entries):
            print(f"{i+1}. {'/'.join(filter(None, entry.path))}")
        sys.exit(0)
    elif args.entry_number is not None:
        entry = entries[args.entry_number-1]
    else:
        entry = entries[0]

    # Generate the QR code
    qr = qrcode.QRCode()
    qr.add_data(entry.password)
    qr.make()

    # Print the QR code as text
    qr.print_ascii()

if __name__ == "__main__":
    main()
