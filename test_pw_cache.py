import os
import hashlib
import time
import getpass
import argparse
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from base64 import urlsafe_b64encode, urlsafe_b64decode

# Constants
CACHE_FILE = 'password_cache.txt'
TTL = 60 * 60 * 24  # 24 hours

# Parse command line arguments
parser = argparse.ArgumentParser()
parser.add_argument('--file-path', default='', help='The file path to use for encryption and as a dictionary key')
args = parser.parse_args()

# Get the path of the script
script_path = os.path.realpath(__file__)

# Read the content of the script
with open(script_path, 'r') as f:
    script_content = f.read()

# Compute a hash of the script content
script_hash = hashlib.sha256(script_content.encode()).hexdigest()

# Combine the script path and the hash to form a unique identifier
unique_id = script_path + script_hash

# Get the file path from the command line arguments or the cache file
file_path = args.file_path
if not file_path and os.path.exists(CACHE_FILE):
    with open(CACHE_FILE, 'r') as f:
        cache = f.read().split(':')
        file_path = cache[3] if len(cache) > 3 else ''
if not file_path:
    print('Error: No file path provided and no file path found in the cache file.')
    sys.exit(1)

# Combine the unique identifier and the file path to form the encryption key
encryption_key = unique_id + file_path

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

# Create a dictionary to store the encrypted passwords
password_dict = {}

# Check if a cached password exists
if os.path.exists(CACHE_FILE):
    with open(CACHE_FILE, 'r') as f:
        cache = f.read().split(':')
        cached_unique_id = cache[0]
        cached_password = urlsafe_b64decode(cache[1])
        timestamp = float(cache[2])

    # If the unique identifier matches and the TTL has not expired, decrypt and use the cached password
    if cached_unique_id == unique_id and time.time() - timestamp < TTL:
        try:
            password = decrypt_password(cached_password, encryption_key)
        except:
            password = getpass.getpass('Enter password: ')
    else:
        password = getpass.getpass('Enter password: ')
else:
    password = getpass.getpass('Enter password: ')

# Encrypt and cache the password
cipher_text = encrypt_password(password, encryption_key)
with open(CACHE_FILE, 'w') as f:
    f.write(f'{unique_id}:{urlsafe_b64encode(cipher_text).decode()}:{time.time()}:{file_path}')

# Add the encrypted password to the dictionary
password_dict[file_path] = cipher_text

# Use the password for your operations
# ...

# Print the password
print(f'The password is: {password}')
