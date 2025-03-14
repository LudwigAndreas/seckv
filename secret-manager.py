#!/usr/bin/env python3.11

import os
import sys
import json
import argparse
import getpass
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

CONFIG_DIR = Path.home() / ".config" / "securekv"
DATA_FILE = CONFIG_DIR / "data.enc"
SALT_FILE = CONFIG_DIR / "salt"

def get_key(password, salt):
    """Derive encryption key from password and salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def initialize():
    """Initialize the storage directory and files."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    
    if not SALT_FILE.exists():
        # Generate a random salt and save it
        salt = os.urandom(16)
        with open(SALT_FILE, "wb") as f:
            f.write(salt)
    
    # Create empty data file if it doesn't exist
    if not DATA_FILE.exists():
        with open(DATA_FILE, "wb") as f:
            pass

def load_data(password):
    """Load and decrypt the data."""
    initialize()
    
    # Read salt
    with open(SALT_FILE, "rb") as f:
        salt = f.read()
    
    key = get_key(password, salt)
    cipher = Fernet(key)
    
    # Read and decrypt data
    try:
        if DATA_FILE.stat().st_size == 0:
            return {}
            
        with open(DATA_FILE, "rb") as f:
            encrypted_data = f.read()
            
        decrypted_data = cipher.decrypt(encrypted_data)
        return json.loads(decrypted_data.decode())
    except Exception as e:
        print(f"Error: Could not decrypt data. Wrong password or corrupted data file.", file=sys.stderr)
        sys.exit(1)

def save_data(data, password):
    """Encrypt and save the data."""
    initialize()
    
    # Read salt
    with open(SALT_FILE, "rb") as f:
        salt = f.read()
    
    key = get_key(password, salt)
    cipher = Fernet(key)
    
    # Encrypt and write data
    json_data = json.dumps(data)
    encrypted_data = cipher.encrypt(json_data.encode())
    
    with open(DATA_FILE, "wb") as f:
        f.write(encrypted_data)

def set_value(args):
    """Set a key-value pair."""
    password = getpass.getpass("Enter password: ")
    
    # Load existing data
    data = load_data(password)
    
    # Set the new value
    data[args.key] = args.value
    
    # Save the updated data
    save_data(data, password)
    print(f"Saved key: {args.key}")

def get_value(args):
    """Get a value by key."""
    password = getpass.getpass("Enter password: ")
    
    # Load data
    data = load_data(password)
    
    # Get the value
    if args.key in data:
        print(data[args.key])
    else:
        print(f"Error: Key '{args.key}' not found.", file=sys.stderr)
        sys.exit(1)

def list_keys(args):
    """List all keys."""
    password = getpass.getpass("Enter password: ")
    
    # Load data
    data = load_data(password)
    
    # List keys
    if not data:
        print("No keys found.")
    else:
        print("Keys:")
        for key in data.keys():
            print(f"  {key}")

def delete_key(args):
    """Delete a key."""
    password = getpass.getpass("Enter password: ")
    
    # Load data
    data = load_data(password)
    
    # Delete the key
    if args.key in data:
        del data[args.key]
        save_data(data, password)
        print(f"Deleted key: {args.key}")
    else:
        print(f"Error: Key '{args.key}' not found.", file=sys.stderr)
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description='Secure key-value store for API keys and secrets')
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # Set command
    set_parser = subparsers.add_parser('set', help='Set a key-value pair')
    set_parser.add_argument('key', help='Key name')
    set_parser.add_argument('value', help='Value to store')
    
    # Get command
    get_parser = subparsers.add_parser('get', help='Get a value by key')
    get_parser.add_argument('key', help='Key name')
    
    # List command
    list_parser = subparsers.add_parser('list', help='List all keys')
    
    # Delete command
    delete_parser = subparsers.add_parser('delete', help='Delete a key')
    delete_parser.add_argument('key', help='Key to delete')
    
    args = parser.parse_args()
    
    if args.command == 'set':
        set_value(args)
    elif args.command == 'get':
        get_value(args)
    elif args.command == 'list':
        list_keys(args)
    elif args.command == 'delete':
        delete_key(args)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
