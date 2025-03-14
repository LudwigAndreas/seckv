#!/usr/bin/env python3
import os
import sys
import json
import base64
import getpass
import argparse
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class SecretManager:
    def __init__(self, storage_path=None):
        """Initialize the secret manager with the storage location."""
        if storage_path is None:
            # Default to ~/.secret-store directory
            self.storage_dir = Path.home() / '.secret-store'
        else:
            self.storage_dir = Path(storage_path)
        
        self.storage_file = self.storage_dir / 'secrets.enc'
        self.salt_file = self.storage_dir / 'salt'
        
        # Create directory if it doesn't exist
        self.storage_dir.mkdir(exist_ok=True)
        
        # Generate and save salt if it doesn't exist
        if not self.salt_file.exists():
            self.salt = os.urandom(16)
            with open(self.salt_file, 'wb') as f:
                f.write(self.salt)
        else:
            with open(self.salt_file, 'rb') as f:
                self.salt = f.read()
    
    def _derive_key(self, password):
        """Derive encryption key from password and salt."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))
    
    def _encrypt_data(self, data, password):
        """Encrypt data using password-derived key."""
        key = self._derive_key(password)
        f = Fernet(key)
        return f.encrypt(json.dumps(data).encode())
    
    def _decrypt_data(self, encrypted_data, password):
        """Decrypt data using password-derived key."""
        key = self._derive_key(password)
        f = Fernet(key)
        try:
            decrypted_data = f.decrypt(encrypted_data)
            return json.loads(decrypted_data)
        except Exception:
            print("Error: Incorrect password or corrupted data.", file=sys.stderr)
            sys.exit(1)
    
    def load_secrets(self, password):
        """Load encrypted secrets from storage."""
        if not self.storage_file.exists():
            return {}
        
        with open(self.storage_file, 'rb') as f:
            encrypted_data = f.read()
        
        return self._decrypt_data(encrypted_data, password)
    
    def save_secrets(self, secrets, password):
        """Save encrypted secrets to storage."""
        encrypted_data = self._encrypt_data(secrets, password)
        
        with open(self.storage_file, 'wb') as f:
            f.write(encrypted_data)
    
    def set_secret(self, key, value, password):
        """Set a secret value."""
        secrets = self.load_secrets(password)
        secrets[key] = value
        self.save_secrets(secrets, password)
        return True
    
    def get_secret(self, key, password):
        """Get a secret value."""
        secrets = self.load_secrets(password)
        return secrets.get(key)
    
    def list_secrets(self, password):
        """List all secret keys."""
        return self.load_secrets(password)
    
    def delete_secret(self, key, password):
        """Delete a secret by key."""
        secrets = self.load_secrets(password)
        if key in secrets:
            del secrets[key]
            self.save_secrets(secrets, password)
            return True
        return False

def main():
    parser = argparse.ArgumentParser(description='Secure CLI Secret Manager')
    parser.add_argument('--storage', help='Path to storage directory')
    
    subparsers = parser.add_subparsers(dest='command', help='Command')
    
    # Set command
    set_parser = subparsers.add_parser('set', help='Set a secret')
    set_parser.add_argument('key', help='Secret key')
    set_parser.add_argument('value', help='Secret value')
    set_parser.add_argument('--password', '-p', help='Password (not recommended, use env var or prompt)')
    
    # Get command
    get_parser = subparsers.add_parser('get', help='Get a secret')
    get_parser.add_argument('key', help='Secret key')
    get_parser.add_argument('--password', '-p', help='Password (not recommended, use env var or prompt)')
    get_parser.add_argument('--no-newline', '-n', action='store_true', help='Do not print newline')
    
    # List command
    list_parser = subparsers.add_parser('list', help='List all secrets')
    list_parser.add_argument('--password', '-p', help='Password (not recommended, use env var or prompt)')
    list_parser.add_argument('--json', '-j', action='store_true', help='Output as JSON')
    
    # Delete command
    delete_parser = subparsers.add_parser('delete', help='Delete a secret')
    delete_parser.add_argument('key', help='Secret key')
    delete_parser.add_argument('--password', '-p', help='Password (not recommended, use env var or prompt)')
    
    args = parser.parse_args()
    
    # Initialize the secret manager
    manager = SecretManager(args.storage)
    
    # Get password from arguments, environment, or prompt
    password = args.password if hasattr(args, 'password') and args.password else os.environ.get('SECRET_STORE_PASSWORD')
    if not password:
        password = getpass.getpass('Password: ')
    
    # Execute the requested command
    if args.command == 'set':
        manager.set_secret(args.key, args.value, password)
        print(f"Secret '{args.key}' set successfully.", file=sys.stderr)
    
    elif args.command == 'get':
        value = manager.get_secret(args.key, password)
        if value is None:
            print(f"No secret found with key '{args.key}'", file=sys.stderr)
            sys.exit(1)
        else:
            sys.stdout.write(value)
            if not args.no_newline:
                sys.stdout.write('\n')
    
    elif args.command == 'list':
        secrets = manager.list_secrets(password)
        if args.json:
            print(json.dumps(secrets))
        else:
            if not secrets:
                print("No secrets stored.", file=sys.stderr)
            else:
                print("Stored secrets:")
                for key in secrets:
                    print(f"  {key}")
    
    elif args.command == 'delete':
        if manager.delete_secret(args.key, password):
            print(f"Secret '{args.key}' deleted successfully.", file=sys.stderr)
        else:
            print(f"No secret found with key '{args.key}'", file=sys.stderr)
            sys.exit(1)
    
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()
