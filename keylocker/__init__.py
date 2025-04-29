import os
import sys
import base64
import yaml # Added
import fire
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# --- YAML Tag Handling ---

# Custom class to represent secrets before saving
class SecureString(str):
    pass

# Custom class to represent env vars before saving
class EnvVariable(str):
    pass

# Loader: Decrypt !SEC tags, Resolve !ENV tags
def keylocker_loader(key_file='storage.key'):
    try:
        with open(key_file, 'rb') as kf:
            key = kf.read()
        fernet = Fernet(key)
    except FileNotFoundError:
        print(f"ERROR: Key file '{key_file}' not found for decryption!")
        sys.exit(998)
    except (InvalidToken, ValueError, TypeError): # Catch potential Fernet init errors
         print(f"ERROR: Invalid key in '{key_file}'. Cannot initialize decryption.")
         sys.exit(997)

    class KeylockerLoader(yaml.SafeLoader):
        pass

    def sec_constructor(loader, node):
        value = loader.construct_scalar(node)
        try:
            decrypted_value = fernet.decrypt(value.encode()).decode()
            return decrypted_value
        except InvalidToken:
            print(f"ERROR: Failed to decrypt value tagged !SEC. Invalid token or key mismatch.")
            # Decide error handling: return placeholder, raise error, etc.
            return f"DECRYPTION_ERROR[InvalidToken]"
        except Exception as e:
            print(f"ERROR: Unexpected error during !SEC decryption: {e}")
            return f"DECRYPTION_ERROR[{type(e).__name__}]"

    def env_constructor(loader, node):
        var_name = loader.construct_scalar(node)
        value = os.environ.get(var_name)
        if value is None:
            print(f"WARNING: Environment variable '{var_name}' (tagged !ENV) not found. Returning None.")
            # Or raise an error: raise ValueError(f"!ENV variable '{var_name}' not set")
        return value # Return the raw value from env

    KeylockerLoader.add_constructor('!SEC', sec_constructor)
    KeylockerLoader.add_constructor('!ENV', env_constructor)
    return KeylockerLoader

# Dumper: Encrypt SecureString, Format EnvVariable
def keylocker_dumper(key_file='storage.key'):
    try:
        with open(key_file, 'rb') as kf:
            key = kf.read()
        fernet = Fernet(key)
    except FileNotFoundError:
         print(f"ERROR: Key file '{key_file}' not found for encryption!")
         sys.exit(998)
    except (InvalidToken, ValueError, TypeError):
         print(f"ERROR: Invalid key in '{key_file}'. Cannot initialize encryption.")
         sys.exit(997)

    class KeylockerDumper(yaml.SafeDumper):
        pass

    def sec_representer(dumper, data):
         encrypted_value = fernet.encrypt(str(data).encode()).decode()
         return dumper.represent_scalar('!SEC', encrypted_value)

    def env_representer(dumper, data):
         return dumper.represent_scalar('!ENV', str(data))

    KeylockerDumper.add_representer(SecureString, sec_representer)
    KeylockerDumper.add_representer(EnvVariable, env_representer)
    return KeylockerDumper

# --- Core Functions ---

def load_yaml_secrets(file_path, key_file='storage.key'):
    """Loads YAML, decrypting !SEC and resolving !ENV."""
    try:
        with open(file_path, 'r') as f:
            # Pass the custom loader initialized with the key file
            data = yaml.load(f, Loader=keylocker_loader(key_file))
        return data
    except FileNotFoundError:
        print(f"ERROR: Input YAML file '{file_path}' not found.")
        return None
    except yaml.YAMLError as e:
        print(f"ERROR: Failed to parse YAML file '{file_path}': {e}")
        return None
    except Exception as e:
        print(f"ERROR: An unexpected error occurred during YAML load: {e}")
        return None

def encrypt_string_value(value_to_encrypt, key_file='storage.key'):
    """Encrypts a string and returns the !SEC tagged value."""
    try:
        with open(key_file, 'rb') as kf:
            key = kf.read()
        fernet = Fernet(key)
        encrypted = fernet.encrypt(str(value_to_encrypt).encode()).decode()
        # Return the full tag representation ready for YAML
        return f"!SEC {encrypted}"
    except FileNotFoundError:
        print(f"ERROR: Key file '{key_file}' not found for encryption!")
        return None
    except (InvalidToken, ValueError, TypeError):
         print(f"ERROR: Invalid key in '{key_file}'. Cannot initialize encryption.")
         return None
    except Exception as e:
         print(f"ERROR: An unexpected error occurred during encryption: {e}")
         return None

# Note: Saving YAML with encrypted values requires representing the data
# correctly *before* calling yaml.dump (e.g., using SecureString).
# A full 'edit' command is more complex and not fully implemented here.

# --- CLI Manager ---

class Manager(object):
    def __init__(self, key_file='storage.key'):
        self.key_file = key_file
        # Check if key exists on init for relevant commands
        # self._check_key_exists() # Optional: Check early

    def _check_key_exists(self):
         if not os.path.exists(self.key_file):
              print(f"ERROR: Key file '{self.key_file}' not found.")
              print("Please run 'keylocker init' first.")
              sys.exit(998)

    def init(self, force=False):
        """Initializes storage and generates the master key file."""
        if os.path.exists(self.key_file) and not force:
            print(f"Key file '{self.key_file}' already exists.")
            print("Use --force to overwrite.")
            return f"Key file '{self.key_file}' already exists."

        print(f"Generating new key file: '{self.key_file}'...")
        # Using original key generation logic for consistency
        password = Fernet.generate_key() # Use a generated key as the 'password'
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000, # Keep iterations reasonable
            backend=default_backend()
        )
        # Derive a key and encode it for Fernet
        key = base64.urlsafe_b64encode(kdf.derive(password))

        try:
            with open(self.key_file, 'wb') as f:
                f.write(key)
            print(f"Successfully created key file: '{self.key_file}'")
            return f"Key file '{self.key_file}' created."
        except IOError as e:
            print(f"ERROR: Could not write key file '{self.key_file}': {e}")
            sys.exit(996)

    def encrypt(self, value):
        """Encrypts a string value using the key file and prints the !SEC tag."""
        self._check_key_exists()
        encrypted_tag = encrypt_string_value(value, self.key_file)
        if encrypted_tag:
             print("Add the following line to your YAML file:")
             print(encrypted_tag)
        else:
             # Error message already printed by encrypt_string_value
             sys.exit(1) # Exit with error code

    def view(self, yaml_file):
        """Loads, decrypts (!SEC), resolves (!ENV) a YAML file and prints it."""
        self._check_key_exists() # Needed for decryption
        data = load_yaml_secrets(yaml_file, self.key_file)
        if data is not None:
             # Dump back to YAML string for viewing (without custom tags)
             print(yaml.dump(data, Dumper=yaml.SafeDumper, default_flow_style=False, sort_keys=False))
        else:
            sys.exit(1) # Exit with error code if loading failed

    # --- Removed old methods ---
    # def write(self,key, value): ...
    # def remove(self,key): ...
    # def read(self,key): ...
    # def list(self): ...

def main():
    # Pass Manager class directly to Fire
    fire.Fire(Manager, name='keylocker')

if __name__ == "__main__":
    main()
