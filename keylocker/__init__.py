# keylocker/__init__.py

import os
import sys
import base64
import yaml # Added
import fire
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# --- Configuration ---
DEFAULT_KEY_FILE = 'storage.key'
ENV_VAR_NAME = 'KEYLOCKER_SECRET_KEY' # Environment variable for the key

# --- Helper Function for Key Loading ---

def _load_fernet_key(key_file=DEFAULT_KEY_FILE):
    """
    Loads the Fernet key, prioritizing the environment variable.
    Returns the key as bytes or None on error.
    """
    key_from_env = os.environ.get(ENV_VAR_NAME)

    if key_from_env:
        print(f"INFO: Using encryption key from environment variable {ENV_VAR_NAME}.")
        try:
            # Assume the key in the env var is the correct base64 encoded string
            key_bytes = key_from_env.encode('utf-8')
            # Validate the key by attempting to initialize Fernet
            Fernet(key_bytes)
            return key_bytes
        except (InvalidToken, ValueError, TypeError):
             print(f"ERROR: Invalid key format found in environment variable {ENV_VAR_NAME}.")
             return None
        except Exception as e:
             print(f"ERROR: Unexpected error validating key from env var {ENV_VAR_NAME}: {e}")
             return None

    else:
        # Environment variable not set, try the key file
        # Suppress message if key file is the default and doesn't exist during certain operations
        # print(f"INFO: Environment variable {ENV_VAR_NAME} not set. Trying key file '{key_file}'.")
        if not os.path.exists(key_file):
            # It's okay if the file doesn't exist initially for 'init' command,
            # but other commands will fail later if no key is found.
            # Errors will be handled by the calling functions if no key is ultimately loaded.
            return None # Indicate no key found *from file*
        try:
            with open(key_file, 'rb') as kf:
                key_bytes = kf.read()
            # Validate the key from the file
            Fernet(key_bytes)
            return key_bytes
        except FileNotFoundError:
             # Should not happen due to os.path.exists check, but included for safety
             print(f"ERROR: Key file '{key_file}' not found.")
             return None
        except (InvalidToken, ValueError, TypeError):
             print(f"ERROR: Invalid key format in file '{key_file}'.")
             return None
        except IOError as e:
            print(f"ERROR: Could not read key file '{key_file}': {e}")
            return None
        except Exception as e:
             print(f"ERROR: Unexpected error reading key file '{key_file}': {e}")
             return None

# --- YAML Tag Handling ---

# Custom class to represent secrets before saving (for the dumper)
class SecureString(str):
    pass

# Custom class to represent env vars before saving (for the dumper)
class EnvVariable(str):
    pass

# Loader: Decrypt !SEC tags, Resolve !ENV tags
def keylocker_loader(key_file=DEFAULT_KEY_FILE):
    """Creates a YAML Loader that handles !SEC and !ENV tags."""
    key_bytes = _load_fernet_key(key_file)
    if not key_bytes:
        # Error message is handled by _load_fernet_key or subsequent checks
        # We need to proceed to allow yaml.load to potentially fail gracefully
        # or let the calling function handle the None key case.
        # Returning None here would prevent loading YAML even with no secrets.
        print("WARNING: No encryption key loaded. !SEC tags cannot be decrypted.")
        fernet = None # Set fernet to None if no key
    else:
        try:
            fernet = Fernet(key_bytes)
        except Exception as e:
            print(f"ERROR: Failed to initialize Fernet with the loaded key: {e}")
            fernet = None # Treat as no key if init fails

    class KeylockerLoader(yaml.SafeLoader):
        pass

    def sec_constructor(loader, node):
        value = loader.construct_scalar(node)
        if fernet is None:
            print(f"ERROR: Cannot decrypt !SEC value as no valid key is loaded.")
            return f"DECRYPTION_ERROR[NoKey]"
        try:
            decrypted_value = fernet.decrypt(value.encode()).decode()
            return decrypted_value
        except InvalidToken:
            print(f"ERROR: Failed to decrypt value tagged !SEC. Invalid token or key mismatch.")
            return f"DECRYPTION_ERROR[InvalidToken]"
        except Exception as e:
            print(f"ERROR: Unexpected error during !SEC decryption: {e}")
            return f"DECRYPTION_ERROR[{type(e).__name__}]"

    def env_constructor(loader, node):
        var_name = loader.construct_scalar(node)
        value = os.environ.get(var_name)
        if value is None:
            print(f"WARNING: Environment variable '{var_name}' (tagged !ENV) not found. Returning None.")
        return value # Return the raw value from env or None

    KeylockerLoader.add_constructor('!SEC', sec_constructor)
    KeylockerLoader.add_constructor('!ENV', env_constructor)
    return KeylockerLoader

# Dumper: Encrypt SecureString, Format EnvVariable
def keylocker_dumper(key_file=DEFAULT_KEY_FILE):
    """Creates a YAML Dumper that handles SecureString and EnvVariable."""
    key_bytes = _load_fernet_key(key_file)
    if not key_bytes:
        print("WARNING: No encryption key loaded. Cannot encrypt values for !SEC tags.")
        fernet = None
    else:
        try:
            fernet = Fernet(key_bytes)
        except Exception as e:
            print(f"ERROR: Failed to initialize Fernet with the loaded key: {e}")
            fernet = None

    class KeylockerDumper(yaml.SafeDumper):
        pass

    def sec_representer(dumper, data):
         if fernet is None:
             print("ERROR: Cannot represent SecureString as !SEC: No valid key loaded.")
             # Represent as plain string with a warning prefix maybe?
             return dumper.represent_scalar('tag:yaml.org,2002:str', f"ENCRYPTION_ERROR[NoKey]: {data}")
         try:
            encrypted_value = fernet.encrypt(str(data).encode()).decode()
            # Use style='|' for literal block scalar automatically if multiline,
            # otherwise default (usually plain scalar)
            style = '|' if '\n' in encrypted_value else None
            return dumper.represent_scalar('!SEC', encrypted_value, style=style)
         except Exception as e:
            print(f"ERROR: Failed to encrypt SecureString: {e}")
            return dumper.represent_scalar('tag:yaml.org,2002:str', f"ENCRYPTION_ERROR[{type(e).__name__}]: {data}")


    def env_representer(dumper, data):
         return dumper.represent_scalar('!ENV', str(data))

    KeylockerDumper.add_representer(SecureString, sec_representer)
    KeylockerDumper.add_representer(EnvVariable, env_representer)
    return KeylockerDumper

# --- Core Functions ---

def load_yaml_secrets(file_path, key_file=DEFAULT_KEY_FILE):
    """Loads YAML, decrypting !SEC and resolving !ENV."""
    try:
        with open(file_path, 'r') as f:
            # Pass the custom loader initialized with the key file path (for fallback)
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

def encrypt_string_value(value_to_encrypt, key_file=DEFAULT_KEY_FILE):
    """Encrypts a string and returns the !SEC tagged value."""
    key_bytes = _load_fernet_key(key_file)
    if not key_bytes:
        print("ERROR: Failed to load a valid encryption key for encryption.")
        return None # Indicate failure
    try:
        fernet = Fernet(key_bytes)
        encrypted = fernet.encrypt(str(value_to_encrypt).encode()).decode()
        # Return the full tag representation ready for YAML
        return f"!SEC {encrypted}"
    except Exception as e:
         print(f"ERROR: An unexpected error occurred during encryption: {e}")
         return None

# --- CLI Manager ---

class Manager(object):
    def __init__(self, key_file=DEFAULT_KEY_FILE):
        # Store the key file path mainly for the 'init' command
        self.key_file = key_file

    def _check_key_available(self):
         """Checks if an encryption key is available via env var or file."""
         key_bytes = _load_fernet_key(self.key_file)
         if not key_bytes:
              print(f"ERROR: No valid encryption key found.")
              print(f"Ensure {ENV_VAR_NAME} environment variable is set,")
              print(f"or run 'keylocker init' to create '{self.key_file}'.")
              return False
         return True # Key is available

    def init(self, force=False):
        """
        Initializes storage by generating the master key file.
        This command ALWAYS interacts with the key FILE, not the env var.
        """
        key_path = self.key_file
        env_key_set = os.environ.get(ENV_VAR_NAME)

        if os.path.exists(key_path) and not force:
            print(f"Key file '{key_path}' already exists.")
            if env_key_set:
                print(f"Note: Environment variable {ENV_VAR_NAME} is set and will take precedence over this file for operations.")
            print("Use --force to overwrite the file.")
            return f"Key file '{key_path}' already exists."

        print(f"Generating new key file: '{key_path}'...")
        # Using Fernet's key generation directly is simpler and sufficient
        key = Fernet.generate_key() # This key is already base64 encoded bytes

        try:
            with open(key_path, 'wb') as f:
                f.write(key)
            print(f"Successfully created key file: '{key_path}'")
            if env_key_set:
                print(f"Note: Environment variable {ENV_VAR_NAME} is set and will take precedence over this file for operations.")
            return f"Key file '{key_path}' created."
        except IOError as e:
            print(f"ERROR: Could not write key file '{key_path}': {e}")
            sys.exit(996)

    def encrypt(self, value):
        """Encrypts a string value using the key and prints the !SEC tag."""
        if not self._check_key_available():
            sys.exit(1) # Exit if no key
        encrypted_tag = encrypt_string_value(value, self.key_file)
        if encrypted_tag:
             print("Add the following line to your YAML file:")
             print(encrypted_tag)
        else:
             # Error message already printed by encrypt_string_value or _load_fernet_key
             sys.exit(1) # Exit with error code

    def view(self, yaml_file):
        """Loads, decrypts (!SEC), resolves (!ENV) a YAML file and prints it."""
        # _check_key_available is implicitly called by load_yaml_secrets -> keylocker_loader -> _load_fernet_key
        # No need to call it explicitly here unless we want the error message earlier.
        data = load_yaml_secrets(yaml_file, self.key_file)
        if data is not None:
             # Dump back to YAML string for viewing (without custom tags, values resolved)
             # Use standard SafeDumper for output
             print(yaml.dump(data, Dumper=yaml.SafeDumper, default_flow_style=False, sort_keys=False, allow_unicode=True))
        else:
            # Error messages were likely printed during loading
            sys.exit(1) # Exit with error code if loading failed

# --- Main execution ---

def main():
    # Pass Manager class directly to Fire
    fire.Fire(Manager, name='keylocker')

if __name__ == "__main__":
    main()