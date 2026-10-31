# keylocker/__init__.py

import os
import sys
import getpass
import tempfile
import yaml
import fire
from cryptography.fernet import Fernet, InvalidToken

# --- Configuration ---
DEFAULT_KEY_FILE = 'storage.key'
ENV_VAR_NAME = 'KEYLOCKER_SECRET_KEY' # Environment variable for the key
KEY_FILE_MODE = 0o600

# --- Exceptions ---

class KeylockerError(Exception):
    """Base class for keylocker errors."""

class EncryptionError(KeylockerError):
    """A value could not be encrypted. Never carries the plaintext."""

class DecryptionError(KeylockerError):
    """A !SEC value could not be decrypted."""

# --- Diagnostics ---

def _log(message):
    """Diagnostics go to stderr so stdout stays clean for data (YAML, !SEC tags)."""
    print(message, file=sys.stderr)

# --- Helper Function for Key Loading ---

def _load_fernet_key(key_file=DEFAULT_KEY_FILE):
    """
    Loads the Fernet key, prioritizing the environment variable.
    Returns the key as bytes or None on error.
    """
    key_from_env = os.environ.get(ENV_VAR_NAME)

    if key_from_env:
        _log(f"INFO: Using encryption key from environment variable {ENV_VAR_NAME}.")
        try:
            # Assume the key in the env var is the correct base64 encoded string
            key_bytes = key_from_env.encode('utf-8')
            # Validate the key by attempting to initialize Fernet
            Fernet(key_bytes)
            return key_bytes
        except (InvalidToken, ValueError, TypeError):
             _log(f"ERROR: Invalid key format found in environment variable {ENV_VAR_NAME}.")
             return None
        except Exception as e:
             _log(f"ERROR: Unexpected error validating key from env var {ENV_VAR_NAME}: {e}")
             return None

    else:
        if not os.path.exists(key_file):
            # It's okay if the file doesn't exist initially for 'init' command,
            # but other commands will fail later if no key is found.
            return None # Indicate no key found *from file*
        try:
            with open(key_file, 'rb') as kf:
                key_bytes = kf.read()
            # Validate the key from the file
            Fernet(key_bytes)
            return key_bytes
        except FileNotFoundError:
             # Should not happen due to os.path.exists check, but included for safety
             _log(f"ERROR: Key file '{key_file}' not found.")
             return None
        except (InvalidToken, ValueError, TypeError):
             _log(f"ERROR: Invalid key format in file '{key_file}'.")
             return None
        except IOError as e:
            _log(f"ERROR: Could not read key file '{key_file}': {e}")
            return None
        except Exception as e:
             _log(f"ERROR: Unexpected error reading key file '{key_file}': {e}")
             return None

def _load_fernet(key_file):
    """Returns a Fernet instance for the available key, or None."""
    key_bytes = _load_fernet_key(key_file)
    if not key_bytes:
        return None
    try:
        return Fernet(key_bytes)
    except Exception as e:
        _log(f"ERROR: Failed to initialize Fernet with the loaded key: {e}")
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
    """
    Creates a YAML Loader that handles !SEC and !ENV tags.
    A !SEC value that cannot be decrypted raises DecryptionError.
    """
    fernet = _load_fernet(key_file)
    if fernet is None:
        _log("WARNING: No encryption key loaded. !SEC tags cannot be decrypted.")

    class KeylockerLoader(yaml.SafeLoader):
        pass

    def sec_constructor(loader, node):
        value = loader.construct_scalar(node)
        # str(node.start_mark) embeds a snippet of the source YAML, which may hold other secrets.
        position = f"line {node.start_mark.line + 1}, column {node.start_mark.column + 1}"
        if fernet is None:
            raise DecryptionError(
                f"Cannot decrypt !SEC value at {position}: no valid key is loaded."
            )
        try:
            return fernet.decrypt(value.encode()).decode()
        except InvalidToken:
            raise DecryptionError(
                f"Failed to decrypt !SEC value at {position}: invalid token or key mismatch."
            ) from None
        except Exception as e:
            raise DecryptionError(
                f"Unexpected error during !SEC decryption at {position}: {type(e).__name__}"
            ) from None

    def env_constructor(loader, node):
        var_name = loader.construct_scalar(node)
        value = os.environ.get(var_name)
        if value is None:
            _log(f"WARNING: Environment variable '{var_name}' (tagged !ENV) not found. Returning None.")
        return value # Return the raw value from env or None

    KeylockerLoader.add_constructor('!SEC', sec_constructor)
    KeylockerLoader.add_constructor('!ENV', env_constructor)
    return KeylockerLoader

# Dumper: Encrypt SecureString, Format EnvVariable
def keylocker_dumper(key_file=DEFAULT_KEY_FILE):
    """
    Creates a YAML Dumper that handles SecureString and EnvVariable.
    A SecureString that cannot be encrypted raises EncryptionError; it is
    never written out in plaintext.
    """
    fernet = _load_fernet(key_file)
    if fernet is None:
        _log("WARNING: No encryption key loaded. Cannot encrypt values for !SEC tags.")

    class KeylockerDumper(yaml.SafeDumper):
        pass

    def sec_representer(dumper, data):
        if fernet is None:
            raise EncryptionError("Cannot represent SecureString as !SEC: no valid key is loaded.")
        try:
            encrypted_value = fernet.encrypt(str(data).encode()).decode()
        except Exception as e:
            raise EncryptionError(f"Failed to encrypt SecureString: {type(e).__name__}") from None
        style = '|' if '\n' in encrypted_value else None
        return dumper.represent_scalar('!SEC', encrypted_value, style=style)

    def env_representer(dumper, data):
        return dumper.represent_scalar('!ENV', str(data))

    KeylockerDumper.add_representer(SecureString, sec_representer)
    KeylockerDumper.add_representer(EnvVariable, env_representer)
    return KeylockerDumper

# --- Core Functions ---

def load_yaml_secrets(file_path, key_file=DEFAULT_KEY_FILE):
    """
    Loads YAML, decrypting !SEC and resolving !ENV.
    Returns None if the file is missing or not valid YAML.
    Raises DecryptionError if any !SEC value cannot be decrypted.
    """
    try:
        with open(file_path, 'r') as f:
            return yaml.load(f, Loader=keylocker_loader(key_file))
    except KeylockerError:
        raise
    except FileNotFoundError:
        _log(f"ERROR: Input YAML file '{file_path}' not found.")
        return None
    except yaml.YAMLError as e:
        _log(f"ERROR: Failed to parse YAML file '{file_path}': {e}")
        return None
    except Exception as e:
        _log(f"ERROR: An unexpected error occurred during YAML load: {e}")
        return None

def encrypt_string_value(value_to_encrypt, key_file=DEFAULT_KEY_FILE):
    """Encrypts a string and returns the !SEC tagged value."""
    key_bytes = _load_fernet_key(key_file)
    if not key_bytes:
        _log("ERROR: Failed to load a valid encryption key for encryption.")
        return None # Indicate failure
    try:
        fernet = Fernet(key_bytes)
        encrypted = fernet.encrypt(str(value_to_encrypt).encode()).decode()
        # Return the full tag representation ready for YAML
        return f"!SEC {encrypted}"
    except Exception as e:
         _log(f"ERROR: An unexpected error occurred during encryption: {type(e).__name__}")
         return None

def _write_all(fd, data):
    while data:
        data = data[os.write(fd, data):]
    os.fsync(fd)

def _write_key_file(key_path, key, overwrite=False):
    """
    Writes the key readable by the owner only (0600 on POSIX), never following symlinks.
    Without overwrite, raises FileExistsError if anything (even a dangling symlink) is at key_path.
    With overwrite, the key is written to a private temp file and atomically renamed over
    key_path, which replaces a symlink itself rather than writing through it.
    """
    if not overwrite:
        flags = (os.O_WRONLY | os.O_CREAT | os.O_EXCL
                 | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0))
        fd = os.open(key_path, flags, KEY_FILE_MODE)
        try:
            _write_all(fd, key)
        except BaseException:
            os.close(fd)
            os.unlink(key_path)
            raise
        os.close(fd)
        return

    directory = os.path.dirname(os.path.abspath(key_path))
    fd, tmp_path = tempfile.mkstemp(dir=directory, prefix='.keylocker-', suffix='.tmp')
    try:
        try:
            _write_all(fd, key)
        finally:
            os.close(fd)
        os.replace(tmp_path, key_path)
    except BaseException:
        if os.path.lexists(tmp_path):
            os.unlink(tmp_path)
        raise

def _read_secret_interactively():
    """Reads a secret from piped stdin or from a hidden, confirmed prompt."""
    if not sys.stdin.isatty():
        value = sys.stdin.read()
        # Drop only the trailing newline added by `echo` / here-strings.
        if value.endswith('\n'):
            value = value[:-1]
            if value.endswith('\r'):
                value = value[:-1]
        return value
    value = getpass.getpass("Secret to encrypt: ")
    if getpass.getpass("Repeat secret: ") != value:
        _log("ERROR: Values do not match.")
        return None
    return value

# --- CLI Manager ---

class Manager(object):
    def __init__(self, key_file=DEFAULT_KEY_FILE):
        # Store the key file path mainly for the 'init' command
        self.key_file = key_file

    def _check_key_available(self):
         """Checks if an encryption key is available via env var or file."""
         key_bytes = _load_fernet_key(self.key_file)
         if not key_bytes:
              _log("ERROR: No valid encryption key found.")
              _log(f"Ensure {ENV_VAR_NAME} environment variable is set,")
              _log(f"or run 'keylocker init' to create '{self.key_file}'.")
              return False
         return True # Key is available

    def init(self, force=False):
        """
        Initializes storage by generating the master key file (mode 0600).
        This command ALWAYS interacts with the key FILE, not the env var.
        """
        key_path = self.key_file
        env_key_set = os.environ.get(ENV_VAR_NAME)

        def already_exists():
            _log(f"Key file '{key_path}' already exists.")
            if env_key_set:
                _log(f"Note: Environment variable {ENV_VAR_NAME} is set and will take precedence over this file for operations.")
            _log("Use --force to overwrite the file.")
            return f"Key file '{key_path}' already exists."

        if os.path.lexists(key_path) and not force:
            return already_exists()

        _log(f"Generating new key file: '{key_path}'...")
        key = Fernet.generate_key() # This key is already base64 encoded bytes

        try:
            _write_key_file(key_path, key, overwrite=force)
        except FileExistsError:
            return already_exists()
        except OSError as e:
            _log(f"ERROR: Could not write key file '{key_path}': {e}")
            sys.exit(996)
        _log(f"Successfully created key file: '{key_path}'")
        _log("Keep it out of version control and container images (.gitignore / .dockerignore).")
        if env_key_set:
            _log(f"Note: Environment variable {ENV_VAR_NAME} is set and will take precedence over this file for operations.")
        return f"Key file '{key_path}' created."

    def encrypt(self, value=None):
        """
        Encrypts a secret and prints the !SEC tag to stdout.
        Without VALUE the secret is read from stdin or a hidden prompt;
        passing it as an argument leaks it to shell history and the process list.
        """
        if not self._check_key_available():
            sys.exit(1) # Exit if no key
        if value is None:
            value = _read_secret_interactively()
            if value is None:
                sys.exit(1)
        else:
            _log("WARNING: Passing a secret as a command-line argument exposes it via shell history "
                 "and the process list. Prefer stdin or the interactive prompt.")
        if value == "":
            _log("ERROR: Refusing to encrypt an empty value.")
            sys.exit(1)
        encrypted_tag = encrypt_string_value(value, self.key_file)
        if encrypted_tag:
             _log("Add the following line to your YAML file:")
             print(encrypted_tag)
        else:
             # Error message already printed by encrypt_string_value or _load_fernet_key
             sys.exit(1) # Exit with error code

    def view(self, yaml_file):
        """Loads, decrypts (!SEC), resolves (!ENV) a YAML file and prints it."""
        try:
            data = load_yaml_secrets(yaml_file, self.key_file)
        except KeylockerError as e:
            _log(f"ERROR: {e}")
            sys.exit(1)
        if data is not None:
             # Dump back to YAML string for viewing (without custom tags, values resolved)
             print(yaml.dump(data, Dumper=yaml.SafeDumper, default_flow_style=False, sort_keys=False, allow_unicode=True), end='')
        else:
            # Error messages were likely printed during loading
            sys.exit(1) # Exit with error code if loading failed

# --- Main execution ---

def main():
    # Pass Manager class directly to Fire
    fire.Fire(Manager, name='keylocker')

if __name__ == "__main__":
    main()
