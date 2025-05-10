# keylocker/__init__.py

import os
import sys
import base64
import yaml
import fire
import hvac
import hvac.exceptions

from cryptography.fernet import Fernet, InvalidToken

# --- Configuration ---
DEFAULT_KEY_FILE = 'storage.key'
ENV_VAR_NAME = 'KEYLOCKER_SECRET_KEY'

VAULT_ADDR_ENV_VAR = 'VAULT_ADDR'
VAULT_TOKEN_ENV_VAR = 'VAULT_TOKEN'

# --- Custom Exceptions ---
class KeylockerError(Exception):
    """Base class for exceptions in this module."""
    pass

class KeylockerFileError(KeylockerError):
    """Custom error for file-related issues in Keylocker."""
    pass

class KeylockerEncryptionError(KeylockerError):
    """Base class for encryption/decryption related errors."""
    pass

class KeylockerConfigError(KeylockerError):
    """For general configuration errors."""
    pass

class KeylockerVaultError(KeylockerError):
    """Base class for Vault related errors."""
    pass

class VaultClientNotInitializedError(KeylockerVaultError):
    """Raised when Vault client is not initialized or authentication fails."""
    pass

class VaultInvalidFormatError(KeylockerVaultError):
    """Raised for invalid !VAULT tag format."""
    pass

class VaultSecretNotFoundError(KeylockerVaultError):
    """Raised when a secret is not found in Vault or data is empty."""
    pass

class VaultKeyNotFoundError(KeylockerVaultError):
    """Raised when a key is not found within a Vault secret."""
    pass

class VaultInvalidPathError(KeylockerVaultError): # Renamed from Keylocker specific to general Vault
    """Raised for an invalid secret path in Vault, wraps hvac.exceptions.InvalidPath."""
    pass

class VaultPermissionError(KeylockerVaultError): # Renamed
    """Raised when permission is denied for a Vault secret, wraps hvac.exceptions.Forbidden."""
    pass

class VaultGenericClientError(KeylockerVaultError): # Renamed
    """Raised for other hvac.exceptions.VaultError during client operations."""
    pass

# --- Helper Function for Fernet Key Loading ---
def _load_fernet_key(key_file_path=DEFAULT_KEY_FILE):
    """
    Loads the Fernet key, prioritizing the environment variable.
    Returns the key as bytes.
    Raises KeylockerEncryptionError or KeylockerFileError on error.
    """
    key_from_env = os.environ.get(ENV_VAR_NAME)

    if key_from_env:
        print(f"INFO: Using encryption key from environment variable {ENV_VAR_NAME}.")
        try:
            key_bytes = key_from_env.encode('utf-8')
            Fernet(key_bytes) # Validate key format
            return key_bytes
        except (InvalidToken, ValueError, TypeError) as e:
            raise KeylockerEncryptionError(
                f"Invalid key format in environment variable {ENV_VAR_NAME}. Details: {e}"
            ) from e
        except Exception as e: # Should be rare
            raise KeylockerEncryptionError(
                f"Unexpected error validating Fernet key from env var {ENV_VAR_NAME}: {e}"
            ) from e
    else:
        if not os.path.exists(key_file_path):
            # This is a common case if the key file is expected but not found.
            # It's not an error if 'init' hasn't been run, but if a key is *needed*, it is.
            raise KeylockerFileError(f"Fernet key file '{key_file_path}' not found and {ENV_VAR_NAME} is not set.")
        try:
            with open(key_file_path, 'rb') as kf:
                key_bytes = kf.read()
            Fernet(key_bytes) # Validate key format
            return key_bytes
        except FileNotFoundError: # Should have been caught by os.path.exists, but defensive
            raise KeylockerFileError(f"Fernet key file '{key_file_path}' could not be opened (not found).") from None
        except (InvalidToken, ValueError, TypeError) as e:
            raise KeylockerEncryptionError(f"Invalid key format in Fernet key file '{key_file_path}'. Details: {e}") from e
        except IOError as e:
            raise KeylockerFileError(f"Could not read Fernet key file '{key_file_path}'. Details: {e}") from e
        except Exception as e: # Should be rare
            raise KeylockerEncryptionError(f"Unexpected error reading Fernet key file '{key_file_path}': {e}") from e

# --- Helper Function for Vault Client ---
def _get_vault_client():
    """
    Initializes and returns an authenticated HVAC client for HashiCorp Vault.
    Raises VaultClientNotInitializedError if configuration is missing or authentication fails.
    """
    vault_addr = os.environ.get(VAULT_ADDR_ENV_VAR)
    if not vault_addr:
        # This is a configuration error if !VAULT tags are to be used.
        # The vault_constructor will check if vault_hvac_client is None.
        # Let's make this function always return a client or raise an error.
        raise VaultClientNotInitializedError(
            f"Vault address environment variable '{VAULT_ADDR_ENV_VAR}' not set."
        )

    try:
        client = hvac.Client(url=vault_addr)
        vault_token = os.environ.get(VAULT_TOKEN_ENV_VAR)

        if not vault_token: # Assuming token auth for now
            raise VaultClientNotInitializedError(
                f"Vault token environment variable '{VAULT_TOKEN_ENV_VAR}' not set (token authentication assumed)."
            )
        client.token = vault_token

        if client.is_authenticated():
            print(f"INFO: Successfully authenticated to Vault at {vault_addr}.")
            return client
        else:
            raise VaultClientNotInitializedError(
                f"Failed to authenticate to Vault at {vault_addr} with the provided token. Check token and Vault policies."
            )
    except hvac.exceptions.VaultError as e: # Covers connection errors, etc.
        raise VaultClientNotInitializedError(f"Vault client setup/connection error for {vault_addr}: {e}") from e
    except Exception as e: # Other unexpected errors during client init
        raise VaultClientNotInitializedError(f"Unexpected error initializing Vault client for {vault_addr}: {e}") from e

# --- YAML Tag Handling ---
class SecureString(str): pass
class EnvVariable(str): pass

def keylocker_loader(key_file_path=DEFAULT_KEY_FILE): # Renamed arg for clarity
    """
    Creates a YAML Loader that handles !SEC, !ENV, and !VAULT tags.
    Raises exceptions from _load_fernet_key or _get_vault_client if setup fails.
    """
    fernet_cipher = None
    try:
        # Attempt to load Fernet key. If not found and !SEC is used, sec_constructor will fail.
        # If key is invalid, _load_fernet_key will raise KeylockerEncryptionError.
        loaded_fernet_key_bytes = _load_fernet_key(key_file_path)
        fernet_cipher = Fernet(loaded_fernet_key_bytes)
    except KeylockerFileError: # Fernet key file not found, and no env var
        # This is not necessarily an error for the loader if no !SEC tags are present.
        # sec_constructor will raise an error if fernet_cipher is None and a !SEC tag is encountered.
        print(f"INFO: Fernet key file '{key_file_path}' not found and {ENV_VAR_NAME} not set. !SEC tags will fail if used.")
        fernet_cipher = None
    except KeylockerEncryptionError as e:
        # Key was found but is invalid/unusable. This is a more severe config error.
        raise KeylockerConfigError(f"Failed to initialize Fernet cipher due to key error: {e}. !SEC tags cannot be processed.") from e

    vault_hvac_client = None
    # Пытаемся инициализировать клиент Vault, только если VAULT_ADDR установлен
    if os.environ.get(VAULT_ADDR_ENV_VAR): # Проверяем, что переменная установлена и имеет значение
        try:
            vault_hvac_client = _get_vault_client()
        except VaultClientNotInitializedError:
            # Если _get_vault_client() не смог инициализировать/аутентифицировать клиент,
            # позволяем этому исключению всплыть дальше.
            # Сообщение об ошибке от _get_vault_client() будет более информативным.
            raise
    else:
        # VAULT_ADDR не установлен. vault_hvac_client остается None.
        # vault_constructor обработает это, если встретит тег !VAULT.
        print(f"INFO: Environment variable '{VAULT_ADDR_ENV_VAR}' is not set. "
              f"Vault client will not be initialized. !VAULT tags will fail if used.")

    class KeylockerLoader(yaml.SafeLoader): pass

    def sec_constructor(loader, node):
        value = loader.construct_scalar(node)
        if fernet_cipher is None:
            raise KeylockerEncryptionError(
                f"Cannot decrypt !SEC value: Fernet encryption cipher not available. "
                f"Ensure key file '{key_file_path}' exists or {ENV_VAR_NAME} is set correctly."
            )
        try:
            return fernet_cipher.decrypt(value.encode()).decode()
        except InvalidToken:
            raise KeylockerEncryptionError(f"Failed to decrypt !SEC value: Invalid token or key mismatch (value: '{value[:15]}...').")
        except Exception as e:
            raise KeylockerEncryptionError(f"Unexpected error during !SEC decryption: {e}")

    def env_constructor(loader, node):
        var_name = loader.construct_scalar(node)
        value = os.environ.get(var_name)
        if value is None:
            # Option: raise KeylockerConfigError(f"Environment variable '{var_name}' for !ENV tag not found.")
            print(f"WARNING: Environment variable '{var_name}' (tagged !ENV) not found. Resolving to None.", file=sys.stderr)
        return value

    def vault_constructor(loader, node):
        if vault_hvac_client is None:
            raise VaultClientNotInitializedError(
                f"Vault client not available for !VAULT tag. Ensure {VAULT_ADDR_ENV_VAR} and auth variables are correctly set and client initialized."
            )
        # No need to check is_authenticated here if _get_vault_client guarantees it or raises an error.

        value_str = loader.construct_scalar(node)
        parts = value_str.split(':', 1)
        if len(parts) != 2:
            raise VaultInvalidFormatError(f"Invalid !VAULT format '{value_str}'. Expected 'path/to/secret:key_in_secret'.")

        secret_path, secret_key = parts[0], parts[1]
        response_data = None # Инициализируем

        # Блок try-except только для взаимодействия с клиентом hvac
        try:
            # print(f"INFO: Reading secret from Vault. Path: '{secret_path}', Key: '{secret_key}'") # Меньше INFO
            response_data = vault_hvac_client.secrets.kv.v2.read_secret_version(path=secret_path, raise_on_deleted_version=True)
        except hvac.exceptions.InvalidPath as e:
            raise VaultInvalidPathError(f"Invalid path for secret in Vault: '{secret_path}'. Details: {e}") from e
        except hvac.exceptions.Forbidden as e:
            raise VaultPermissionError(f"Permission denied for secret in Vault: '{secret_path}'. Check Vault ACL policies. Details: {e}") from e
        except hvac.exceptions.VaultError as e: # Другие ошибки клиента Vault (например, 500, недоступность)
            raise VaultGenericClientError(f"Vault API error when reading secret '{secret_path}': {e}") from e
        except Exception as e: # Действительно неожиданные ошибки во время вызова hvac, не являющиеся hvac.exceptions.VaultError
            raise KeylockerVaultError(f"An unexpected low-level error occurred during Vault communication for path '{secret_path}': {type(e).__name__} - {e}") from e

        # Если вызов к Vault прошел без исключений hvac, обрабатываем ответ
        # Ошибки, возбуждаемые здесь, являются ошибками нашей логики парсинга ответа
        if response_data and 'data' in response_data and 'data' in response_data['data']:
            secret_data_map = response_data['data']['data']
            if secret_key in secret_data_map:
                return secret_data_map[secret_key]
            else:
                # Ключ не найден в полученных данных
                raise VaultKeyNotFoundError(f"Key '{secret_key}' not found in secret data at Vault path '{secret_path}'.")
        else:
            # Ответ от Vault получен, но его структура некорректна или данные отсутствуют
            raise VaultSecretNotFoundError(f"Secret data malformed or not found at Vault path '{secret_path}'. Response structure: {response_data}")


    KeylockerLoader.add_constructor('!SEC', sec_constructor)
    KeylockerLoader.add_constructor('!ENV', env_constructor)
    KeylockerLoader.add_constructor('!VAULT', vault_constructor)
    return KeylockerLoader

# Dumper
def keylocker_dumper(key_file_path=DEFAULT_KEY_FILE): # Renamed arg
    fernet_cipher = None
    try:
        loaded_fernet_key_bytes = _load_fernet_key(key_file_path)
        fernet_cipher = Fernet(loaded_fernet_key_bytes)
    except (KeylockerFileError, KeylockerEncryptionError) as e:
        # If key is not available/usable, dumper cannot encrypt.
        # This will be raised by sec_representer if called.
        # We can print a warning here, but sec_representer will be the one to raise if needed.
        print(f"WARNING: Fernet key not loaded for dumper (path: '{key_file_path}'): {e}. !SEC tags cannot be encrypted.", file=sys.stderr)
        fernet_cipher = None # Ensure it's None

    class KeylockerDumper(yaml.SafeDumper): pass

    def sec_representer(dumper, data: SecureString):
         if fernet_cipher is None:
             raise KeylockerEncryptionError(
                 f"Cannot represent SecureString as !SEC: Fernet encryption cipher not available. "
                 f"Ensure key file '{key_file_path}' exists or {ENV_VAR_NAME} is set correctly for dumping."
             )
         try:
            encrypted_value = fernet_cipher.encrypt(str(data).encode()).decode()
            style = '|' if '\n' in encrypted_value else None
            return dumper.represent_scalar('!SEC', encrypted_value, style=style)
         except Exception as e: # Should be rare if Fernet object is valid
            raise KeylockerEncryptionError(f"Failed to encrypt SecureString value: {e}") from e

    def env_representer(dumper, data: EnvVariable):
         return dumper.represent_scalar('!ENV', str(data)) # No encryption involved

    KeylockerDumper.add_representer(SecureString, sec_representer)
    KeylockerDumper.add_representer(EnvVariable, env_representer)
    return KeylockerDumper


# --- Core Functions ---
def load_yaml_secrets(file_path, key_file_path=DEFAULT_KEY_FILE): # Renamed arg
    """
    Loads YAML, decrypting !SEC, resolving !ENV and !VAULT.
    Raises relevant KeylockerError subclasses or yaml.YAMLError.
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = yaml.load(f, Loader=keylocker_loader(key_file_path))
        return data
    except FileNotFoundError as e:
        raise KeylockerFileError(f"Input YAML file not found: '{file_path}'") from e
    except (yaml.YAMLError, KeylockerError): # Includes all our custom errors
        raise # Propagate as is
    except Exception as e: # Catch any other unexpected low-level exceptions
        raise KeylockerError(f"An unexpected error occurred while loading YAML file '{file_path}': {type(e).__name__} - {e}") from e

def encrypt_string_value(value_to_encrypt, key_file_path=DEFAULT_KEY_FILE): # Renamed arg
    """
    Encrypts a string using the Fernet key.
    Returns the !SEC tagged string.
    Raises KeylockerEncryptionError or KeylockerFileError.
    """
    # _load_fernet_key will raise if key is not found/invalid
    key_bytes = _load_fernet_key(key_file_path)
    try:
        fernet = Fernet(key_bytes)
        encrypted = fernet.encrypt(str(value_to_encrypt).encode()).decode()
        return f"!SEC {encrypted}"
    except Exception as e: # Any error during Fernet ops
         raise KeylockerEncryptionError(f"Failed to encrypt string value: {e}") from e

# --- CLI Manager ---
class Manager(object):
    def __init__(self, key_file=DEFAULT_KEY_FILE): # 'key_file' is the name used by python-fire
        self.key_file_path = key_file # Use a more descriptive internal name

    def _ensure_key_available_for_encryption(self):
        """Ensures Fernet key is loaded, raises KeylockerError if not. For commands needing encryption."""
        try:
            _load_fernet_key(self.key_file_path) # Just to check availability and validity
        except (KeylockerFileError, KeylockerEncryptionError) as e:
            # Re-wrap for a more CLI-friendly top-level error for this specific check
            raise KeylockerConfigError(
                f"Fernet encryption key is not available or invalid. Cannot proceed. Details: {e}\n"
                f"Ensure {ENV_VAR_NAME} is set or run 'keylocker init' (for key file '{self.key_file_path}')."
            ) from e


    def init(self, force=False):
        """Initializes Fernet key file storage."""
        key_path = self.key_file_path
        env_key_set = os.environ.get(ENV_VAR_NAME)

        if os.path.exists(key_path) and not force:
            print(f"Fernet key file '{key_path}' already exists.")
            if env_key_set:
                print(f"Note: Environment variable {ENV_VAR_NAME} is set and will take precedence for !SEC operations.")
            print("Use --force to overwrite the Fernet key file.")
            return # Successful no-op

        try:
            print(f"Generating new Fernet key file: '{key_path}'...")
            key = Fernet.generate_key()
            with open(key_path, 'wb') as f:
                f.write(key)
            print(f"Successfully created Fernet key file: '{key_path}'")
            if env_key_set:
                print(f"Note: Environment variable {ENV_VAR_NAME} is set and will take precedence for !SEC operations.")
        except IOError as e:
            print(f"ERROR: Could not write Fernet key file '{key_path}': {e}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"ERROR: Unexpected error during Fernet key generation for '{key_path}': {e}", file=sys.stderr)
            sys.exit(1)


    def encrypt(self, value: str):
        """Encrypts a string value using the Fernet key and prints the !SEC tag."""
        try:
            self._ensure_key_available_for_encryption() # Will raise if key is bad
            encrypted_tag = encrypt_string_value(value, self.key_file_path)
            print("Add the following line to your YAML file for the encrypted value:")
            print(encrypted_tag)
        except (KeylockerConfigError, KeylockerEncryptionError) as e: # Catch errors from check or encryption
            print(f"ERROR: Encryption failed. {e}", file=sys.stderr)
            sys.exit(1)
        except Exception as e: # Catch-all for other unexpected errors
            print(f"ERROR: An unexpected error occurred during encryption: {type(e).__name__} - {e}", file=sys.stderr)
            sys.exit(1)


    def view(self, yaml_file: str):
        """Loads, decrypts (!SEC), and resolves (!ENV, !VAULT) a YAML file, then prints it."""
        print(f"Attempting to load and process YAML file: '{yaml_file}'...")
        try:
            data = load_yaml_secrets(yaml_file, self.key_file_path)
            print("\nProcessed YAML content:")
            print(yaml.dump(data, Dumper=yaml.SafeDumper, default_flow_style=False, sort_keys=False, allow_unicode=True))
        except KeylockerFileError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            sys.exit(1)
        except yaml.YAMLError as e:
            print(f"ERROR: Invalid YAML syntax in '{yaml_file}'.", file=sys.stderr)
            print(f"Details: {e}", file=sys.stderr)
            sys.exit(1)
        except KeylockerVaultError as e:
            print(f"ERROR: Vault secret processing failed in '{yaml_file}': {e}", file=sys.stderr)
            sys.exit(1)
        except KeylockerEncryptionError as e:
            print(f"ERROR: Encryption/decryption process failed in '{yaml_file}': {e}", file=sys.stderr)
            sys.exit(1)
        except KeylockerConfigError as e: # For errors like Fernet key setup during loader init
             print(f"ERROR: Configuration problem for '{yaml_file}': {e}", file=sys.stderr)
             sys.exit(1)
        except KeylockerError as e: # Other keylocker errors
            print(f"ERROR: Failed to process secrets in '{yaml_file}': {e}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"ERROR: An unexpected critical error occurred while viewing '{yaml_file}': {type(e).__name__} - {e}", file=sys.stderr)
            sys.exit(1)

def main():
    fire.Fire(Manager, name='keylocker')

if __name__ == "__main__":
    main()