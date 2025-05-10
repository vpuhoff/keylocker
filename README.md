# Keylocker CLI (YAML Edition)
[![PyPI Downloads](https://img.shields.io/pypi/dm/keylocker)](https://pypi.org/project/keylocker/) [![Downloads](https://static.pepy.tech/badge/keylocker)](https://pepy.tech/project/keylocker)

A command-line interface (CLI) tool and Python library for managing secrets directly within YAML configuration files. Allows encrypting individual values using the `!SEC` tag, loading values from environment variables using the `!ENV` tag, and fetching secrets from HashiCorp Vault using the `!VAULT` tag.

* Wiki: [https://deepwiki.com/vpuhoff/keylocker](https://deepwiki.com/vpuhoff/keylocker/1-overview)

![Alt](https://repobeats.axiom.co/api/embed/61e3a712de309936dc034c3851dc1a6144d3b4dd.svg "Repobeats analytics image")

## Encryption Key (Fernet)

Keylocker uses a Fernet key for encrypting and decrypting `!SEC` tags. The key is obtained in the following order of priority:

1.  **`KEYLOCKER_SECRET_KEY` Environment Variable**: If this environment variable is set, its value is used directly as the Fernet key (it should be a valid base64 encoded key string).
2.  **`storage.key` File**: If the environment variable is not set, Keylocker attempts to read the key from the `storage.key` file in the current directory by default.

Use the `keylocker init` command to generate a `storage.key` file if you prefer file-based key storage. Note that if `KEYLOCKER_SECRET_KEY` is set, it will always take precedence over the file for `!SEC` encryption/decryption operations.

## HashiCorp Vault Configuration

To use the `!VAULT` tag, you need to configure access to your HashiCorp Vault instance via the following environment variables:
* **`VAULT_ADDR`**: The URL of your Vault instance (e.g., `http://127.0.0.1:8200`).
* **`VAULT_TOKEN`**: The token for authenticating with Vault. (Other authentication methods may be added in the future).

If these variables are not set, attempting to use a `!VAULT` tag will result in an error.

## Installation

You can install the package using pip. The `hvac` library will also be installed as a dependency for Vault support.

```bash
pip install keylocker
```

The package is available on PyPI: [https://pypi.org/project/keylocker/](https://pypi.org/project/keylocker/)

## Example YAML file (`config.yaml`):

```yaml
# config.yaml
database:
  host: db.example.com
  username: user
  # Encrypted password using 'keylocker encrypt'
  password: !SEC gAAAAABh...[rest_of_encrypted_data]...
api:
  endpoint: https://api.example.com
  # Load key from the API_KEY environment variable
  key: !ENV API_KEY
deployment:
  region: us-east-1
  # Secret from HashiCorp Vault (e.g., KV v2)
  # Path: 'your_kv_mount/data/path/to/secret', Key in secret: 'secret_key_name'
  vault_secret: !VAULT your_kv_mount/data/path/to/secret:secret_key_name
  # Another encrypted secret
  ssh_key_pass: !SEC gAAAAABh...[another_encrypted_data]...
```

## CLI Usage:

1.  **Initialization (create Fernet key file):**
    * Generates the `storage.key` file (if it doesn't exist). This file is used *only* if the `KEYLOCKER_SECRET_KEY` environment variable is *not* set.
    ```bash
    keylocker init [--force]
    ```

2.  **Encrypt value for YAML:**
    * Encrypts a string using the available Fernet key (from Environment Variable or Key File) and prints the `!SEC` tag for you to copy into your YAML file.
    ```bash
    keylocker encrypt "my_secret_value"
    # Output:
    # Add the following line to your YAML file:
    # !SEC gAAAAABh...[encrypted_data]...
    ```

3.  **View decrypted YAML:**
    * Loads the specified YAML file, resolves `!ENV` variables, decrypts `!SEC` values (using the Fernet key), and fetches `!VAULT` secrets (using Vault configuration), then prints the resulting YAML to standard output.
    ```bash
    # Set environment variables if your YAML uses !ENV
    export API_KEY="your_actual_api_key"
    # Set variables for Vault if your YAML uses !VAULT
    export VAULT_ADDR="http://127.0.0.1:8200"
    export VAULT_TOKEN="your_vault_token"
    # Set KEYLOCKER_SECRET_KEY if using it for !SEC
    # export KEYLOCKER_SECRET_KEY='your_base64_fernet_key'

    keylocker view config.yaml
    # Example output (values resolved/decrypted):
    # database:
    #   host: db.example.com
    #   username: user
    #   password: my_secret_value
    # api:
    #   endpoint: https://api.example.com
    #   key: your_actual_api_key
    # deployment:
    #   region: us-east-1
    #   vault_secret: value_from_vault
    #   ssh_key_pass: decrypted_pass
    ```
    *(Note: An `edit` command might be added in the future for interactive editing)*

## Usage in Python Code:

```python
import os
import yaml # For yaml.YAMLError
from keylocker import (
    load_yaml_secrets,
    KeylockerError, # Base keylocker error class
    KeylockerFileError,
    KeylockerEncryptionError,
    KeylockerVaultError
    # ... and other specific exceptions if you need to catch them separately
)

# Set environment variables if your YAML uses !ENV
os.environ['API_KEY'] = 'your_actual_api_key_for_python'

# Set variables for Vault if your YAML uses !VAULT
os.environ['VAULT_ADDR'] = 'http://127.0.0.1:8200' # Example
os.environ['VAULT_TOKEN'] = 'your_python_vault_token'

# Set KEYLOCKER_SECRET_KEY if using it for the !SEC encryption key
# os.environ['KEYLOCKER_SECRET_KEY'] = 'your_base64_encoded_fernet_key'
# Alternatively, ensure 'storage.key' exists if KEYLOCKER_SECRET_KEY is not set

config_file = 'config.yaml'
# The key_file_path parameter is used if KEYLOCKER_SECRET_KEY is not set
key_file_path = 'storage.key' # Default path

try:
    # Automatically load, resolve !ENV, !VAULT, and decrypt !SEC
    secrets = load_yaml_secrets(config_file, key_file_path=key_file_path)

    if secrets:
        db_password = secrets.get('database', {}).get('password')
        api_key_from_env = secrets.get('api', {}).get('key')
        vault_secret_value = secrets.get('deployment', {}).get('vault_secret')

        print(f"Database Password (from Python): {db_password}")
        print(f"API Key (from Python): {api_key_from_env}")
        print(f"Vault Secret (from Python): {vault_secret_value}")

except KeylockerFileError as e:
    print(f"File error: {e}")
except KeylockerEncryptionError as e:
    print(f"Encryption/Decryption error: {e}")
except KeylockerVaultError as e:
    print(f"Vault error: {e}")
except KeylockerError as e: # General keylocker error
    print(f"Keylocker processing error: {e}")
except yaml.YAMLError as e:
    print(f"YAML parsing error: {e}")
except Exception as e: # Any other unexpected errors
    print(f"An unexpected error occurred: {type(e).__name__} - {e}")
```

## Usage in Bash:

To extract specific values from the resolved/decrypted YAML for use in scripts.

```bash
#!/bin/bash

# Set environment variables if your YAML uses !ENV
export API_KEY="your_bash_api_key"

# Set variables for Vault if your YAML uses !VAULT
export VAULT_ADDR="http://127.0.0.1:8200"
export VAULT_TOKEN="your_bash_vault_token"

# Set KEYLOCKER_SECRET_KEY if using it for the !SEC encryption key
# export KEYLOCKER_SECRET_KEY='your_base64_encoded_fernet_key'

# Get the decrypted YAML content
# Redirect stderr to /dev/null if you don't want to see keylocker's INFO/WARNING messages
CONFIG_YAML=$(keylocker view config.yaml 2>/dev/null)

# Check if the command executed successfully
if [ $? -ne 0 ]; then
  echo "Error executing keylocker view. Check stderr for details from keylocker."
  # To see errors from keylocker if any, run without 2>/dev/null
  # keylocker view config.yaml
  exit 1
fi

# Example extraction using yq (requires yq installation)
# DB_PASS=$(echo "$CONFIG_YAML" | yq e '.database.password' -)
# API_KEY_FROM_YAML=$(echo "$CONFIG_YAML" | yq e '.api.key' -)
# VAULT_SECRET_FROM_YAML=$(echo "$CONFIG_YAML" | yq e '.deployment.vault_secret' -)


# Example extraction using grep/awk (less robust, sensitive to formatting)
# This method may not work correctly for multi-line or complex values.
DB_PASS=$(echo "$CONFIG_YAML" | grep -A 2 'database:' | grep 'password:' | awk '{print $NF}')
API_KEY_FROM_YAML=$(echo "$CONFIG_YAML" | grep -A 2 'api:' | grep 'key:' | awk '{print $NF}')
VAULT_SECRET_FROM_YAML=$(echo "$CONFIG_YAML" | grep -A 2 'deployment:' | grep 'vault_secret:' | awk '{print $NF}')


echo "Extracted DB Password (from Bash): $DB_PASS"
echo "Extracted API Key (from Bash): $API_KEY_FROM_YAML"
echo "Extracted Vault Secret (from Bash): $VAULT_SECRET_FROM_YAML"

# Further use of variables in your script
# e.g., ./deploy_script.sh --db-password "$DB_PASS" --api-key "$API_KEY_FROM_YAML"
```

## Source Code:

  * [https://github.com/vpuhoff/keylocker](https://github.com/vpuhoff/keylocker)
  * [https://deepwiki.com/vpuhoff/keylocker](https://deepwiki.com/vpuhoff/keylocker/1-overview)

-----