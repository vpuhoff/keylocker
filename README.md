# Keylocker CLI (YAML Edition)
[![PyPI Downloads](https://img.shields.io/pypi/dm/keylocker)](https://pypi.org/project/keylocker/) [![Downloads](https://static.pepy.tech/badge/keylocker)](https://pepy.tech/project/keylocker)
[![codecov](https://codecov.io/github/vpuhoff/keylocker/graph/badge.svg?token=9VTMTGHPX1)](https://codecov.io/github/vpuhoff/keylocker)

A command-line interface (CLI) tool and Python library for managing secrets directly within YAML configuration files. Allows encrypting individual values using the `!SEC` tag and loading values from environment variables using the `!ENV` tag.

* Wiki: [https://deepwiki.com/vpuhoff/keylocker](https://deepwiki.com/vpuhoff/keylocker/1-overview)

![Alt](https://repobeats.axiom.co/api/embed/61e3a712de309936dc034c3851dc1a6144d3b4dd.svg "Repobeats analytics image")

## Encryption Key

Keylocker uses a Fernet key for encryption and decryption. The key is obtained in the following order of priority:

1.  **`KEYLOCKER_SECRET_KEY` Environment Variable:** If this environment variable is set, its value is used directly as the Fernet key (it should be a valid base64 encoded key).
2.  **`storage.key` File:** If the environment variable is not set, Keylocker attempts to read the key from the `storage.key` file in the current directory by default.

Use the `keylocker init` command to generate a `storage.key` file if you prefer file-based key storage. Note that if `KEYLOCKER_SECRET_KEY` is set, it will always take precedence over the file for encryption/decryption operations.

`keylocker init` creates `storage.key` readable by its owner only (mode `0600` on Linux/macOS). Never commit it or bake it into container images: add `storage.key` to both `.gitignore` and `.dockerignore`, and prefer `KEYLOCKER_SECRET_KEY` injected at runtime in CI and containers.

## Installation

You can install the package using pip:

```bash
pip install keylocker
```

The package is available on PyPI: [https://pypi.org/project/keylocker/](https://pypi.org/project/keylocker/)

Runtime dependencies are declared in `pyproject.toml` and installed automatically
by pip. `Pipfile` and both requirements files use the same supported ranges;
`Pipfile.lock` records exact versions for reproducible development and CI.
Tests check these declarations for drift, and CI smoke-tests the built wheel
in a fresh virtualenv without Pipenv or an editable source install.

## Example YAML file (`config.yaml`):

```yaml
# config.yaml
database:
  host: db.example.com
  username: user
  # Encrypted password using 'keylocker encrypt'
  password: !SEC gAAAAABh...[rest of encrypted data]...
api:
  endpoint: [https://api.example.com](https://api.example.com)
  # Load key from the API_KEY environment variable
  key: !ENV API_KEY
deployment:
  region: us-east-1
  # Another secret
  ssh_key_pass: !SEC gAAAAABh...[another encrypted data]...
```

## CLI Usage:

1.  **Initialization (create key file):**
    * Generates the `storage.key` file (if it doesn't exist). This file is used *only* if the `KEYLOCKER_SECRET_KEY` environment variable is *not* set.
    ```bash
    keylocker init [--force]
    ```

2.  **Encrypt value for YAML:**
    * Encrypts a string using the available key (Environment Variable or Key File) and prints the `!SEC` tag to stdout for you to copy into your YAML file. Hints and diagnostics go to stderr.
    * Without an argument the secret is read from stdin, or from a hidden prompt (entered twice) when run in a terminal. Avoid passing the secret as an argument: it ends up in shell history and is visible in the process list.
    ```bash
    keylocker encrypt
    # Secret to encrypt:
    # Repeat secret:
    # Add the following line to your YAML file:
    # !SEC gAAAAABh...[encrypted data]...

    # Non-interactive (one trailing newline is stripped):
    printf '%s' "$DB_PASSWORD" | keylocker encrypt
    ```

3.  **View decrypted YAML:**
    * Loads the specified YAML file, resolves `!ENV` variables, decrypts `!SEC` values using the available key (Environment Variable or Key File), and prints the resulting YAML to standard output. Only YAML is written to stdout, so it can be piped into `yq`. If any `!SEC` value cannot be decrypted, nothing is printed and the command exits with code 1.
    ```bash
    # Set environment variables if your YAML uses !ENV
    export API_KEY="your_actual_api_key"

    keylocker view config.yaml
    # Example output (values resolved/decrypted):
    # database:
    #   host: db.example.com
    #   username: user
    #   password: my_secret_value
    # api:
    #   endpoint: [https://api.example.com](https://api.example.com)
    #   key: your_actual_api_key
    # deployment:
    #   region: us-east-1
    #   ssh_key_pass: decrypted_pass
    ```
    *(Note: An `edit` command might be added in the future for interactive editing)*

## Usage in Python Code:

```python
import os
from keylocker import load_yaml_secrets, DecryptionError

# Set environment variables if your YAML uses !ENV
os.environ['API_KEY'] = 'your_actual_api_key_for_python'
# Set KEYLOCKER_SECRET_KEY if using env var for the encryption key
# os.environ['KEYLOCKER_SECRET_KEY'] = 'your_base64_encoded_fernet_key'

config_file = 'config.yaml'
# The key_file parameter acts as a fallback if KEYLOCKER_SECRET_KEY is not set
key_file_path = 'storage.key'

try:
    # Load, resolve !ENV, and decrypt !SEC automatically
    secrets = load_yaml_secrets(config_file, key_file_path)

    if secrets:
        db_password = secrets.get('database', {}).get('password')
        api_key = secrets.get('api', {}).get('key')

        print(f"Database Password (from Python): {db_password}")
        print(f"API Key (from Python): {api_key}")

except DecryptionError as e:
    # Raised when a !SEC value cannot be decrypted (no key, wrong key, corrupted value).
    # Never fall back to a placeholder value: fail closed.
    raise SystemExit(f"Cannot load secrets: {e}")

```

Writing YAML with `keylocker_dumper()` raises `EncryptionError` if a `SecureString` cannot be encrypted, so a secret is never written out in plaintext. Both exceptions inherit from `KeylockerError`.

## Usage in Bash:

To extract specific values from the resolved/decrypted YAML for use in scripts.

```bash
#!/bin/bash

# Set environment variables if your YAML uses !ENV
export API_KEY="your_bash_api_key"
# Set KEYLOCKER_SECRET_KEY if using env var for the encryption key
# export KEYLOCKER_SECRET_KEY='your_base64_encoded_fernet_key'

# Get the decrypted YAML content
CONFIG_YAML=$(keylocker view config.yaml)

# Check if the command executed successfully
if [ $? -ne 0 ]; then
  echo "Error executing keylocker view"
  exit 1
fi

# Example extraction using yq (requires yq installation)
# DB_PASS=$(echo "$CONFIG_YAML" | yq e '.database.password' -)
# API_KEY_FROM_YAML=$(echo "$CONFIG_YAML" | yq e '.api.key' -)

# Example extraction using grep/awk (less robust)
DB_PASS=$(echo "$CONFIG_YAML" | grep -A 1 'database:' | grep 'password:' | awk '{print $2}')
API_KEY_FROM_YAML=$(echo "$CONFIG_YAML" | grep -A 1 'api:' | grep 'key:' | awk '{print $2}')


echo "Extracted DB Password (from Bash): $DB_PASS"
echo "Extracted API Key (from Bash): $API_KEY_FROM_YAML"

# Further use of variables in your script
# e.g., ./deploy_script.sh --db-password "$DB_PASS" --api-key "$API_KEY_FROM_YAML"
```

## Source Code:
* [https://github.com/vpuhoff/keylocker](https://github.com/vpuhoff/keylocker)
* [https://deepwiki.com/vpuhoff/keylocker](https://deepwiki.com/vpuhoff/keylocker/1-overview)

```
