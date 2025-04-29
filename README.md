# Keylocker CLI (YAML Edition)

A command-line interface (CLI) tool and Python library for managing secrets directly within YAML configuration files. Allows encrypting individual values using the `!SEC` tag and loading values from environment variables using the `!ENV` tag.

## Encryption Key

Keylocker uses a Fernet key for encryption and decryption. The key is obtained in the following order of priority:

1.  **`KEYLOCKER_SECRET_KEY` Environment Variable:** If this environment variable is set, its value is used directly as the Fernet key (it should be a valid base64 encoded key).
2.  **`storage.key` File:** If the environment variable is not set, Keylocker attempts to read the key from the `storage.key` file in the current directory by default.

Use the `keylocker init` command to generate a `storage.key` file if you prefer file-based key storage. Note that if `KEYLOCKER_SECRET_KEY` is set, it will always take precedence over the file for encryption/decryption operations.

## Installation

You can install the package using pip:

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
    * Encrypts a string using the available key (Environment Variable or Key File) and prints the `!SEC` tag for you to copy into your YAML file.
    ```bash
    keylocker encrypt "my_secret_value"
    # Output:
    # Add the following line to your YAML file:
    # !SEC gAAAAABh...[encrypted data]...
    ```

3.  **View decrypted YAML:**
    * Loads the specified YAML file, resolves `!ENV` variables, decrypts `!SEC` values using the available key (Environment Variable or Key File), and prints the resulting YAML to standard output.
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
from keylocker import load_yaml_secrets

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

except Exception as e:
    print(f"An error occurred: {e}")

```

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

```