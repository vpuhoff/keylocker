# Keylocker CLI (YAML Edition)

A command-line interface (CLI) tool and Python library for managing secrets directly within YAML configuration files. Allows encrypting individual values using the `!SEC` tag and loading values from environment variables using the `!ENV` tag.

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

1.  **Initialization (create key):**
    ```bash
    keylocker init
    # The storage.key file will be created (if it doesn't exist)
    ```

2.  **Encrypt value for YAML insertion:**
    ```bash
    keylocker encrypt "my_secret_value"
    # Output:
    # Add the following line to your YAML file:
    # !SEC gAAAAABh...[encrypted data]...

    # Copy the !SEC ... line into your YAML file
    ```

3.  **View decrypted YAML:**
    ```bash
    # Set the environment variable (if using !ENV)
    export API_KEY="your_actual_api_key"

    keylocker view config.yaml
    # Outputs the YAML with !SEC values decrypted
    # and !ENV values substituted
    # Example output:
    # database:
    #   host: db.example.com
    #   username: user
    #   password: my_secret_value # Decrypted!
    # api:
    #   endpoint: [https://api.example.com](https://api.example.com)
    #   key: your_actual_api_key  # Substituted from env!
    # deployment:
    #   region: us-east-1
    #   ssh_key_pass: decrypted_pass # Decrypted!
    ```
    *(Note: An `edit` command might be added in the future for interactive editing)*

## Usage in Python Code:

```python
import os
from keylocker import load_yaml_secrets

# Set environment variables if needed
os.environ['API_KEY'] = 'your_actual_api_key_for_python'

config_file = 'config.yaml'
key_file = 'storage.key' # Make sure the key exists

try:
    # Load and automatically decrypt/substitute
    secrets = load_yaml_secrets(config_file, key_file)

    if secrets:
        db_password = secrets.get('database', {}).get('password')
        api_key = secrets.get('api', {}).get('key')

        print(f"Database Password: {db_password}")
        print(f"API Key: {api_key}")

except Exception as e:
    print(f"An error occurred: {e}")
```

## Usage in Bash:

To extract specific values from the decrypted YAML, you can use utilities like `yq` or standard Unix tools.

```bash
#!/bin/bash

# Make sure the environment variable is set if needed
export API_KEY="your_bash_api_key"

# Get the decrypted YAML
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


echo "Extracted DB Password: $DB_PASS"
echo "Extracted API Key: $API_KEY_FROM_YAML"

# Further use of variables...
# e.g., publish command using extracted credentials
# some_command --username user --password "${DB_PASS}"
```

## Source Code:
* [https://github.com/vpuhoff/keylocker](https://github.com/vpuhoff/keylocker)
