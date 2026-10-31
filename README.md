# Keylocker CLI (YAML Edition)
[![PyPI Downloads](https://img.shields.io/pypi/dm/keylocker)](https://pypi.org/project/keylocker/) [![Downloads](https://static.pepy.tech/badge/keylocker)](https://pepy.tech/project/keylocker)
[![codecov](https://codecov.io/github/vpuhoff/keylocker/graph/badge.svg?token=9VTMTGHPX1)](https://codecov.io/github/vpuhoff/keylocker)

A command-line interface (CLI) tool and Python library for managing secrets directly within YAML configuration files. Allows encrypting individual values using the `!SEC` tag and loading values from environment variables using the `!ENV` tag.

* Wiki: [https://deepwiki.com/vpuhoff/keylocker](https://deepwiki.com/vpuhoff/keylocker/1-overview)

![Alt](https://repobeats.axiom.co/api/embed/61e3a712de309936dc034c3851dc1a6144d3b4dd.svg "Repobeats analytics image")

## Encryption Key

Keylocker uses a Fernet key for encryption and decryption. The key is obtained in the following order of priority:

1.  **`KEYLOCKER_SECRET_KEY` Environment Variable:** If this environment variable is set, its value is used directly as the Fernet key (it should be a valid base64 encoded key).
2.  **Key file:** If the environment variable is not set, the key is read from a file: the `key_file` argument / `--key-file` option if given, otherwise the path in the `KEYLOCKER_KEY_FILE` environment variable, otherwise `storage.key` in the current directory.

Use the `keylocker init` command to generate a key file if you prefer file-based key storage. Note that if `KEYLOCKER_SECRET_KEY` is set, it will always take precedence over the file for encryption/decryption operations.

`keylocker init` creates the key file readable by its owner only (mode `0600` on Linux/macOS; missing parent directories are created with mode `0700`). Never commit it or bake it into container images: add `storage.key` to both `.gitignore` and `.dockerignore`, and prefer `KEYLOCKER_SECRET_KEY` injected at runtime in CI and containers.

The default `./storage.key` depends on the working directory and usually sits right next to `config.yaml`, where it is easy to commit by accident. To keep the key outside the project, point `KEYLOCKER_KEY_FILE` to a per-user location:

```bash
export KEYLOCKER_KEY_FILE=~/.config/keylocker/storage.key
keylocker init   # creates ~/.config/keylocker/ (0700) and the key (0600)
```

### Several keys and key rotation

Both the key file and `KEYLOCKER_SECRET_KEY` may hold several keys. The **first key is primary**: it encrypts new values. All keys are tried for decryption, so values encrypted with an older key keep working. In the file, put one key per line (lines starting with `#` are comments); in the environment variable, separate keys with commas: `KEYLOCKER_SECRET_KEY="new_key,old_key"`.

Rotating a file-based key:

```bash
keylocker init --rotate                      # prepend a new primary key, keep the old one
keylocker rotate config.yaml other.yaml      # re-encrypt every !SEC value with the new key
# then delete the old key (every line after the first) from the key file
```

`keylocker rotate` rewrites only the `!SEC` tokens in place: comments, formatting and values already encrypted with the primary key stay untouched, so running it twice changes nothing. If any value cannot be decrypted, the file is left unchanged and the command exits with code 1. With `KEYLOCKER_SECRET_KEY`, set it to `"new_key,old_key"`, run `keylocker rotate`, then drop the old key.

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
  # Fall back to a default when LOG_LEVEL is unset or empty
  log_level: !ENV LOG_LEVEL:-info
deployment:
  region: us-east-1
  # Another secret
  ssh_key_pass: !SEC gAAAAABh...[another encrypted data]...
```

## CLI Usage:

Global options (accepted before or after the command): `--key-file PATH` (alias `--key_file`) and `-q/--quiet` (only warnings and errors on stderr). Every command writes data to stdout and diagnostics to stderr; failures exit with code 1, invalid usage with code 2.

1.  **Initialization (create key file):**
    * Generates the key file (if it doesn't exist). This file is used *only* if the `KEYLOCKER_SECRET_KEY` environment variable is *not* set. `--rotate` adds a new primary key to an existing file (see [key rotation](#several-keys-and-key-rotation)).
    ```bash
    keylocker init [--force | --rotate]
    ```

2.  **Encrypt value for YAML:**
    * Encrypts a string using the available key (Environment Variable or Key File) and prints the `!SEC` tag to stdout for you to copy into your YAML file. Hints and diagnostics go to stderr.
    * Without an argument the secret is read from stdin, or from a hidden prompt (entered twice) when run in a terminal. Avoid passing the secret as an argument: it ends up in shell history and is visible in the process list. An argument is encrypted verbatim (`'{"a": 1}'` stays exactly that string).
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
    * `--strict` also fails when a `!ENV` variable without a default is unset (otherwise it is shown as `null`).
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
    #   log_level: info
    # deployment:
    #   region: us-east-1
    #   ssh_key_pass: decrypted_pass
    ```
    > **CI/CD caution:** `view` prints every secret in plaintext. Never run it bare in a CI job: its output ends up in build logs. Capture it into a variable or pipe it straight into the consumer (`keylocker view config.yaml | yq ...`), and register extracted values with your CI's secret masking (for example `echo "::add-mask::$DB_PASS"` on GitHub Actions).

4.  **Edit secrets in your editor (like `ansible-vault edit`):**
    * Decrypts every `!SEC` value into a temporary copy, opens it in `$VISUAL` / `$EDITOR` (default: `notepad` on Windows, `vi` elsewhere) and encrypts the file back when the editor exits. Comments and layout are kept.
    * In the editor secrets look like `password: !SEC "plaintext"`. Change them, or add new ones as `!SEC new value`: every `!SEC` value is encrypted on save. Unchanged secrets keep their exact ciphertext, so the git diff shows only what you edited.
    * The temporary copy is created with mode `0600` (in RAM-backed `/dev/shm` when available) and deleted afterwards. If the editor exits with an error, nothing is saved; if the result is not valid YAML, you are offered to re-open the editor.
    * GUI editors must wait until the file is closed, e.g. `EDITOR="code --wait"`.
    ```bash
    keylocker edit config.yaml
    ```

5.  **Re-encrypt with the primary key (rotation):**
    ```bash
    keylocker rotate config.yaml [more.yaml ...]
    ```

## `!ENV` references

* `!ENV NAME` resolves to the value of `NAME`. If it is unset, the value is `None` and a warning is logged; in strict mode (`strict=True` / `view --strict`) a `MissingEnvVarError` is raised instead.
* `!ENV NAME:-default` resolves to `default` when `NAME` is unset **or empty**, like `${NAME:-default}` in the shell. `!ENV NAME:-` gives an empty string. A default is never an error, even in strict mode.

## Usage in Python Code:

```python
import os
from keylocker import load_yaml_secrets, KeylockerError

# Set environment variables if your YAML uses !ENV
os.environ['API_KEY'] = 'your_actual_api_key_for_python'
# Set KEYLOCKER_SECRET_KEY if using env var for the encryption key
# os.environ['KEYLOCKER_SECRET_KEY'] = 'your_base64_encoded_fernet_key'

config_file = 'config.yaml'
# Optional: without it, $KEYLOCKER_KEY_FILE or ./storage.key is used.
# Ignored when KEYLOCKER_SECRET_KEY is set.
key_file_path = 'storage.key'

try:
    # Load, resolve !ENV, and decrypt !SEC automatically. strict=True fails closed.
    secrets = load_yaml_secrets(config_file, key_file_path, strict=True)
except KeylockerError as e:
    # Never fall back to a placeholder value: fail closed.
    raise SystemExit(f"Cannot load secrets: {e}")

db_password = secrets['database']['password']
api_key = secrets['api']['key']
```

All errors inherit from `KeylockerError`:

| Exception | Raised when |
| --- | --- |
| `DecryptionError` | a `!SEC` value cannot be decrypted (no key, wrong key, corrupted value) |
| `ConfigError` | the YAML file is missing, unreadable or invalid (`strict=True`) |
| `MissingEnvVarError` | a `!ENV` variable without a default is unset (`strict=True`) |
| `EncryptionError` | a `SecureString` cannot be encrypted, so it is never written out in plaintext |

For backward compatibility `strict` defaults to `False`: a missing or invalid file then returns `None` (with a `FutureWarning`) and an unset `!ENV` variable resolves to `None`. `strict=True` will become the default in the next major release.

### Editing YAML from code without noisy diffs

Fernet ciphertext is randomized, so encrypting the same value twice gives different tokens. To change a config programmatically without touching unrelated `!SEC` lines in the git diff, load it in round-trip mode: `!SEC` values come back as `SecureString` objects that remember their token, and `!ENV` values as unresolved `EnvVariable` references. `keylocker_dumper()` reuses the remembered token as long as the value is unchanged.

```python
import yaml
from keylocker import keylocker_loader, keylocker_dumper, SecureString

with open('config.yaml') as f:
    data = yaml.load(f, Loader=keylocker_loader(round_trip=True))

data['database']['password'] = SecureString('new password')   # only this line changes

with open('config.yaml', 'w') as f:
    yaml.dump(data, f, Dumper=keylocker_dumper(), sort_keys=False)
```

(PyYAML drops comments when dumping. To change secrets while keeping comments and layout, use `keylocker edit`.)

### Logging

The library logs through the standard `logging` module under the `keylocker` logger and never prints. Routine messages (such as which key source is used) are `DEBUG`; misconfiguration (an invalid key, an unset `!ENV` variable) is `WARNING`/`ERROR`. Without any logging configuration Python prints only warnings and errors to stderr. To silence or redirect them:

```python
import logging
logging.getLogger('keylocker').setLevel(logging.ERROR)
```

## Security notes

* **Ciphertext is not bound to its location.** Fernet has no associated data, so a `!SEC` token copied from `db.password` to `admin.password` (in the same or another file encrypted with the same key) decrypts without error. Anyone who can edit the YAML can move secrets around; protect the integrity of config files (code review, signed commits) if that matters in your threat model, and use separate keys for separate trust boundaries.
* Fernet authenticates every token: a modified token fails to decrypt (`DecryptionError`) instead of yielding garbage.
* Loading YAML uses `yaml.SafeLoader`; error messages report the line and column of a failing value but never the YAML source, which could contain other secrets.

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
