# keylocker/__init__.py

import argparse
import contextlib
import getpass
import json
import logging
import os
import re
import shlex
import subprocess
import sys
import tempfile
import warnings

import yaml
from cryptography.fernet import Fernet, InvalidToken, MultiFernet

# --- Configuration ---
DEFAULT_KEY_FILE = 'storage.key'
ENV_VAR_NAME = 'KEYLOCKER_SECRET_KEY' # Environment variable for the key(s)
KEY_FILE_ENV_VAR = 'KEYLOCKER_KEY_FILE' # Environment variable for the key file path
KEY_FILE_MODE = 0o600
KEY_DIR_MODE = 0o700
ENV_DEFAULT_SEPARATOR = ':-' # !ENV NAME:-default
_WINDOWS = os.name == 'nt'

logger = logging.getLogger('keylocker')

# --- Exceptions ---

class KeylockerError(Exception):
    """Base class for keylocker errors."""

class EncryptionError(KeylockerError):
    """A value could not be encrypted. Never carries the plaintext."""

class DecryptionError(KeylockerError):
    """A !SEC value could not be decrypted."""

class ConfigError(KeylockerError):
    """A YAML file could not be read or parsed."""

class MissingEnvVarError(KeylockerError):
    """A !ENV variable without a default is not set (strict mode only)."""

# --- Key Loading ---

def _resolve_key_file(key_file=None):
    """Explicit argument, then $KEYLOCKER_KEY_FILE, then ./storage.key."""
    path = key_file or os.environ.get(KEY_FILE_ENV_VAR) or DEFAULT_KEY_FILE
    return os.path.expanduser(path)

def _parse_keys(raw):
    """
    Splits key material into individual keys. Keys are separated by newlines,
    commas or whitespace; lines starting with '#' are comments. The first key is primary.
    """
    keys = []
    for line in raw.splitlines():
        line = line.strip()
        if line and not line.startswith('#'):
            keys.extend(k.encode('ascii') for k in re.split(r'[\s,]+', line) if k)
    if not keys:
        raise ValueError("no keys found")
    for key in keys:
        Fernet(key)
    return keys

def _load_keys(key_file=None):
    """
    Loads all Fernet keys (primary first), prioritizing the environment variable.
    Returns a list of key bytes, or None if no valid key is available.
    """
    key_from_env = os.environ.get(ENV_VAR_NAME)

    if key_from_env:
        logger.debug("Using encryption key from environment variable %s.", ENV_VAR_NAME)
        try:
            return _parse_keys(key_from_env)
        except (InvalidToken, ValueError, TypeError):
            logger.error("Invalid key format found in environment variable %s.", ENV_VAR_NAME)
            return None
        except Exception as e:
            logger.error("Unexpected error validating key from env var %s: %s", ENV_VAR_NAME, e)
            return None

    key_file = _resolve_key_file(key_file)
    if not os.path.exists(key_file):
        # Fine for 'init'; other commands fail later if no key is found.
        return None
    try:
        with open(key_file, 'rb') as kf:
            raw = kf.read()
        return _parse_keys(raw.decode('ascii'))
    except FileNotFoundError:
        logger.error("Key file '%s' not found.", key_file)
        return None
    except (InvalidToken, ValueError, TypeError):
        logger.error("Invalid key format in file '%s'.", key_file)
        return None
    except IOError as e:
        logger.error("Could not read key file '%s': %s", key_file, e)
        return None
    except Exception as e:
        logger.error("Unexpected error reading key file '%s': %s", key_file, e)
        return None

def _load_fernet_key(key_file=None):
    """Returns the primary key as bytes, or None if no valid key is available."""
    keys = _load_keys(key_file)
    return keys[0] if keys else None

def _load_fernet(key_file=None):
    """
    Returns a MultiFernet that encrypts with the primary key and decrypts with
    any configured key, or None.
    """
    keys = _load_keys(key_file)
    if not keys:
        return None
    try:
        return MultiFernet([Fernet(key) for key in keys])
    except Exception as e:
        logger.error("Failed to initialize Fernet with the loaded key: %s", e)
        return None

# --- YAML Tag Handling ---

class SecureString(str):
    """
    A value written as !SEC by keylocker_dumper(). ``ciphertext`` holds the token it
    was loaded from, so re-dumping an unchanged value does not change the file.
    """
    def __new__(cls, value='', ciphertext=None):
        obj = super().__new__(cls, value)
        obj.ciphertext = ciphertext
        return obj

class EnvVariable(str):
    """A variable reference (NAME or NAME:-default) written as !ENV by keylocker_dumper()."""

def _position(mark):
    # str(mark) embeds a snippet of the source YAML, which may hold other secrets.
    return f"line {mark.line + 1}, column {mark.column + 1}"

def _resolve_env(reference, position, strict):
    name, separator, default = reference.partition(ENV_DEFAULT_SEPARATOR)
    name = name.strip()
    value = os.environ.get(name)
    if separator:
        # Like the shell's ${NAME:-default}: an empty variable also falls back.
        return value if value else default
    if value is None:
        if strict:
            raise MissingEnvVarError(
                f"Environment variable '{name}' (tagged !ENV at {position}) is not set."
            )
        logger.warning("Environment variable '%s' (tagged !ENV) not found. Returning None.", name)
    return value

def keylocker_loader(key_file=None, strict=False, round_trip=False):
    """
    Creates a YAML Loader that handles !SEC and !ENV tags.
    A !SEC value that cannot be decrypted raises DecryptionError.
    With strict=True an unset !ENV variable without a default raises MissingEnvVarError
    instead of resolving to None.
    With round_trip=True, !SEC values load as SecureString (remembering their token) and
    !ENV values as unresolved EnvVariable, so keylocker_dumper() writes back an identical file.
    """
    fernet = _load_fernet(key_file)
    if fernet is None:
        logger.debug("No encryption key loaded. !SEC tags cannot be decrypted.")

    class KeylockerLoader(yaml.SafeLoader):
        pass

    def sec_constructor(loader, node):
        value = loader.construct_scalar(node)
        position = _position(node.start_mark)
        if fernet is None:
            raise DecryptionError(
                f"Cannot decrypt !SEC value at {position}: no valid key is loaded."
            )
        try:
            plaintext = fernet.decrypt(value.encode()).decode()
        except InvalidToken:
            raise DecryptionError(
                f"Failed to decrypt !SEC value at {position}: invalid token or key mismatch."
            ) from None
        except Exception as e:
            raise DecryptionError(
                f"Unexpected error during !SEC decryption at {position}: {type(e).__name__}"
            ) from None
        return SecureString(plaintext, ciphertext=value) if round_trip else plaintext

    def env_constructor(loader, node):
        reference = loader.construct_scalar(node)
        if round_trip:
            return EnvVariable(reference)
        return _resolve_env(reference, _position(node.start_mark), strict)

    KeylockerLoader.add_constructor('!SEC', sec_constructor)
    KeylockerLoader.add_constructor('!ENV', env_constructor)
    return KeylockerLoader

def keylocker_dumper(key_file=None):
    """
    Creates a YAML Dumper that handles SecureString and EnvVariable.
    A SecureString that cannot be encrypted raises EncryptionError; it is
    never written out in plaintext. A SecureString that still carries a valid
    token for its value (see keylocker_loader(round_trip=True)) keeps that token.
    """
    fernet = _load_fernet(key_file)
    if fernet is None:
        logger.debug("No encryption key loaded. Cannot encrypt values for !SEC tags.")

    class KeylockerDumper(yaml.SafeDumper):
        pass

    def reusable_token(data):
        token = getattr(data, 'ciphertext', None)
        if not token:
            return None
        try:
            if fernet.decrypt(token.encode()) == str(data).encode():
                return token
        except Exception:
            pass
        return None

    def sec_representer(dumper, data):
        if fernet is None:
            raise EncryptionError("Cannot represent SecureString as !SEC: no valid key is loaded.")
        encrypted_value = reusable_token(data)
        if encrypted_value is None:
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

def _load_yaml(file_path, key_file=None, strict_env=False):
    """Like load_yaml_secrets(strict=True), with !ENV strictness controlled separately."""
    try:
        with open(file_path, 'r') as f:
            return yaml.load(f, Loader=keylocker_loader(key_file, strict=strict_env))
    except KeylockerError:
        raise
    except FileNotFoundError:
        raise ConfigError(f"Input YAML file '{file_path}' not found.") from None
    except yaml.YAMLError as e:
        raise ConfigError(f"Failed to parse YAML file '{file_path}': {e}") from None
    except Exception as e:
        raise ConfigError(
            f"An unexpected error occurred during YAML load of '{file_path}': {e}"
        ) from None

def load_yaml_secrets(file_path, key_file=None, strict=False):
    """
    Loads YAML, decrypting !SEC and resolving !ENV (NAME or NAME:-default).
    Raises DecryptionError if any !SEC value cannot be decrypted.

    strict=True (recommended) fails closed everywhere: a missing or unparsable file
    raises ConfigError and an unset !ENV variable without a default raises
    MissingEnvVarError. With the default strict=False those cases return None
    (whole document, or the single !ENV value) for backward compatibility.
    """
    try:
        return _load_yaml(file_path, key_file, strict_env=strict)
    except ConfigError as e:
        if strict:
            raise
        logger.error("%s", e)
        warnings.warn(
            "load_yaml_secrets() returned None after a load error. Pass strict=True to get "
            "ConfigError instead; this will become the default in the next major release.",
            FutureWarning, stacklevel=2,
        )
        return None

def encrypt_string_value(value_to_encrypt, key_file=None):
    """Encrypts a string with the primary key and returns the !SEC tagged value, or None."""
    fernet = _load_fernet(key_file)
    if fernet is None:
        logger.error("Failed to load a valid encryption key for encryption.")
        return None
    try:
        encrypted = fernet.encrypt(str(value_to_encrypt).encode()).decode()
        return f"!SEC {encrypted}"
    except Exception as e:
        logger.error("An unexpected error occurred during encryption: %s", type(e).__name__)
        return None

def _read_text(file_path):
    try:
        with open(file_path, 'rb') as f:
            return f.read().decode('utf-8')
    except FileNotFoundError:
        raise ConfigError(f"Input YAML file '{file_path}' not found.") from None
    except UnicodeDecodeError as e:
        raise ConfigError(f"Failed to parse YAML file '{file_path}': {e}") from None
    except OSError as e:
        raise ConfigError(f"Could not read YAML file '{file_path}': {e}") from None

def _scalar_paths(documents):
    """Maps the end index of every scalar value node to its path (document index, keys/indexes)."""
    paths, seen = {}, set()

    def walk(node, path):
        if isinstance(node, yaml.ScalarNode):
            paths.setdefault(node.end_mark.index, path)
            return
        if id(node) in seen:
            return
        seen.add(id(node))
        if isinstance(node, yaml.MappingNode):
            for key, value in node.value:
                walk(value, path + (key.value if isinstance(key, yaml.ScalarNode) else None,))
        else:
            for index, item in enumerate(node.value):
                walk(item, path + (index,))

    for index, document in enumerate(documents):
        if document is not None:
            walk(document, (index,))
    return paths

def _sec_scalars(text, file_path):
    """
    Returns (start, end, value, mark, path) for every scalar tagged !SEC, where start:end is
    the scalar's span in text (quotes and block indicators included, tag and anchor excluded)
    and path locates it in the document (None for mapping keys).
    """
    try:
        paths = _scalar_paths(yaml.compose_all(text, Loader=yaml.SafeLoader))
        tokens = list(yaml.scan(text, Loader=yaml.SafeLoader))
    except yaml.YAMLError as e:
        raise ConfigError(f"Failed to parse YAML file '{file_path}': {e}") from None
    scalars = []
    tag = None
    for token in tokens:
        if isinstance(token, yaml.TagToken):
            handle, suffix = token.value
            tag = token if (handle or '') + suffix == '!SEC' else None
        elif isinstance(token, yaml.AnchorToken):
            continue
        elif tag is not None:
            if not isinstance(token, yaml.ScalarToken):
                raise ConfigError(f"!SEC at {_position(tag.start_mark)} must tag a single "
                                  "string value.")
            scalars.append((token.start_mark.index, token.end_mark.index, token.value,
                            tag.start_mark, paths.get(token.end_mark.index)))
            tag = None
    return scalars

def _replace_scalars(text, replacements):
    """Applies (start, end, new_scalar) replacements, keeping a block scalar's trailing breaks."""
    for start, end, scalar in sorted(replacements, reverse=True):
        source = text[start:end]
        text = text[:start] + scalar + source[len(source.rstrip()):] + text[end:]
    return text

def _decrypt_token(fernet, token, mark):
    try:
        return fernet.decrypt(token.strip().encode()).decode()
    except (InvalidToken, UnicodeDecodeError):
        raise DecryptionError(
            f"Failed to decrypt !SEC value at {_position(mark)}: invalid token or key mismatch."
        ) from None

def rotate_yaml_file(file_path, key_file=None):
    """
    Re-encrypts every !SEC value of a YAML file with the primary key, in place.
    Values already encrypted with the primary key, comments and formatting are left
    untouched. Returns the number of rotated values.
    Raises ConfigError, DecryptionError or EncryptionError; the file is then unchanged.
    """
    keys = _load_keys(key_file)
    if not keys:
        raise EncryptionError("Cannot rotate: no valid key is loaded.")
    primary = Fernet(keys[0])
    fernet = MultiFernet([Fernet(key) for key in keys])

    text = _read_text(file_path)
    replacements = []
    for start, end, value, mark, _path in _sec_scalars(text, file_path):
        token = value.strip()
        try:
            primary.decrypt(token.encode())
            continue
        except InvalidToken:
            pass
        try:
            rotated = fernet.rotate(token.encode()).decode()
        except InvalidToken:
            raise DecryptionError(
                f"Failed to decrypt !SEC value at {_position(mark)}: invalid token or key mismatch."
            ) from None
        replacements.append((start, end, rotated))

    if not replacements:
        return 0
    text = _replace_scalars(text, replacements)
    _atomic_replace(file_path, text.encode('utf-8'), mode=os.stat(file_path).st_mode & 0o7777)
    return len(replacements)

def _quote_plaintext(value):
    """A double-quoted YAML scalar for value; JSON strings are valid YAML, minus raw C1 controls."""
    quoted = json.dumps(value, ensure_ascii=False)
    return re.sub(r'[\x7f-\x9f]', lambda m: f"\\u{ord(m.group()):04x}", quoted)

def _decrypt_for_edit(text, fernet, file_path='<string>'):
    """
    Replaces every !SEC token in YAML text with its plaintext as a double-quoted scalar.
    Returns the editable text and a list of (path, plaintext, token), one per secret,
    for _encrypt_after_edit().
    """
    known = []
    replacements = []
    for start, end, value, mark, path in _sec_scalars(text, file_path):
        plaintext = _decrypt_token(fernet, value, mark)
        known.append((path, plaintext, value.strip()))
        replacements.append((start, end, _quote_plaintext(plaintext)))
    return _replace_scalars(text, replacements), known

def _encrypt_after_edit(text, fernet, known=(), file_path='<string>'):
    """
    Encrypts every !SEC plaintext in YAML text. An unchanged secret keeps its original token
    from known (from _decrypt_for_edit()), preferably the one at the same path, so it stays
    byte-identical. Each original token is reused at most once: a value changed to equal
    another secret is encrypted afresh, so an edit never makes two values share a token.
    """
    scalars = _sec_scalars(text, file_path)
    unused = list(known)
    tokens = [None] * len(scalars)

    def claim(index, matches):
        for position, entry in enumerate(unused):
            if matches(entry):
                tokens[index] = unused.pop(position)[2]
                return

    for index, (_, _, value, _, path) in enumerate(scalars):
        if path is not None:
            claim(index, lambda entry: entry[0] == path and entry[1] == value)
    for index, (_, _, value, _, _) in enumerate(scalars):
        if tokens[index] is None:
            claim(index, lambda entry: entry[1] == value)

    replacements = []
    for (start, end, value, mark, _), token in zip(scalars, tokens):
        if token is None:
            try:
                token = fernet.encrypt(value.encode()).decode()
            except Exception as e:
                raise EncryptionError(f"Failed to encrypt !SEC value at {_position(mark)}: "
                                      f"{type(e).__name__}") from None
        replacements.append((start, end, token))
    return _replace_scalars(text, replacements)

# --- File Writing ---

def _write_all(fd, data):
    while data:
        data = data[os.write(fd, data):]
    os.fsync(fd)

def _atomic_replace(path, data, mode=None):
    """
    Writes data to a private temp file next to path and atomically renames it over
    path, which replaces a symlink itself rather than writing through it.
    The result keeps mkstemp's 0600 unless mode is given.
    """
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp_path = tempfile.mkstemp(dir=directory, prefix='.keylocker-', suffix='.tmp')
    try:
        try:
            _write_all(fd, data)
        finally:
            os.close(fd)
        if mode is not None:
            os.chmod(tmp_path, mode)
        os.replace(tmp_path, path)
    except BaseException:
        if os.path.lexists(tmp_path):
            os.unlink(tmp_path)
        raise

def _write_key_file(key_path, key, overwrite=False):
    """
    Writes the key readable by the owner only (0600 on POSIX), never following symlinks.
    Without overwrite, raises FileExistsError if anything (even a dangling symlink) is at key_path.
    With overwrite, the key is replaced atomically (see _atomic_replace).
    """
    directory = os.path.dirname(os.path.abspath(key_path))
    try:
        os.makedirs(directory, mode=KEY_DIR_MODE, exist_ok=True)
    except FileExistsError:
        # Callers treat FileExistsError as "the key already exists".
        raise NotADirectoryError(f"'{directory}' is not a directory") from None

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

    _atomic_replace(key_path, key)

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
        logger.error("Values do not match.")
        return None
    return value

def _editor_command():
    return (os.environ.get('VISUAL') or os.environ.get('EDITOR')
            or ('notepad' if _WINDOWS else 'vi'))

def _run_editor(path):
    """Opens path in $VISUAL / $EDITOR and returns the editor's exit code."""
    editor = _editor_command()
    if _WINDOWS:
        # The shell resolves .cmd/.bat launchers such as `code --wait`.
        return subprocess.call(f'{editor} "{path}"', shell=True)
    return subprocess.call(shlex.split(editor) + [path])

def _confirm(prompt, default=True):
    """Asks a yes/no question on the terminal; without a terminal the answer is always no."""
    if not sys.stdin.isatty():
        return False
    sys.stderr.write(prompt)
    sys.stderr.flush()
    answer = sys.stdin.readline().strip().lower()
    return default if answer == '' else answer in ('y', 'yes')

def _plaintext_tempfile(suffix):
    """A 0600 temp file for decrypted content, in RAM-backed /dev/shm when available."""
    directory = '/dev/shm' if os.path.isdir('/dev/shm') and os.access('/dev/shm', os.W_OK) else None
    return tempfile.mkstemp(prefix='keylocker-', suffix=suffix, dir=directory)

# --- CLI Manager ---

class Manager(object):
    def __init__(self, key_file=None):
        self.key_file = key_file

    @property
    def key_path(self):
        return _resolve_key_file(self.key_file)

    def _check_key_available(self):
        """Checks if an encryption key is available via env var or file."""
        if not _load_fernet_key(self.key_file):
            logger.error("No valid encryption key found.")
            logger.error("Ensure %s environment variable is set,", ENV_VAR_NAME)
            logger.error("or run 'keylocker init' to create '%s'.", self.key_path)
            return False
        return True

    def _note_env_precedence(self):
        if os.environ.get(ENV_VAR_NAME):
            logger.info("Note: Environment variable %s is set and will take precedence "
                        "over this file for operations.", ENV_VAR_NAME)

    def init(self, force=False, rotate=False):
        """
        Initializes storage by generating the master key file (mode 0600).
        With rotate=True a new primary key is prepended to an existing key file;
        old keys stay usable for decryption until removed from the file.
        This command ALWAYS interacts with the key FILE, not the env var.
        """
        key_path = self.key_path
        if rotate:
            return self._add_primary_key(key_path)

        def already_exists():
            logger.info("Key file '%s' already exists.", key_path)
            self._note_env_precedence()
            logger.info("Use --force to overwrite the file, or --rotate to add a new primary key.")
            return f"Key file '{key_path}' already exists."

        if os.path.lexists(key_path) and not force:
            return already_exists()

        logger.info("Generating new key file: '%s'...", key_path)
        key = Fernet.generate_key() # This key is already base64 encoded bytes

        try:
            _write_key_file(key_path, key, overwrite=force)
        except FileExistsError:
            return already_exists()
        except OSError as e:
            logger.error("Could not write key file '%s': %s", key_path, e)
            sys.exit(1)
        logger.info("Successfully created key file: '%s'", key_path)
        logger.info("Keep it out of version control and container images (.gitignore / .dockerignore).")
        self._note_env_precedence()
        return f"Key file '{key_path}' created."

    def _add_primary_key(self, key_path):
        try:
            with open(key_path, 'rb') as kf:
                old_keys = _parse_keys(kf.read().decode('ascii'))
        except FileNotFoundError:
            logger.error("Key file '%s' not found. Run 'keylocker init' first.", key_path)
            sys.exit(1)
        except (OSError, ValueError, TypeError):
            logger.error("Could not read a valid key from '%s'.", key_path)
            sys.exit(1)
        keys = [Fernet.generate_key()] + old_keys
        try:
            _write_key_file(key_path, b'\n'.join(keys) + b'\n', overwrite=True)
        except OSError as e:
            logger.error("Could not write key file '%s': %s", key_path, e)
            sys.exit(1)
        logger.info("Added a new primary key to '%s' (%d keys total).", key_path, len(keys))
        logger.info("Run 'keylocker rotate <file.yaml>' for every config, then delete the old "
                    "keys (all lines after the first) from the key file.")
        self._note_env_precedence()
        return f"Key file '{key_path}' rotated."

    def encrypt(self, value=None):
        """
        Encrypts a secret and prints the !SEC tag to stdout.
        Without VALUE the secret is read from stdin or a hidden prompt;
        passing it as an argument leaks it to shell history and the process list.
        """
        if not self._check_key_available():
            sys.exit(1)
        if value is None:
            value = _read_secret_interactively()
            if value is None:
                sys.exit(1)
        else:
            logger.warning("Passing a secret as a command-line argument exposes it via shell history "
                           "and the process list. Prefer stdin or the interactive prompt.")
        if value == "":
            logger.error("Refusing to encrypt an empty value.")
            sys.exit(1)
        encrypted_tag = encrypt_string_value(value, self.key_file)
        if not encrypted_tag:
            sys.exit(1)
        logger.info("Add the following line to your YAML file:")
        print(encrypted_tag)

    def view(self, yaml_file, strict=False):
        """
        Loads, decrypts (!SEC), resolves (!ENV) a YAML file and prints it to stdout.
        With strict=True an unset !ENV variable without a default is an error.
        """
        try:
            data = _load_yaml(yaml_file, self.key_file, strict_env=strict)
        except KeylockerError as e:
            logger.error("%s", e)
            sys.exit(1)
        print(yaml.dump(data, Dumper=yaml.SafeDumper, default_flow_style=False,
                        sort_keys=False, allow_unicode=True), end='')

    def edit(self, yaml_file):
        """
        Decrypts a YAML file into a temporary copy, opens $VISUAL / $EDITOR on it and
        encrypts the result back. Unchanged secrets keep their tokens; new `!SEC plaintext`
        values are encrypted. The decrypted copy is deleted afterwards.
        """
        if not self._check_key_available():
            sys.exit(1)
        fernet = _load_fernet(self.key_file)
        try:
            text = _read_text(yaml_file)
            plaintext, known = _decrypt_for_edit(text, fernet, yaml_file)
        except KeylockerError as e:
            logger.error("%s", e)
            sys.exit(1)

        fd, tmp_path = _plaintext_tempfile(os.path.splitext(yaml_file)[1] or '.yaml')
        try:
            try:
                _write_all(fd, plaintext.encode('utf-8'))
            finally:
                os.close(fd)
            while True:
                try:
                    code = _run_editor(tmp_path)
                except OSError as e:
                    logger.error("Could not start editor '%s': %s", _editor_command(), e)
                    sys.exit(1)
                if code != 0:
                    logger.error("Editor exited with code %s; '%s' left unchanged.", code, yaml_file)
                    sys.exit(1)
                try:
                    with open(tmp_path, 'rb') as f:
                        edited = f.read().decode('utf-8').lstrip('\ufeff')
                    if '\r\n' not in plaintext:
                        edited = edited.replace('\r\n', '\n')
                    if edited == plaintext:
                        logger.info("No changes; '%s' left unchanged.", yaml_file)
                        return
                    result = _encrypt_after_edit(edited, fernet, known, yaml_file)
                    removed = len(known) - len(_sec_scalars(edited, yaml_file))
                except (KeylockerError, UnicodeDecodeError, OSError) as e:
                    logger.error("%s", e)
                    if not _confirm("Re-open the editor to fix it? [Y/n] "):
                        logger.error("'%s' left unchanged.", yaml_file)
                        sys.exit(1)
                    continue
                if removed <= 0:
                    break
                logger.warning("The file now has %d !SEC value(s) fewer than before. A value whose "
                               "!SEC tag was deleted is saved in plaintext.", removed)
                if _confirm("Save anyway? [y/N] ", False):
                    break
                if not _confirm("Re-open the editor? [Y/n] "):
                    logger.error("'%s' left unchanged.", yaml_file)
                    sys.exit(1)
        finally:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(tmp_path)

        try:
            _atomic_replace(yaml_file, result.encode('utf-8'),
                            mode=os.stat(yaml_file).st_mode & 0o7777)
        except OSError as e:
            logger.error("Could not write '%s': %s", yaml_file, e)
            sys.exit(1)
        logger.info("Saved '%s'.", yaml_file)

    def rotate(self, *yaml_files):
        """Re-encrypts every !SEC value in the given YAML files with the primary key."""
        if not self._check_key_available():
            sys.exit(1)
        failed = False
        for yaml_file in yaml_files:
            try:
                count = rotate_yaml_file(yaml_file, self.key_file)
            except KeylockerError as e:
                logger.error("%s", e)
                failed = True
                continue
            logger.info("%s: %d value(s) re-encrypted.", yaml_file, count)
        if failed:
            sys.exit(1)

# --- Main execution ---

class _CliFormatter(logging.Formatter):
    def format(self, record):
        message = record.getMessage()
        return message if record.levelno == logging.INFO else f"{record.levelname}: {message}"

def _build_parser():
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument('--key-file', '--key_file', dest='key_file', default=argparse.SUPPRESS,
                        help=f"key file path (default: ${KEY_FILE_ENV_VAR} or ./{DEFAULT_KEY_FILE}); "
                             f"${ENV_VAR_NAME} takes precedence over any file")
    common.add_argument('-q', '--quiet', action='store_true', default=argparse.SUPPRESS,
                        help="only print warnings and errors to stderr")

    parser = argparse.ArgumentParser(
        prog='keylocker', parents=[common],
        description="Keep encrypted secrets (!SEC) and environment references (!ENV) in YAML files.",
    )
    commands = parser.add_subparsers(dest='command', metavar='COMMAND')

    init = commands.add_parser('init', parents=[common], help="create the key file (mode 0600)")
    mode = init.add_mutually_exclusive_group()
    mode.add_argument('--force', action='store_true', help="overwrite an existing key file")
    mode.add_argument('--rotate', action='store_true',
                      help="add a new primary key, keeping old keys for decryption")

    encrypt = commands.add_parser('encrypt', parents=[common], help="print a !SEC tag for a secret")
    encrypt.add_argument('value', nargs='?',
                         help="secret to encrypt; omit to read stdin or a hidden prompt (recommended)")

    view = commands.add_parser('view', parents=[common],
                               help="print a YAML file with secrets decrypted (to stdout!)")
    view.add_argument('yaml_file')
    view.add_argument('--strict', action='store_true',
                      help="fail if a !ENV variable without a default is not set")

    edit = commands.add_parser('edit', parents=[common],
                               help="decrypt a YAML file into $VISUAL/$EDITOR and re-encrypt on save")
    edit.add_argument('yaml_file')

    rotate = commands.add_parser('rotate', parents=[common],
                                 help="re-encrypt !SEC values with the primary key, in place")
    rotate.add_argument('yaml_files', nargs='+', metavar='yaml_file')
    return parser

def main(argv=None):
    parser = _build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return 0

    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(_CliFormatter())
    saved = logger.level, logger.propagate
    logger.addHandler(handler)
    logger.setLevel(logging.WARNING if getattr(args, 'quiet', False) else logging.INFO)
    logger.propagate = False
    try:
        manager = Manager(key_file=getattr(args, 'key_file', None))
        if args.command == 'init':
            print(manager.init(force=args.force, rotate=args.rotate))
        elif args.command == 'encrypt':
            manager.encrypt(args.value)
        elif args.command == 'view':
            manager.view(args.yaml_file, strict=args.strict)
        elif args.command == 'edit':
            manager.edit(args.yaml_file)
        else:
            manager.rotate(*args.yaml_files)
    finally:
        logger.removeHandler(handler)
        logger.setLevel(saved[0])
        logger.propagate = saved[1]
    return 0

if __name__ == "__main__":
    sys.exit(main())
