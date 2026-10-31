# tests/test_review_features.py
# Strict mode, !ENV defaults, key rotation, round-trip dumping, logging and the argparse CLI.

import logging
import os
import sys

import pytest
import yaml
from cryptography.fernet import Fernet

import keylocker
from keylocker import (
    ConfigError,
    DecryptionError,
    EncryptionError,
    EnvVariable,
    KeylockerError,
    Manager,
    MissingEnvVarError,
    SecureString,
    encrypt_string_value,
    keylocker_dumper,
    keylocker_loader,
    load_yaml_secrets,
    main,
    rotate_yaml_file,
    DEFAULT_KEY_FILE,
    ENV_VAR_NAME,
    KEY_FILE_ENV_VAR,
)


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    monkeypatch.delenv(ENV_VAR_NAME, raising=False)
    monkeypatch.delenv(KEY_FILE_ENV_VAR, raising=False)


@pytest.fixture
def key_file(tmp_path):
    path = tmp_path / DEFAULT_KEY_FILE
    path.write_bytes(Fernet.generate_key())
    return str(path)


def _token(key, value):
    return Fernet(key).encrypt(value.encode()).decode()


def _write(tmp_path, content, name="config.yaml"):
    path = tmp_path / name
    path.write_bytes(content.encode())
    return str(path)


# === Strict mode / fail-closed loading ===

def test_strict_missing_file_raises(tmp_path):
    with pytest.raises(ConfigError, match="not found") as excinfo:
        load_yaml_secrets(str(tmp_path / "missing.yaml"), strict=True)
    assert isinstance(excinfo.value, KeylockerError)


def test_strict_invalid_yaml_raises(tmp_path):
    with pytest.raises(ConfigError, match="Failed to parse"):
        load_yaml_secrets(_write(tmp_path, "key: [unclosed"), strict=True)


def test_non_strict_failure_warns_about_future_default(tmp_path):
    with pytest.warns(FutureWarning, match="strict=True"):
        assert load_yaml_secrets(str(tmp_path / "missing.yaml")) is None


def test_strict_missing_env_raises(tmp_path):
    path = _write(tmp_path, "a: 1\nb: !ENV KEYLOCKER_TEST_UNSET\n")
    with pytest.raises(MissingEnvVarError, match="KEYLOCKER_TEST_UNSET.*line 2"):
        load_yaml_secrets(path, strict=True)


def test_strict_loader_accepts_set_env(tmp_path, monkeypatch):
    monkeypatch.setenv("KEYLOCKER_TEST_SET", "value")
    assert yaml.load("a: !ENV KEYLOCKER_TEST_SET", Loader=keylocker_loader(strict=True)) == {'a': 'value'}


@pytest.mark.parametrize("env_value, reference, expected", [
    (None, "KEYLOCKER_TEST_VAR:-fallback", "fallback"),
    ("", "KEYLOCKER_TEST_VAR:-fallback", "fallback"),
    ("real", "KEYLOCKER_TEST_VAR:-fallback", "real"),
    (None, "KEYLOCKER_TEST_VAR:-", ""),
    (None, "KEYLOCKER_TEST_VAR:-with:-colons and spaces", "with:-colons and spaces"),
    ("", "KEYLOCKER_TEST_VAR", ""),
])
def test_env_default(monkeypatch, env_value, reference, expected):
    if env_value is None:
        monkeypatch.delenv("KEYLOCKER_TEST_VAR", raising=False)
    else:
        monkeypatch.setenv("KEYLOCKER_TEST_VAR", env_value)
    for strict in (False, True):
        loaded = yaml.load(f"a: !ENV '{reference}'", Loader=keylocker_loader(strict=strict))
        assert loaded == {'a': expected}


def test_view_strict_fails_on_missing_env(tmp_path, key_file, capsys):
    path = _write(tmp_path, "a: !ENV KEYLOCKER_TEST_UNSET\n")
    Manager(key_file).view(path)
    assert yaml.safe_load(capsys.readouterr().out) == {'a': None}
    with pytest.raises(SystemExit) as excinfo:
        Manager(key_file).view(path, strict=True)
    assert excinfo.value.code == 1
    assert capsys.readouterr().out == ""


# === Logging ===

def test_library_logs_key_source_only_at_debug(tmp_path, monkeypatch, caplog):
    key = Fernet.generate_key()
    monkeypatch.setenv(ENV_VAR_NAME, key.decode())
    caplog.set_level(logging.DEBUG, logger="keylocker")
    load_yaml_secrets(_write(tmp_path, f"a: !SEC {_token(key, 'x')}"))
    records = [r for r in caplog.records if "environment variable" in r.getMessage()]
    assert records and all(r.levelno == logging.DEBUG for r in records)


def test_main_restores_logger_state(tmp_path, key_file):
    logger = logging.getLogger("keylocker")
    before = (logger.level, logger.propagate, list(logger.handlers))
    main(['--key-file', key_file, 'view', _write(tmp_path, "a: 1")])
    assert (logger.level, logger.propagate, list(logger.handlers)) == before


def test_cli_quiet_hides_info(tmp_path, key_file, capsys, monkeypatch):
    monkeypatch.setattr(keylocker.logger, 'propagate', False)
    main(['encrypt', '--key-file', key_file, 'abc'])
    err = capsys.readouterr().err
    assert "Add the following line" in err and "WARNING: Passing a secret" in err
    main(['encrypt', '--key-file', key_file, '-q', 'abc'])
    err = capsys.readouterr().err
    assert "Add the following line" not in err and "WARNING: Passing a secret" in err


# === argparse CLI ===

def test_cli_encrypt_keeps_argument_verbatim(key_file, capsys):
    """Fire turned '{"a": 1}' into a dict and encrypted "{'a': 1}"; argparse must not."""
    main(['--key_file', key_file, 'encrypt', '{"a": 1}'])
    tag = capsys.readouterr().out.strip()
    assert Fernet(open(key_file, 'rb').read()).decrypt(tag.split(" ", 1)[1].encode()) == b'{"a": 1}'


@pytest.mark.parametrize("value", ["123", "True", "[1, 2]", "None", "1e3"])
def test_cli_encrypt_literal_lookalikes(key_file, capsys, value):
    main(['encrypt', '--key-file', key_file, value])
    tag = capsys.readouterr().out.strip()
    assert Fernet(open(key_file, 'rb').read()).decrypt(tag.split(" ", 1)[1].encode()).decode() == value


def test_cli_init_prints_result(tmp_path, capsys):
    path = tmp_path / "k.key"
    assert main(['init', '--key-file', str(path)]) == 0
    assert "created." in capsys.readouterr().out
    Fernet(path.read_bytes())


def test_cli_init_force_and_rotate_are_exclusive(tmp_path):
    with pytest.raises(SystemExit) as excinfo:
        main(['init', '--force', '--rotate'])
    assert excinfo.value.code == 2


def test_cli_unknown_command_exits_with_usage_error():
    with pytest.raises(SystemExit) as excinfo:
        main(['frobnicate'])
    assert excinfo.value.code == 2


# === Key file location ===

def test_key_file_env_var_is_used(tmp_path, monkeypatch, capsys):
    path = tmp_path / "nested" / "dir" / "k.key"
    monkeypatch.setenv(KEY_FILE_ENV_VAR, str(path))
    Manager().init()
    assert path.exists()
    if os.name != 'nt':
        assert (path.parent.stat().st_mode & 0o777) == 0o700
    tag = encrypt_string_value("via-env-path")
    config = _write(tmp_path, f"a: {tag}")
    assert load_yaml_secrets(config) == {'a': 'via-env-path'}


def test_explicit_key_file_beats_env_var(tmp_path, monkeypatch, key_file):
    monkeypatch.setenv(KEY_FILE_ENV_VAR, str(tmp_path / "unused.key"))
    assert Manager(key_file).key_path == key_file


def test_key_file_path_expands_user(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    assert os.path.normpath(Manager("~/k.key").key_path) == os.path.join(str(tmp_path), "k.key")


# === Multiple keys / rotation ===

def test_env_with_several_keys_decrypts_old_and_encrypts_with_first(tmp_path, monkeypatch):
    new, old = Fernet.generate_key(), Fernet.generate_key()
    monkeypatch.setenv(ENV_VAR_NAME, f"{new.decode()}, {old.decode()}")
    config = _write(tmp_path, f"a: !SEC {_token(old, 'old-secret')}")
    assert load_yaml_secrets(config) == {'a': 'old-secret'}
    tag = encrypt_string_value("fresh")
    assert Fernet(new).decrypt(tag.split(" ", 1)[1].encode()) == b"fresh"


def test_key_file_with_several_keys_and_comments(tmp_path):
    new, old = Fernet.generate_key(), Fernet.generate_key()
    path = tmp_path / "multi.key"
    path.write_bytes(b"# primary\n" + new + b"\n\n# retired\n" + old + b"\n")
    config = _write(tmp_path, f"a: !SEC {_token(old, 'v')}")
    assert load_yaml_secrets(config, str(path)) == {'a': 'v'}
    assert keylocker._load_fernet_key(str(path)) == new


def test_key_file_with_one_invalid_key_is_rejected(tmp_path, caplog):
    path = tmp_path / "bad.key"
    path.write_bytes(Fernet.generate_key() + b"\nnot-a-key\n")
    assert keylocker._load_fernet_key(str(path)) is None
    assert "Invalid key format" in caplog.text


def test_empty_key_file_is_rejected(tmp_path):
    path = tmp_path / "empty.key"
    path.write_bytes(b"# nothing here\n")
    assert keylocker._load_fernet_key(str(path)) is None


def test_init_rotate_prepends_new_key(key_file, capsys):
    old = open(key_file, 'rb').read()
    result = Manager(key_file).init(rotate=True)
    assert "rotated" in result
    keys = open(key_file, 'rb').read().split()
    assert len(keys) == 2 and keys[1] == old and keys[0] != old
    if os.name != 'nt':
        assert (os.stat(key_file).st_mode & 0o777) == 0o600


def test_init_rotate_without_key_file_exits(tmp_path):
    with pytest.raises(SystemExit) as excinfo:
        Manager(str(tmp_path / "missing.key")).init(rotate=True)
    assert excinfo.value.code == 1


def test_init_rotate_with_invalid_key_file_exits(tmp_path):
    path = tmp_path / "bad.key"
    path.write_bytes(b"garbage")
    with pytest.raises(SystemExit) as excinfo:
        Manager(str(path)).init(rotate=True)
    assert excinfo.value.code == 1
    assert path.read_bytes() == b"garbage"


def test_init_rotate_write_failure_exits(key_file, monkeypatch):
    old = open(key_file, 'rb').read()
    monkeypatch.setattr(os, 'replace', lambda s, d: (_ for _ in ()).throw(OSError("nope")))
    with pytest.raises(SystemExit) as excinfo:
        Manager(key_file).init(rotate=True)
    assert excinfo.value.code == 1
    assert open(key_file, 'rb').read() == old


def test_init_rotate_notes_env_precedence(key_file, monkeypatch, caplog):
    caplog.set_level(logging.INFO, logger="keylocker")
    monkeypatch.setenv(ENV_VAR_NAME, Fernet.generate_key().decode())
    Manager(key_file).init(rotate=True)
    assert "will take precedence" in caplog.text


def test_rotate_yaml_file_rewrites_only_stale_tokens(tmp_path, key_file):
    old = open(key_file, 'rb').read()
    Manager(key_file).init(rotate=True)
    new = open(key_file, 'rb').read().split()[0]
    fresh = _token(new, 'fresh')
    source = (
        "# header comment\r\n"
        "db:\r\n"
        f"  password: !SEC {_token(old, 'db-pass')}  # inline comment\r\n"
        f"  quoted: !SEC \"{_token(old, 'quoted')}\"\r\n"
        f"  anchored: &a !SEC {_token(old, 'anchored')}\r\n"
        "  alias: *a\r\n"
        f"  current: !SEC {fresh}\r\n"
        f"  block: !SEC |\r\n    {_token(old, 'block')}\r\n"
        "list:\r\n"
        f"  - !SEC {_token(old, 'item')}\r\n"
        "plain: value\r\n"
    )
    path = _write(tmp_path, source)
    assert rotate_yaml_file(path, key_file) == 5
    text = open(path, 'rb').read().decode()
    assert text.startswith("# header comment\r\n") and "# inline comment\r\n" in text
    assert "\n" not in text.replace("\r\n", "")
    assert fresh in text and "&a !SEC " in text
    loaded = load_yaml_secrets(path, key_file)
    assert loaded['db'] == {'password': 'db-pass', 'quoted': 'quoted', 'anchored': 'anchored',
                            'alias': 'anchored', 'current': 'fresh', 'block': 'block'}
    assert loaded['list'] == ['item'] and loaded['plain'] == 'value'

    # Only the new key is needed afterwards, and a second run changes nothing.
    open(key_file, 'wb').write(new)
    assert load_yaml_secrets(path, key_file)['db']['password'] == 'db-pass'
    assert rotate_yaml_file(path, key_file) == 0
    assert open(path, 'rb').read().decode() == text


def test_rotate_yaml_file_multiple_documents(tmp_path, key_file):
    old = open(key_file, 'rb').read()
    Manager(key_file).init(rotate=True)
    path = _write(tmp_path, f"a: !SEC {_token(old, '1')}\n---\nb: !SEC {_token(old, '2')}\n")
    assert rotate_yaml_file(path, key_file) == 2


def test_rotate_yaml_file_wrong_key_leaves_file_untouched(tmp_path, key_file):
    source = f"a: !SEC {_token(Fernet.generate_key(), 'x')}\n"
    path = _write(tmp_path, source)
    with pytest.raises(DecryptionError, match="line 1"):
        rotate_yaml_file(path, key_file)
    assert open(path, 'rb').read().decode() == source


def test_rotate_yaml_file_errors(tmp_path, key_file):
    with pytest.raises(ConfigError, match="not found"):
        rotate_yaml_file(str(tmp_path / "missing.yaml"), key_file)
    with pytest.raises(ConfigError, match="Failed to parse"):
        rotate_yaml_file(_write(tmp_path, "a: [unclosed"), key_file)
    with pytest.raises(ConfigError, match="Could not read"):
        rotate_yaml_file(str(tmp_path), key_file)
    with pytest.raises(EncryptionError, match="no valid key"):
        rotate_yaml_file(_write(tmp_path, "a: 1"), str(tmp_path / "missing.key"))


def test_rotate_yaml_file_verbatim_tag(tmp_path, key_file):
    old = open(key_file, 'rb').read()
    Manager(key_file).init(rotate=True)
    path = _write(tmp_path, f"a: !<!SEC> {_token(old, 'x')}\n")
    assert rotate_yaml_file(path, key_file) == 1
    assert open(path).read().startswith("a: !<!SEC> gAAAAA")
    assert load_yaml_secrets(path, key_file) == {'a': 'x'}


def test_rotate_yaml_file_escaped_token(tmp_path, key_file):
    old = open(key_file, 'rb').read()
    Manager(key_file).init(rotate=True)
    token = _token(old, 'x')
    path = _write(tmp_path, f'a: !SEC "\\x{ord(token[0]):02x}{token[1:]}"  # c\n')
    assert rotate_yaml_file(path, key_file) == 1
    assert open(path).read().endswith("  # c\n")
    assert load_yaml_secrets(path, key_file) == {'a': 'x'}


def test_rotate_yaml_file_rejects_non_scalar_sec(tmp_path, key_file):
    with pytest.raises(ConfigError, match="line 1, column 4.*single string"):
        rotate_yaml_file(_write(tmp_path, "a: !SEC [1, 2]\n"), key_file)


@pytest.mark.skipif(os.name == 'nt', reason="POSIX permissions")
def test_rotate_yaml_file_keeps_permissions(tmp_path, key_file):
    old = open(key_file, 'rb').read()
    Manager(key_file).init(rotate=True)
    path = _write(tmp_path, f"a: !SEC {_token(old, 'x')}\n")
    os.chmod(path, 0o640)
    rotate_yaml_file(path, key_file)
    assert (os.stat(path).st_mode & 0o777) == 0o640


def test_manager_rotate(tmp_path, key_file, caplog):
    caplog.set_level(logging.INFO, logger="keylocker")
    old = open(key_file, 'rb').read()
    Manager(key_file).init(rotate=True)
    good = _write(tmp_path, f"a: !SEC {_token(old, 'x')}\n", "good.yaml")
    Manager(key_file).rotate(good)
    assert "1 value(s) re-encrypted" in caplog.text

    bad = _write(tmp_path, f"a: !SEC {_token(Fernet.generate_key(), 'x')}\n", "bad.yaml")
    with pytest.raises(SystemExit) as excinfo:
        Manager(key_file).rotate(bad, good)
    assert excinfo.value.code == 1
    assert "0 value(s) re-encrypted" in caplog.text


def test_manager_rotate_without_key_exits(tmp_path):
    with pytest.raises(SystemExit) as excinfo:
        Manager(str(tmp_path / "missing.key")).rotate("config.yaml")
    assert excinfo.value.code == 1


def test_cli_rotate(tmp_path, key_file):
    old = open(key_file, 'rb').read()
    main(['init', '--rotate', '--key-file', key_file])
    path = _write(tmp_path, f"a: !SEC {_token(old, 'x')}\n")
    assert main(['rotate', '--key-file', key_file, path]) == 0
    assert old.decode() not in open(path).read()


# === Round trip / stable dumps ===

def test_round_trip_keeps_unchanged_tokens(tmp_path, key_file, monkeypatch):
    key = open(key_file, 'rb').read()
    token_a, token_b = _token(key, 'a-secret'), _token(key, 'b-secret')
    path = _write(tmp_path, f"a: !SEC {token_a}\nb: !SEC {token_b}\nc: !ENV API_KEY:-dflt\n")
    with open(path) as f:
        data = yaml.load(f, Loader=keylocker_loader(key_file, round_trip=True))
    assert data == {'a': 'a-secret', 'b': 'b-secret', 'c': 'API_KEY:-dflt'}
    assert isinstance(data['a'], SecureString) and isinstance(data['c'], EnvVariable)

    data['b'] = SecureString('changed')
    dumped = yaml.dump(data, Dumper=keylocker_dumper(key_file), sort_keys=False)
    assert token_a in dumped and token_b not in dumped
    assert "!ENV 'API_KEY:-dflt'" in dumped
    reloaded = yaml.load(dumped, Loader=keylocker_loader(key_file))
    assert reloaded == {'a': 'a-secret', 'b': 'changed', 'c': 'dflt'}


def test_dumper_ignores_mismatched_ciphertext(key_file):
    key = open(key_file, 'rb').read()
    stale = SecureString('new-value', ciphertext=_token(key, 'old-value'))
    garbage = SecureString('other', ciphertext='not-a-token')
    dumped = yaml.dump({'a': stale, 'b': garbage}, Dumper=keylocker_dumper(key_file))
    assert yaml.load(dumped, Loader=keylocker_loader(key_file)) == {'a': 'new-value', 'b': 'other'}


def test_plain_load_returns_plain_str(tmp_path, key_file):
    key = open(key_file, 'rb').read()
    data = load_yaml_secrets(_write(tmp_path, f"a: !SEC {_token(key, 'x')}"), key_file)
    assert type(data['a']) is str
    yaml.safe_dump(data)


def test_secure_string_default_has_no_ciphertext():
    assert SecureString("x").ciphertext is None
