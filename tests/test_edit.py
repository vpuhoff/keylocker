# tests/test_edit.py
# `keylocker edit`: decrypt into an editor, encrypt back on save.

import logging
import os
import sys

import pytest
import yaml
from cryptography.fernet import Fernet, MultiFernet

import keylocker
from keylocker import (
    ConfigError,
    DecryptionError,
    Manager,
    load_yaml_secrets,
    main,
    DEFAULT_KEY_FILE,
    ENV_VAR_NAME,
    KEY_FILE_ENV_VAR,
)


@pytest.fixture(autouse=True)
def clean_env(monkeypatch, caplog):
    for name in (ENV_VAR_NAME, KEY_FILE_ENV_VAR, 'VISUAL', 'EDITOR'):
        monkeypatch.delenv(name, raising=False)
    caplog.set_level(logging.INFO, logger="keylocker")


@pytest.fixture
def key(tmp_path):
    return Fernet.generate_key()


@pytest.fixture
def key_file(tmp_path, key):
    path = tmp_path / DEFAULT_KEY_FILE
    path.write_bytes(key)
    return str(path)


def _token(key, value):
    return Fernet(key).encrypt(value.encode()).decode()


def _write(tmp_path, content, name="config.yaml"):
    path = tmp_path / name
    path.write_bytes(content.encode())
    return str(path)


class FakeEditor:
    """Replaces _run_editor: records what the user saw and applies scripted edits."""
    def __init__(self, *edits, code=0):
        self.edits, self.code = list(edits), code
        self.seen, self.paths = [], []

    def __call__(self, path):
        self.paths.append(path)
        with open(path, encoding='utf-8', newline='') as f:
            text = f.read()
        self.seen.append(text)
        if self.edits:
            edit = self.edits.pop(0)
            with open(path, 'w', encoding='utf-8', newline='') as f:
                f.write(edit(text) if callable(edit) else edit)
        return self.code


@pytest.fixture
def editor(monkeypatch):
    def install(*edits, code=0):
        fake = FakeEditor(*edits, code=code)
        monkeypatch.setattr(keylocker, '_run_editor', fake)
        return fake
    return install


SOURCE = """# database settings
db:
  password: !SEC {password}  # rotated yearly
  user: admin
api:
  key: !ENV API_KEY:-dev
  token: !SEC {token}
"""


@pytest.fixture
def config(tmp_path, key):
    return _write(tmp_path, SOURCE.format(password=_token(key, 'p@ss'), token=_token(key, 'tkn')))


def test_edit_shows_plaintext_and_keeps_layout(config, key_file, editor):
    fake = editor()
    Manager(key_file).edit(config)
    assert fake.seen[0] == SOURCE.format(password='"p@ss"', token='"tkn"')


def test_edit_without_changes_leaves_file_untouched(config, key_file, editor, caplog):
    before = open(config, 'rb').read()
    editor()
    Manager(key_file).edit(config)
    assert open(config, 'rb').read() == before
    assert "No changes" in caplog.text


def test_edit_changes_only_edited_secret(config, key_file, editor, caplog):
    before = open(config).read()
    editor(lambda text: text.replace('"p@ss"', '"n3w pass"')
           + 'extra: !SEC added-secret\n')
    Manager(key_file).edit(config)
    after = open(config).read()

    old_lines, new_lines = before.splitlines(), after.splitlines()
    changed = [i for i, (a, b) in enumerate(zip(old_lines, new_lines)) if a != b]
    assert changed == [2]
    assert new_lines[2].startswith("  password: !SEC gAAAAA") and new_lines[2].endswith("  # rotated yearly")
    assert new_lines[-1].startswith("extra: !SEC gAAAAA")
    assert "added-secret" not in after and "n3w pass" not in after
    loaded = load_yaml_secrets(config, key_file)
    assert loaded['db']['password'] == 'n3w pass'
    assert loaded['api'] == {'key': 'dev', 'token': 'tkn'}
    assert loaded['extra'] == 'added-secret'
    assert "Saved" in caplog.text


@pytest.mark.parametrize("secret", [
    "привет мир", "multi\nline\nsecret\n", 'quotes "\' and \\ backslash',
    "tab\tand\x85nel\x7f", "  padded  ", "", "# not a comment", "key: value",
])
def test_edit_roundtrips_awkward_values(tmp_path, key, key_file, editor, secret):
    path = _write(tmp_path, f"a: !SEC {_token(key, secret)}\nb: !SEC {_token(key, 'x')}\n")
    editor(lambda text: text.replace('"x"', '"y"'))
    Manager(key_file).edit(path)
    assert load_yaml_secrets(path, key_file) == {'a': secret, 'b': 'y'}


def test_edit_temp_file_is_private_and_removed(config, key_file, editor):
    modes = []
    fake = editor(lambda text: modes.append(os.stat(fake.paths[0]).st_mode & 0o777) or text)
    Manager(key_file).edit(config)
    assert not os.path.exists(fake.paths[0])
    assert fake.paths[0].endswith('.yaml')
    if os.name != 'nt':
        assert modes == [0o600]


def test_edit_editor_failure_leaves_file(config, key_file, editor, caplog):
    before = open(config, 'rb').read()
    fake = editor(lambda text: text.replace('"p@ss"', '"changed"'), code=3)
    with pytest.raises(SystemExit) as excinfo:
        Manager(key_file).edit(config)
    assert excinfo.value.code == 1
    assert open(config, 'rb').read() == before
    assert not os.path.exists(fake.paths[0])
    assert "exited with code 3" in caplog.text


def test_edit_editor_missing(config, key_file, monkeypatch, caplog):
    monkeypatch.setattr(keylocker, '_run_editor', lambda path: (_ for _ in ()).throw(
        FileNotFoundError("no such editor")))
    with pytest.raises(SystemExit) as excinfo:
        Manager(key_file).edit(config)
    assert excinfo.value.code == 1
    assert "Could not start editor" in caplog.text


def test_edit_invalid_yaml_reopens_editor(config, key_file, editor, monkeypatch):
    monkeypatch.setattr(keylocker, '_confirm', lambda prompt: True)
    fake = editor("a: [broken\n", "a: !SEC fixed\n")
    Manager(key_file).edit(config)
    assert fake.seen[1] == "a: [broken\n"
    assert load_yaml_secrets(config, key_file) == {'a': 'fixed'}


def test_edit_invalid_yaml_declined(config, key_file, editor, monkeypatch, caplog):
    before = open(config, 'rb').read()
    monkeypatch.setattr(keylocker, '_confirm', lambda prompt: False)
    fake = editor("a: [broken\n")
    with pytest.raises(SystemExit) as excinfo:
        Manager(key_file).edit(config)
    assert excinfo.value.code == 1
    assert open(config, 'rb').read() == before
    assert not os.path.exists(fake.paths[0])
    assert "Failed to parse" in caplog.text and "left unchanged" in caplog.text


def test_edit_rejects_sec_on_non_scalar(config, key_file, editor, monkeypatch, caplog):
    monkeypatch.setattr(keylocker, '_confirm', lambda prompt: False)
    editor("a: !SEC [1, 2]\n")
    with pytest.raises(SystemExit):
        Manager(key_file).edit(config)
    assert "must tag a single string value" in caplog.text


def test_edit_editor_deleting_file(config, key_file, monkeypatch, caplog):
    before = open(config, 'rb').read()
    monkeypatch.setattr(keylocker, '_confirm', lambda prompt: False)
    monkeypatch.setattr(keylocker, '_run_editor', lambda path: (os.unlink(path), 0)[1])
    with pytest.raises(SystemExit):
        Manager(key_file).edit(config)
    assert open(config, 'rb').read() == before


def test_edit_strips_bom_added_by_editor(config, key_file, editor):
    editor(lambda text: '\ufeff' + text)
    before = open(config, 'rb').read()
    Manager(key_file).edit(config)
    assert open(config, 'rb').read() == before


def test_edit_restores_lf_after_crlf_editor(config, key_file, editor):
    before = open(config, 'rb').read()
    editor(lambda text: text.replace('\n', '\r\n').replace('"tkn"', '"new"'))
    Manager(key_file).edit(config)
    after = open(config, 'rb').read()
    assert b'\r\n' not in after
    assert after.splitlines()[:5] == before.splitlines()[:5]


def test_edit_keeps_crlf_files(tmp_path, key, key_file, editor):
    path = _write(tmp_path, f"a: !SEC {_token(key, 'x')}\r\nb: 1\r\n")
    editor(lambda text: text.replace('"x"', '"y"'))
    Manager(key_file).edit(path)
    assert open(path, 'rb').read().endswith(b"\r\nb: 1\r\n")


def test_edit_wrong_key_does_not_open_editor(tmp_path, key_file, editor, caplog):
    path = _write(tmp_path, f"a: !SEC {_token(Fernet.generate_key(), 'x')}\n")
    fake = editor()
    with pytest.raises(SystemExit) as excinfo:
        Manager(key_file).edit(path)
    assert excinfo.value.code == 1
    assert fake.paths == []
    assert "line 1, column 4" in caplog.text


def test_edit_missing_file(tmp_path, key_file, editor):
    with pytest.raises(SystemExit) as excinfo:
        Manager(key_file).edit(str(tmp_path / "missing.yaml"))
    assert excinfo.value.code == 1


def test_edit_non_utf8_file(tmp_path, key_file, editor, caplog):
    path = tmp_path / "latin1.yaml"
    path.write_bytes("a: caf\xe9\n".encode('latin-1'))
    with pytest.raises(SystemExit):
        Manager(key_file).edit(str(path))
    assert "Failed to parse" in caplog.text


def test_edit_without_key(config, tmp_path, editor):
    with pytest.raises(SystemExit) as excinfo:
        Manager(str(tmp_path / "missing.key")).edit(config)
    assert excinfo.value.code == 1


def test_edit_write_failure(config, key_file, editor, monkeypatch, caplog):
    before = open(config, 'rb').read()
    editor(lambda text: text.replace('"tkn"', '"other"'))
    monkeypatch.setattr(keylocker, '_atomic_replace', lambda *a, **kw: (_ for _ in ()).throw(
        OSError("read-only")))
    with pytest.raises(SystemExit) as excinfo:
        Manager(key_file).edit(config)
    assert excinfo.value.code == 1
    assert open(config, 'rb').read() == before
    assert "read-only" in caplog.text


@pytest.mark.skipif(os.name == 'nt', reason="POSIX permissions")
def test_edit_keeps_file_mode(config, key_file, editor):
    os.chmod(config, 0o640)
    editor(lambda text: text.replace('"tkn"', '"other"'))
    Manager(key_file).edit(config)
    assert (os.stat(config).st_mode & 0o777) == 0o640


def test_edit_reuses_tokens_of_old_keys(tmp_path, key, key_file, editor):
    """Unchanged values keep their token even if it was made with a non-primary key."""
    Manager(key_file).init(rotate=True)
    old_token = _token(key, 'old')
    path = _write(tmp_path, f"a: !SEC {old_token}\nb: !SEC {_token(key, 'x')}\n")
    editor(lambda text: text.replace('"x"', '"y"'))
    Manager(key_file).edit(path)
    assert old_token in open(path).read()


def test_cli_edit(config, key_file, editor):
    editor(lambda text: text.replace('"tkn"', '"via-cli"'))
    assert main(['edit', '--key-file', key_file, config]) == 0
    assert load_yaml_secrets(config, key_file)['api']['token'] == 'via-cli'


# === Library helpers ===

def test_decrypt_and_encrypt_helpers(key):
    fernet = MultiFernet([Fernet(key)])
    token = _token(key, 's')
    text, known = keylocker._decrypt_for_edit(f"a: &x !SEC {token}\nb: *x\nc: !<!SEC> {token}\n", fernet)
    assert text == 'a: &x !SEC "s"\nb: *x\nc: !<!SEC> "s"\n'
    assert keylocker._encrypt_after_edit(text, fernet, known) == f"a: &x !SEC {token}\nb: *x\nc: !<!SEC> {token}\n"
    fresh = keylocker._encrypt_after_edit("a: !SEC new\n", fernet)
    assert fernet.decrypt(fresh.split()[-1].encode()) == b"new"


def test_block_scalar_keeps_following_lines(key):
    fernet = MultiFernet([Fernet(key)])
    token = _token(key, 'blk')
    source = f"a: !SEC |\n  {token}\n\nb: 1\n"
    text, known = keylocker._decrypt_for_edit(source, fernet)
    assert text == 'a: !SEC "blk"\n\nb: 1\n'
    assert keylocker._encrypt_after_edit(text, fernet, known) == f"a: !SEC {token}\n\nb: 1\n"


def test_encrypt_after_edit_failure_hides_plaintext():
    class Broken:
        def encrypt(self, data):
            raise RuntimeError("boom")
    with pytest.raises(keylocker.EncryptionError, match="line 1, column 4.*RuntimeError") as excinfo:
        keylocker._encrypt_after_edit("a: !SEC topsecret\n", Broken())
    assert "topsecret" not in str(excinfo.value)


def test_decrypt_for_edit_invalid_yaml(key):
    with pytest.raises(ConfigError, match="'cfg.yaml'"):
        keylocker._decrypt_for_edit("a: [", MultiFernet([Fernet(key)]), "cfg.yaml")


def test_decrypt_for_edit_bad_token(key):
    with pytest.raises(DecryptionError):
        keylocker._decrypt_for_edit("a: !SEC nope\n", MultiFernet([Fernet(key)]))


# === Editor launching ===

@pytest.mark.parametrize("windows, default", [(True, 'notepad'), (False, 'vi')])
def test_editor_command_default(monkeypatch, windows, default):
    monkeypatch.setattr(keylocker, '_WINDOWS', windows)
    assert keylocker._editor_command() == default


def test_editor_command_precedence(monkeypatch):
    monkeypatch.setenv('EDITOR', 'nano')
    assert keylocker._editor_command() == 'nano'
    monkeypatch.setenv('VISUAL', 'code --wait')
    assert keylocker._editor_command() == 'code --wait'


def test_run_editor_executes_command_with_arguments(tmp_path, monkeypatch):
    script = tmp_path / "ed it.py"
    script.write_text("import sys\nopen(sys.argv[-1], 'a').write('edited\\n')\n")
    monkeypatch.setenv('EDITOR', f'"{sys.executable}" "{script}"')
    target = tmp_path / "with space.yaml"
    target.write_text("")
    assert keylocker._run_editor(str(target)) == 0
    assert target.read_text() == "edited\n"


def _record_call(monkeypatch, code=0):
    calls = []
    monkeypatch.setattr(keylocker.subprocess, 'call',
                        lambda *args, **kwargs: calls.append((args, kwargs)) or code)
    return calls


def test_run_editor_windows_uses_shell(monkeypatch):
    monkeypatch.setattr(keylocker, '_WINDOWS', True)
    monkeypatch.setenv('EDITOR', 'code --wait')
    calls = _record_call(monkeypatch, code=5)
    assert keylocker._run_editor(r'C:\Temp dir\keylocker-1.yaml') == 5
    assert calls == [(('code --wait "C:\\Temp dir\\keylocker-1.yaml"',), {'shell': True})]


def test_run_editor_posix_splits_command(monkeypatch):
    monkeypatch.setattr(keylocker, '_WINDOWS', False)
    monkeypatch.setenv('EDITOR', "'/opt/my editor/bin/ed' --wait -n")
    calls = _record_call(monkeypatch)
    assert keylocker._run_editor('/dev/shm/keylocker 1.yaml') == 0
    assert calls == [((['/opt/my editor/bin/ed', '--wait', '-n', '/dev/shm/keylocker 1.yaml'],), {})]


def test_confirm(monkeypatch, capsys):
    class Stdin:
        def __init__(self, answer, tty=True):
            self.answer, self.tty = answer, tty
        def isatty(self):
            return self.tty
        def readline(self):
            return self.answer
    for answer, expected in [("\n", True), ("y\n", True), ("YES\n", True), ("n\n", False)]:
        monkeypatch.setattr(sys, 'stdin', Stdin(answer))
        assert keylocker._confirm("? ") is expected
    assert "? " in capsys.readouterr().err
    monkeypatch.setattr(sys, 'stdin', Stdin("y\n", tty=False))
    assert keylocker._confirm("? ") is False


@pytest.mark.parametrize("shm, expected", [(True, '/dev/shm'), (False, None)])
def test_plaintext_tempfile_location(monkeypatch, shm, expected):
    calls = []
    monkeypatch.setattr(os.path, 'isdir', lambda p: shm)
    monkeypatch.setattr(os, 'access', lambda p, mode: True)
    monkeypatch.setattr(keylocker.tempfile, 'mkstemp', lambda **kw: calls.append(kw) or (0, 'x'))
    keylocker._plaintext_tempfile('.yaml')
    assert calls == [{'prefix': 'keylocker-', 'suffix': '.yaml', 'dir': expected}]
