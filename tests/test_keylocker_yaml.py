# tests/test_keylocker_yaml.py

import pytest
import os
import yaml
# Импортируем необходимые части из обновленного keylocker
import sys
import builtins
import subprocess
import runpy

from cryptography.fernet import Fernet

import keylocker
from keylocker import (
    Manager,
    load_yaml_secrets,
    encrypt_string_value,
    _load_fernet_key,
    keylocker_loader,
    keylocker_dumper,
    SecureString,
    EnvVariable,
    KeylockerError,
    EncryptionError,
    DecryptionError,
    # Вспомогательные переменные или функции, если они доступны и нужны
    DEFAULT_KEY_FILE,
    ENV_VAR_NAME # Имя переменной окружения с ключом
)

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(keylocker.__file__)))

# --- Fixtures ---

@pytest.fixture(scope="function")
def temp_dir(tmp_path_factory):
    """Создает временную директорию для каждого теста."""
    return tmp_path_factory.mktemp("keylocker_test")

@pytest.fixture(scope="function")
def key_file_in_temp_dir(temp_dir):
    """Путь к файлу ключа во временной директории теста."""
    return temp_dir / DEFAULT_KEY_FILE

@pytest.fixture(scope="function")
def generated_key_file(key_file_in_temp_dir):
    """Фикстура для создания валидного файла ключа во временной директории."""
    manager = Manager(key_file=str(key_file_in_temp_dir))
    manager.init(force=True)
    assert key_file_in_temp_dir.exists()
    return str(key_file_in_temp_dir)

@pytest.fixture(scope="function")
def valid_fernet_key():
    """Генерирует и возвращает валидный ключ Fernet в виде байтов."""
    return Fernet.generate_key()

@pytest.fixture(scope="function")
def set_env_key(monkeypatch, valid_fernet_key):
    """Фикстура для установки переменной окружения с ключом."""
    key_str = valid_fernet_key.decode('utf-8')
    monkeypatch.setenv(ENV_VAR_NAME, key_str)
    # Возвращаем сам ключ для возможного использования в тесте
    yield valid_fernet_key
    # Очистка происходит автоматически благодаря monkeypatch

@pytest.fixture(scope="function")
def set_env_key_invalid(monkeypatch):
    """Фикстура для установки переменной окружения с НЕвалидным ключом."""
    monkeypatch.setenv(ENV_VAR_NAME, "not-a-valid-fernet-key")

@pytest.fixture(scope="function")
def unset_env_key(monkeypatch):
    """Фикстура для гарантии, что переменная окружения НЕ установлена."""
    monkeypatch.delenv(ENV_VAR_NAME, raising=False) # Не вызывать ошибку, если ее и так нет

@pytest.fixture
def yaml_file_factory(temp_dir):
    """Фабрика для создания временных YAML файлов с заданным содержимым."""
    def _create_yaml(filename="test_config.yaml", content=""):
        yaml_path = temp_dir / filename
        yaml_path.write_text(content)
        return str(yaml_path)
    return _create_yaml

# --- Test Functions ---

# === Тесты команды init ===
def test_init_creates_key_file(key_file_in_temp_dir, unset_env_key):
    """Тест: keylocker init создает файл ключа."""
    assert not key_file_in_temp_dir.exists()
    manager = Manager(key_file=str(key_file_in_temp_dir))
    manager.init()
    assert key_file_in_temp_dir.exists()
    # Проверим, что ключ валиден
    key_bytes = key_file_in_temp_dir.read_bytes()
    assert len(key_bytes) > 30
    Fernet(key_bytes) # Должно работать без исключений

def test_init_does_not_overwrite_by_default(generated_key_file, unset_env_key):
    """Тест: keylocker init не перезаписывает существующий ключ без --force."""
    manager = Manager(key_file=generated_key_file)
    initial_content = open(generated_key_file, 'rb').read()
    result = manager.init() # Без force
    assert "already exists" in result
    assert open(generated_key_file, 'rb').read() == initial_content

def test_init_force_overwrites(generated_key_file, unset_env_key):
    """Тест: keylocker init --force перезаписывает существующий ключ."""
    manager = Manager(key_file=generated_key_file)
    initial_content = open(generated_key_file, 'rb').read()
    result = manager.init(force=True)
    assert "created." in result
    # Убедимся, что файл действительно перезаписан
    assert open(generated_key_file, 'rb').read() != initial_content

# === Тесты шифрования (encrypt_string_value) ===
def test_encrypt_string_with_file_key(generated_key_file, unset_env_key):
    """Тест шифрования строки с использованием ключа из файла."""
    plain_text = "secret file data"
    encrypted_tag = encrypt_string_value(plain_text, generated_key_file)
    assert encrypted_tag is not None
    assert encrypted_tag.startswith("!SEC ")
    # Расшифруем для проверки
    key_bytes = open(generated_key_file, 'rb').read()
    fernet = Fernet(key_bytes)
    decrypted = fernet.decrypt(encrypted_tag.split(" ", 1)[1].encode()).decode()
    assert decrypted == plain_text

def test_encrypt_string_with_env_key(set_env_key):
    """Тест шифрования строки с использованием ключа из переменной окружения."""
    env_key_bytes = set_env_key # Получаем ключ из фикстуры
    plain_text = "secret env data"
    # Передаем любой путь к файлу, он не должен использоваться
    encrypted_tag = encrypt_string_value(plain_text, "non_existent_file.key")
    assert encrypted_tag is not None
    assert encrypted_tag.startswith("!SEC ")
    # Расшифруем для проверки
    fernet = Fernet(env_key_bytes)
    decrypted = fernet.decrypt(encrypted_tag.split(" ", 1)[1].encode()).decode()
    assert decrypted == plain_text

def test_encrypt_string_no_key(key_file_in_temp_dir, unset_env_key):
    """Тест: Шифрование не работает без ключа (ни файла, ни env var)."""
    assert not key_file_in_temp_dir.exists() # Убедимся, что файла нет
    encrypted_tag = encrypt_string_value("data", str(key_file_in_temp_dir))
    assert encrypted_tag is None # Ожидаем ошибку (None)

# === Тесты загрузки YAML (load_yaml_secrets) ===
def test_load_yaml_with_file_key(yaml_file_factory, generated_key_file, unset_env_key, monkeypatch):
    """Тест загрузки YAML с !SEC и !ENV, используя ключ из файла."""
    secret_value = "file_key_secret"
    env_var = "TEST_VAR_FILE"
    env_val = "file_key_env_val"
    monkeypatch.setenv(env_var, env_val)

    encrypted_tag = encrypt_string_value(secret_value, generated_key_file)
    yaml_content = f"""
    db_pass: {encrypted_tag}
    api_key: !ENV {env_var}
    plain: value
    """
    yaml_path = yaml_file_factory("config_file.yaml", yaml_content)

    loaded_data = load_yaml_secrets(yaml_path, generated_key_file)
    assert loaded_data is not None
    assert loaded_data['db_pass'] == secret_value
    assert loaded_data['api_key'] == env_val
    assert loaded_data['plain'] == 'value'

def test_load_yaml_with_env_key(yaml_file_factory, set_env_key, key_file_in_temp_dir, monkeypatch):
    """Тест загрузки YAML с !SEC и !ENV, используя ключ из переменной окружения."""
    env_key_bytes = set_env_key
    fernet = Fernet(env_key_bytes)

    secret_value = "env_key_secret"
    env_var = "TEST_VAR_ENV"
    env_val = "env_key_env_val"
    monkeypatch.setenv(env_var, env_val)

    # Шифруем значение ключом из env var для теста
    encrypted_val = fernet.encrypt(secret_value.encode()).decode()
    encrypted_tag = f"!SEC {encrypted_val}"

    yaml_content = f"""
    db_pass: {encrypted_tag}
    api_key: !ENV {env_var}
    plain: value2
    """
    # Файл ключа не должен существовать или использоваться
    assert not key_file_in_temp_dir.exists()
    yaml_path = yaml_file_factory("config_env.yaml", yaml_content)

    # Передаем путь к несуществующему файлу, т.к. ключ берется из env
    loaded_data = load_yaml_secrets(yaml_path, str(key_file_in_temp_dir))
    assert loaded_data is not None
    assert loaded_data['db_pass'] == secret_value
    assert loaded_data['api_key'] == env_val
    assert loaded_data['plain'] == 'value2'

def test_load_yaml_no_key_fails_sec(yaml_file_factory, key_file_in_temp_dir, unset_env_key, capsys):
    """Тест: Загрузка YAML с !SEC без ключа -> DecryptionError (fail closed)."""
    yaml_content = """
    secret: !SEC GAAAAAB...invalid...
    plain: value
    """
    yaml_path = yaml_file_factory("config_no_key.yaml", yaml_content)
    assert not key_file_in_temp_dir.exists() # Файла нет

    with pytest.raises(DecryptionError, match="no valid key is loaded"):
        load_yaml_secrets(yaml_path, str(key_file_in_temp_dir))
    captured = capsys.readouterr()
    assert "No encryption key loaded" in captured.err # Должно быть предупреждение
    assert captured.out == ""

def test_load_yaml_no_key_without_sec(yaml_file_factory, key_file_in_temp_dir, unset_env_key):
    """Тест: YAML без !SEC загружается и без ключа."""
    yaml_path = yaml_file_factory("plain.yaml", "plain: value")
    assert load_yaml_secrets(yaml_path, str(key_file_in_temp_dir)) == {'plain': 'value'}

def test_load_yaml_env_not_set(yaml_file_factory, generated_key_file, unset_env_key, capsys):
    """Тест: !ENV возвращает None и выводит предупреждение, если переменная не установлена."""
    env_var = "UNSET_TEST_VAR"
    yaml_content = f"""
    config_val: !ENV {env_var}
    """
    yaml_path = yaml_file_factory("config_unset_env.yaml", yaml_content)

    loaded_data = load_yaml_secrets(yaml_path, generated_key_file)
    assert loaded_data is not None
    assert loaded_data['config_val'] is None # Ожидаем None
    captured = capsys.readouterr()
    assert f"Environment variable '{env_var}' (tagged !ENV) not found" in captured.err

# === Тесты ошибок загрузки ключа (_load_fernet_key) ===

def test_load_fernet_key_invalid_env_key(set_env_key_invalid, capsys):
    """Тест: невалидный ключ в переменной окружения -> None + ошибка."""
    result = _load_fernet_key("nonexistent.key")
    assert result is None
    captured = capsys.readouterr()
    assert "Invalid key format found in environment variable" in captured.err

def test_load_fernet_key_invalid_file_key(key_file_in_temp_dir, unset_env_key, capsys):
    """Тест: невалидное содержимое файла ключа -> None + ошибка."""
    key_file_in_temp_dir.write_text("not-a-valid-fernet-key")
    result = _load_fernet_key(str(key_file_in_temp_dir))
    assert result is None
    captured = capsys.readouterr()
    assert f"Invalid key format in file '{key_file_in_temp_dir}'" in captured.err

def test_load_fernet_key_unreadable_file(temp_dir, unset_env_key, capsys):
    """Тест: путь ключа указывает на директорию -> IOError -> None + ошибка."""
    result = _load_fernet_key(str(temp_dir))
    assert result is None
    captured = capsys.readouterr()
    assert "Could not read key file" in captured.err

def test_load_fernet_key_unexpected_read_error(temp_dir, unset_env_key, monkeypatch, capsys):
    """Тест: непредвиденная ошибка при чтении файла ключа -> None + ошибка."""
    key_path = temp_dir / "weird.key"
    key_path.write_bytes(Fernet.generate_key())
    real_open = builtins.open
    def failing_open(file, *args, **kwargs):
        if str(file) == str(key_path):
            raise RuntimeError("boom")
        return real_open(file, *args, **kwargs)
    monkeypatch.setattr(builtins, 'open', failing_open)
    result = _load_fernet_key(str(key_path))
    assert result is None
    captured = capsys.readouterr()
    assert "Unexpected error reading key file" in captured.err

def test_load_fernet_key_env_unexpected_error(monkeypatch, capsys):
    """Тест: непредвиденная ошибка валидации ключа из env -> None + ошибка."""
    monkeypatch.setenv(ENV_VAR_NAME, Fernet.generate_key().decode())
    monkeypatch.setattr(keylocker, 'Fernet', lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("boom")))
    result = _load_fernet_key("nonexistent.key")
    assert result is None
    captured = capsys.readouterr()
    assert "Unexpected error validating key from env var" in captured.err

# === Тесты граничных случаев загрузки YAML ===

def test_load_yaml_file_not_found(unset_env_key, capsys):
    """Тест: несуществующий YAML файл -> None + ошибка."""
    result = load_yaml_secrets("no_such_file.yaml")
    assert result is None
    captured = capsys.readouterr()
    assert "not found" in captured.err

def test_load_yaml_invalid_yaml(yaml_file_factory, unset_env_key, capsys):
    """Тест: синтаксически невалидный YAML -> None + ошибка."""
    yaml_path = yaml_file_factory("broken.yaml", "key: [unclosed")
    result = load_yaml_secrets(yaml_path)
    assert result is None
    captured = capsys.readouterr()
    assert "Failed to parse YAML file" in captured.err

def test_load_yaml_unexpected_error(temp_dir, unset_env_key, capsys):
    """Тест: неожиданная ошибка при загрузке (путь - директория) -> None + ошибка."""
    result = load_yaml_secrets(str(temp_dir))
    assert result is None
    captured = capsys.readouterr()
    assert "unexpected error occurred during YAML load" in captured.err

def test_load_yaml_invalid_sec_token(yaml_file_factory, generated_key_file, unset_env_key):
    """Тест: !SEC зашифрован другим ключом -> DecryptionError."""
    other_key = Fernet.generate_key()
    other_fernet = Fernet(other_key)
    encrypted_val = other_fernet.encrypt(b"other-key-secret").decode()
    yaml_content = f"secret: !SEC {encrypted_val}"
    yaml_path = yaml_file_factory("mismatched_key.yaml", yaml_content)

    with pytest.raises(DecryptionError, match="invalid token or key mismatch") as excinfo:
        load_yaml_secrets(yaml_path, generated_key_file)
    assert isinstance(excinfo.value, KeylockerError)
    assert "line 1" in str(excinfo.value)

# === Тесты дампера (keylocker_dumper) ===

def test_dumper_no_key(key_file_in_temp_dir, unset_env_key, capsys):
    """Тест: дамп SecureString без ключа -> EncryptionError, открытый текст не утекает."""
    assert not key_file_in_temp_dir.exists()
    dumper = keylocker_dumper(str(key_file_in_temp_dir))
    with pytest.raises(EncryptionError) as excinfo:
        yaml.dump({'secret': SecureString("sensitive")}, Dumper=dumper)
    assert "sensitive" not in str(excinfo.value)
    captured = capsys.readouterr()
    assert "Cannot encrypt values for !SEC tags" in captured.err
    assert "sensitive" not in captured.out + captured.err

def test_dumper_no_key_env_only(key_file_in_temp_dir, unset_env_key):
    """Тест: без ключа дампер по-прежнему пишет !ENV."""
    dumper = keylocker_dumper(str(key_file_in_temp_dir))
    assert yaml.dump({'api_key': EnvVariable("API_KEY")}, Dumper=dumper).strip() == "api_key: !ENV 'API_KEY'"

def test_dumper_roundtrip(yaml_file_factory, generated_key_file, unset_env_key, monkeypatch):
    """Тест: дамп !SEC/!ENV и обратная загрузка через loader."""
    env_var = "DUMPER_TEST_VAR"
    env_val = "dumper_env_val"
    monkeypatch.setenv(env_var, env_val)

    data = {
        'password': SecureString("roundtrip_secret"),
        'api_key': EnvVariable(env_var),
    }
    dumped = yaml.dump(data, Dumper=keylocker_dumper(generated_key_file))
    assert '!SEC ' in dumped
    assert '!ENV' in dumped and env_var in dumped

    yaml_path = yaml_file_factory("roundtrip.yaml", dumped)
    loaded = load_yaml_secrets(yaml_path, generated_key_file)
    assert loaded['password'] == "roundtrip_secret"
    assert loaded['api_key'] == env_val

# === Тесты CLI Manager ===

def test_manager_encrypt_no_key_exits(key_file_in_temp_dir, unset_env_key):
    """Тест: encrypt без ключа -> sys.exit(1)."""
    assert not key_file_in_temp_dir.exists()
    manager = Manager(key_file=str(key_file_in_temp_dir))
    with pytest.raises(SystemExit) as excinfo:
        manager.encrypt("secret")
    assert excinfo.value.code == 1

def test_manager_encrypt_success(generated_key_file, unset_env_key, capsys):
    """Тест: encrypt с валидным ключом печатает !SEC тег."""
    manager = Manager(key_file=generated_key_file)
    manager.encrypt("cli_secret")
    captured = capsys.readouterr()
    assert "Add the following line to your YAML file:" in captured.err
    assert "command-line argument" in captured.err
    assert captured.out.startswith("!SEC ")
    assert len(captured.out.splitlines()) == 1

def test_manager_encrypt_failure_exits(generated_key_file, unset_env_key, monkeypatch):
    """Тест: encrypt при ошибке шифрования -> sys.exit(1)."""
    monkeypatch.setattr(keylocker, 'encrypt_string_value', lambda v, kf=None: None)
    manager = Manager(key_file=generated_key_file)
    with pytest.raises(SystemExit) as excinfo:
        manager.encrypt("secret")
    assert excinfo.value.code == 1

def test_manager_view_success(yaml_file_factory, generated_key_file, unset_env_key, monkeypatch, capsys):
    """Тест: view печатает расшифрованный YAML."""
    secret_value = "view_secret"
    env_var = "VIEW_TEST_VAR"
    env_val = "view_env_val"
    monkeypatch.setenv(env_var, env_val)
    encrypted_tag = encrypt_string_value(secret_value, generated_key_file)
    yaml_path = yaml_file_factory("view_config.yaml", f"password: {encrypted_tag}\napi_key: !ENV {env_var}")

    manager = Manager(key_file=generated_key_file)
    manager.view(yaml_path)
    captured = capsys.readouterr()
    assert yaml.safe_load(captured.out) == {'password': secret_value, 'api_key': env_val}

def test_manager_view_failure_exits(generated_key_file, unset_env_key):
    """Тест: view несуществующего файла -> sys.exit(1)."""
    manager = Manager(key_file=generated_key_file)
    with pytest.raises(SystemExit) as excinfo:
        manager.view("no_such_config.yaml")
    assert excinfo.value.code == 1

def test_manager_view_decryption_error_exits(yaml_file_factory, generated_key_file, unset_env_key, capsys):
    """Тест: view с нерасшифровываемым !SEC -> sys.exit(1), ничего в stdout."""
    encrypted_val = Fernet(Fernet.generate_key()).encrypt(b"x").decode()
    yaml_path = yaml_file_factory("bad_view.yaml", f"secret: !SEC {encrypted_val}")
    manager = Manager(key_file=generated_key_file)
    with pytest.raises(SystemExit) as excinfo:
        manager.view(yaml_path)
    assert excinfo.value.code == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "invalid token or key mismatch" in captured.err

def test_manager_view_env_key_stdout_is_pure_yaml(yaml_file_factory, set_env_key, capsys):
    """Тест: при ключе из env INFO уходит в stderr, stdout — валидный YAML."""
    encrypted_val = Fernet(set_env_key).encrypt(b"env_view_secret").decode()
    yaml_path = yaml_file_factory("env_view.yaml", f"password: !SEC {encrypted_val}")
    Manager(key_file="nonexistent.key").view(yaml_path)
    captured = capsys.readouterr()
    assert yaml.safe_load(captured.out) == {'password': 'env_view_secret'}
    assert f"Using encryption key from environment variable {ENV_VAR_NAME}" in captured.err

class _FakeStdin:
    def __init__(self, data, tty):
        self._data, self._tty = data, tty
    def isatty(self):
        return self._tty
    def read(self):
        return self._data

def _decrypt_tag(tag, key_file):
    return Fernet(open(key_file, 'rb').read()).decrypt(tag.split(" ", 1)[1].encode()).decode()

@pytest.mark.parametrize("piped, expected", [
    ("piped_secret\n", "piped_secret"),
    ("piped_secret\r\n", "piped_secret"),
    ("multi\nline\n", "multi\nline"),
    ("  spaced  ", "  spaced  "),
])
def test_manager_encrypt_from_stdin(generated_key_file, unset_env_key, monkeypatch, capsys, piped, expected):
    """Тест: encrypt без аргумента читает секрет из stdin."""
    monkeypatch.setattr(sys, 'stdin', _FakeStdin(piped, tty=False))
    Manager(key_file=generated_key_file).encrypt()
    captured = capsys.readouterr()
    assert _decrypt_tag(captured.out.strip(), generated_key_file) == expected
    assert "command-line argument" not in captured.err

def test_manager_encrypt_prompt(generated_key_file, unset_env_key, monkeypatch, capsys):
    """Тест: encrypt в терминале запрашивает секрет скрытым вводом с подтверждением."""
    monkeypatch.setattr(sys, 'stdin', _FakeStdin("", tty=True))
    answers = iter(["prompt_secret", "prompt_secret"])
    monkeypatch.setattr(keylocker.getpass, 'getpass', lambda prompt="": next(answers))
    Manager(key_file=generated_key_file).encrypt()
    captured = capsys.readouterr()
    assert _decrypt_tag(captured.out.strip(), generated_key_file) == "prompt_secret"

def test_manager_encrypt_prompt_mismatch_exits(generated_key_file, unset_env_key, monkeypatch, capsys):
    """Тест: несовпадение подтверждения -> sys.exit(1)."""
    monkeypatch.setattr(sys, 'stdin', _FakeStdin("", tty=True))
    answers = iter(["one", "two"])
    monkeypatch.setattr(keylocker.getpass, 'getpass', lambda prompt="": next(answers))
    with pytest.raises(SystemExit) as excinfo:
        Manager(key_file=generated_key_file).encrypt()
    assert excinfo.value.code == 1
    assert "do not match" in capsys.readouterr().err

def test_manager_encrypt_empty_exits(generated_key_file, unset_env_key, monkeypatch):
    """Тест: пустой секрет отклоняется."""
    monkeypatch.setattr(sys, 'stdin', _FakeStdin("\n", tty=False))
    with pytest.raises(SystemExit) as excinfo:
        Manager(key_file=generated_key_file).encrypt()
    assert excinfo.value.code == 1

@pytest.mark.skipif(os.name == 'nt', reason="POSIX permissions")
def test_init_key_file_permissions(key_file_in_temp_dir, unset_env_key):
    """Тест: init создаёт ключ с правами 0600 независимо от umask."""
    old_umask = os.umask(0o022)
    try:
        Manager(key_file=str(key_file_in_temp_dir)).init()
    finally:
        os.umask(old_umask)
    assert (key_file_in_temp_dir.stat().st_mode & 0o777) == 0o600

@pytest.mark.skipif(os.name == 'nt', reason="POSIX permissions")
def test_init_force_tightens_permissions(key_file_in_temp_dir, unset_env_key):
    """Тест: init --force исправляет права уже существующего файла."""
    key_file_in_temp_dir.write_bytes(b"old")
    os.chmod(key_file_in_temp_dir, 0o644)
    Manager(key_file=str(key_file_in_temp_dir)).init(force=True)
    assert (key_file_in_temp_dir.stat().st_mode & 0o777) == 0o600

@pytest.mark.parametrize("use_key", [True, False])
def test_decryption_error_does_not_leak_yaml_source(generated_key_file, unset_env_key, use_key):
    """Тест: DecryptionError не содержит фрагмент исходного YAML с соседними секретами."""
    key_file = generated_key_file if use_key else "nonexistent.key"
    with pytest.raises(DecryptionError) as excinfo:
        yaml.load("{key: S3CR3T, bad: !SEC invalid}", Loader=keylocker_loader(key_file))
    assert "S3CR3T" not in str(excinfo.value)
    assert "line 1, column 20" in str(excinfo.value)
    assert excinfo.value.__cause__ is None

@pytest.mark.skipif(os.name == 'nt', reason="POSIX symlinks")
def test_init_refuses_dangling_symlink(temp_dir, unset_env_key):
    """Тест: init без --force не создаёт ключ по цели висячего симлинка."""
    target = temp_dir / "elsewhere.key"
    link = temp_dir / DEFAULT_KEY_FILE
    os.symlink(target, link)
    result = Manager(key_file=str(link)).init()
    assert "already exists" in result
    assert not target.exists()
    assert os.path.islink(link)

@pytest.mark.skipif(os.name == 'nt', reason="POSIX symlinks")
def test_init_force_replaces_symlink_without_writing_target(temp_dir, unset_env_key):
    """Тест: init --force заменяет сам симлинк, не трогая файл, на который он указывает."""
    target = temp_dir / "victim.txt"
    target.write_bytes(b"do not touch")
    link = temp_dir / DEFAULT_KEY_FILE
    os.symlink(target, link)
    Manager(key_file=str(link)).init(force=True)
    assert target.read_bytes() == b"do not touch"
    assert not os.path.islink(link)
    Fernet(link.read_bytes())
    assert (link.stat().st_mode & 0o777) == 0o600

def test_init_race_does_not_overwrite(generated_key_file, unset_env_key, monkeypatch):
    """Тест: файл, появившийся после проверки, не перезаписывается без --force."""
    initial_content = open(generated_key_file, 'rb').read()
    monkeypatch.setattr(os.path, 'lexists', lambda p: False)
    result = Manager(key_file=generated_key_file).init()
    assert "already exists" in result
    assert open(generated_key_file, 'rb').read() == initial_content

def test_init_write_failure_removes_partial_file(key_file_in_temp_dir, unset_env_key, monkeypatch):
    """Тест: сбой записи без --force не оставляет частичный файл ключа."""
    def failing_write(fd, data):
        raise OSError("disk full")
    monkeypatch.setattr(keylocker, '_write_all', failing_write)
    with pytest.raises(SystemExit) as excinfo:
        Manager(key_file=str(key_file_in_temp_dir)).init()
    assert excinfo.value.code == 996
    assert not key_file_in_temp_dir.exists()

def test_init_force_failure_keeps_old_key_and_cleans_temp(generated_key_file, temp_dir, unset_env_key, monkeypatch):
    """Тест: сбой --force сохраняет старый ключ и удаляет временный файл."""
    initial_content = open(generated_key_file, 'rb').read()
    def failing_replace(src, dst):
        raise OSError("rename failed")
    monkeypatch.setattr(os, 'replace', failing_replace)
    with pytest.raises(SystemExit) as excinfo:
        Manager(key_file=generated_key_file).init(force=True)
    assert excinfo.value.code == 996
    assert open(generated_key_file, 'rb').read() == initial_content
    assert sorted(p.name for p in temp_dir.iterdir()) == [DEFAULT_KEY_FILE]

def test_manager_init_write_error(temp_dir, unset_env_key):
    """Тест: init в несуществующую директорию -> sys.exit(996)."""
    bad_path = temp_dir / "no_such_dir" / "storage.key"
    manager = Manager(key_file=str(bad_path))
    with pytest.raises(SystemExit) as excinfo:
        manager.init()
    assert excinfo.value.code == 996

def test_manager_init_existing_with_env_key(generated_key_file, monkeypatch, capsys):
    """Тест: init при существующем файле и установленной env-переменной -> подсказка о приоритете."""
    monkeypatch.setenv(ENV_VAR_NAME, Fernet.generate_key().decode())
    manager = Manager(key_file=generated_key_file)
    initial_content = open(generated_key_file, 'rb').read()
    result = manager.init()
    assert "already exists" in result
    assert open(generated_key_file, 'rb').read() == initial_content
    captured = capsys.readouterr()
    assert "will take precedence" in captured.err

def test_manager_init_force_with_env_key(generated_key_file, monkeypatch, capsys):
    """Тест: init --force с установленной env-переменной -> файл перезаписан + подсказка."""
    monkeypatch.setenv(ENV_VAR_NAME, Fernet.generate_key().decode())
    manager = Manager(key_file=generated_key_file)
    initial_content = open(generated_key_file, 'rb').read()
    result = manager.init(force=True)
    assert "created." in result
    assert open(generated_key_file, 'rb').read() != initial_content
    captured = capsys.readouterr()
    assert "will take precedence" in captured.err

# === Тесты точки входа ===

def test_main_no_args_prints_help(monkeypatch, capsys):
    """Тест: main() без аргументов выводит справку и не падает."""
    monkeypatch.setattr(sys, 'argv', ['keylocker'])
    keylocker.main()
    captured = capsys.readouterr()
    assert "keylocker" in captured.out or "keylocker" in captured.err

def test_main_module_entry(monkeypatch, capsys):
    """Тест: python -m keylocker без аргументов выводит справку."""
    monkeypatch.setattr(sys, 'argv', ['keylocker'])
    runpy.run_module('keylocker.__main__', run_name='__main__')
    captured = capsys.readouterr()
    assert "keylocker" in captured.out or "keylocker" in captured.err

# === Тесты сбойных веток Fernet (моки) ===

class _FlakyFernet:
    """Мок Fernet: конструктор валиден, но encrypt/decrypt падают."""
    def __init__(self, *args, **kwargs):
        pass
    def decrypt(self, data):
        raise RuntimeError("decrypt boom")
    def encrypt(self, data):
        raise RuntimeError("encrypt boom")

def test_loader_unexpected_decrypt_error(yaml_file_factory, set_env_key, monkeypatch):
    """Тест: непредвиденная ошибка при расшифровке !SEC -> DecryptionError."""
    monkeypatch.setattr(keylocker, 'Fernet', _FlakyFernet)
    yaml_path = yaml_file_factory("flaky.yaml", "secret: !SEC gAAAAABommitted")
    with pytest.raises(DecryptionError, match="Unexpected error during !SEC decryption.*RuntimeError"):
        load_yaml_secrets(yaml_path, "nonexistent.key")

def test_loader_fernet_init_failure(yaml_file_factory, monkeypatch, capsys):
    """Тест: битый ключ от _load_fernet_key -> Fernet init падает в loader."""
    monkeypatch.setattr(keylocker, '_load_fernet_key', lambda kf: b'not-a-fernet-key')
    Loader = keylocker_loader('nonexistent.key')
    captured = capsys.readouterr()
    assert "Failed to initialize Fernet with the loaded key" in captured.err

def test_dumper_fernet_init_failure(monkeypatch, capsys):
    """Тест: битый ключ от _load_fernet_key -> Fernet init падает в dumper."""
    monkeypatch.setattr(keylocker, '_load_fernet_key', lambda kf: b'not-a-fernet-key')
    dumper = keylocker_dumper('nonexistent.key')
    captured = capsys.readouterr()
    assert "Failed to initialize Fernet with the loaded key" in captured.err

def test_dumper_encrypt_failure(yaml_file_factory, set_env_key, monkeypatch):
    """Тест: сбой encrypt в representer -> EncryptionError без открытого текста."""
    monkeypatch.setattr(keylocker, 'Fernet', _FlakyFernet)
    dumper = keylocker_dumper('nonexistent.key')
    with pytest.raises(EncryptionError, match="RuntimeError") as excinfo:
        yaml.dump({'secret': SecureString("sensitive")}, Dumper=dumper)
    assert "sensitive" not in str(excinfo.value)

def test_encrypt_string_value_unexpected_error(set_env_key, monkeypatch, capsys):
    """Тест: непредвиденная ошибка при шифровании -> None + ошибка."""
    monkeypatch.setattr(keylocker, 'Fernet', _FlakyFernet)
    result = encrypt_string_value("data", "nonexistent.key")
    assert result is None
    captured = capsys.readouterr()
    assert "An unexpected error occurred during encryption" in captured.err

def test_load_fernet_key_file_vanishes(key_file_in_temp_dir, unset_env_key, monkeypatch, capsys):
    """Тест: файл ключа исчез между проверкой exists и open -> None + ошибка."""
    monkeypatch.setattr(os.path, 'exists', lambda p: True)
    result = _load_fernet_key(str(key_file_in_temp_dir))
    assert result is None
    captured = capsys.readouterr()
    assert "Key file" in captured.err and "not found" in captured.err

def test_init_module_guard(monkeypatch, capsys):
    """Тест: guard-строка if __name__ == '__main__' в __init__.py."""
    monkeypatch.setattr(sys, 'argv', ['keylocker'])
    runpy.run_path(os.path.abspath(keylocker.__file__), run_name='__main__')
    captured = capsys.readouterr()
    assert "keylocker" in captured.out or "keylocker" in captured.err

# === CLI E2E через subprocess ===

def _run_cli(args, cwd, input=None):
    env = {k: v for k, v in os.environ.items() if k != ENV_VAR_NAME}
    env['PYTHONPATH'] = _REPO_ROOT
    return subprocess.run(
        [sys.executable, '-m', 'keylocker'] + args,
        capture_output=True, text=True, cwd=str(cwd), env=env, input=input
    )

def test_cli_encrypt_stdin_view(tmp_path):
    """E2E: секрет через stdin, stdout encrypt и view пригодны для пайпов."""
    assert _run_cli(['init'], tmp_path).returncode == 0
    result = _run_cli(['encrypt'], tmp_path, input="stdin_secret\n")
    assert result.returncode == 0, result.stderr
    tag = result.stdout.strip()
    assert tag.startswith("!SEC ") and "\n" not in tag
    assert "stdin_secret" not in result.stdout + result.stderr

    yaml_path = tmp_path / "stdin_config.yaml"
    yaml_path.write_text(f"password: {tag}")
    result = _run_cli(['view', str(yaml_path)], tmp_path)
    assert result.returncode == 0, result.stderr
    assert yaml.safe_load(result.stdout) == {'password': 'stdin_secret'}

def test_cli_init_encrypt_view(tmp_path):
    """E2E: init -> encrypt -> view через python -m keylocker."""
    result = _run_cli(['init'], tmp_path)
    assert result.returncode == 0, result.stderr
    key_file = tmp_path / DEFAULT_KEY_FILE
    assert key_file.exists()
    Fernet(key_file.read_bytes())  # ключ валиден

    result = _run_cli(['encrypt', 'e2e_secret'], tmp_path)
    assert result.returncode == 0, result.stderr
    assert "!SEC " in result.stdout

    encrypted_tag = [l for l in result.stdout.splitlines() if l.startswith('!SEC ')][0]
    yaml_path = tmp_path / "e2e_config.yaml"
    yaml_path.write_text(f"password: {encrypted_tag}")
    result = _run_cli(['view', str(yaml_path)], tmp_path)
    assert result.returncode == 0, result.stderr
    assert "e2e_secret" in result.stdout