# tests/test_keylocker_yaml.py

import pytest
import os
import yaml
import subprocess # Для тестирования CLI вызовов (альтернатива)
from cryptography.fernet import Fernet

# Импортируем необходимые части из обновленного keylocker
from keylocker import (
    Manager,
    load_yaml_secrets,
    encrypt_string_value,
    # Вспомогательные переменные или функции, если они доступны и нужны
    DEFAULT_KEY_FILE,
    ENV_VAR_NAME # Имя переменной окружения с ключом
)

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
    """Тест: Загрузка YAML с !SEC падает (возвращает ошибку), если нет ключа."""
    yaml_content = """
    secret: !SEC GAAAAAB...invalid...
    plain: value
    """
    yaml_path = yaml_file_factory("config_no_key.yaml", yaml_content)
    assert not key_file_in_temp_dir.exists() # Файла нет

    loaded_data = load_yaml_secrets(yaml_path, str(key_file_in_temp_dir))
    assert loaded_data is not None # Загрузка YAML не падает полностью
    assert "DECRYPTION_ERROR[NoKey]" in loaded_data['secret'] # Значение не расшифровано
    assert loaded_data['plain'] == 'value'
    # Проверяем сообщения в stderr/stdout
    captured = capsys.readouterr()
    assert "No encryption key loaded" in captured.out or "No encryption key loaded" in captured.err # Должно быть предупреждение
    assert "Cannot decrypt !SEC value" in captured.out or "Cannot decrypt !SEC value" in captured.err # Должна быть ошибка при расшифровке

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
    assert f"Environment variable '{env_var}' (tagged !ENV) not found" in captured.out or \
           f"Environment variable '{env_var}' (tagged !ENV) not found" in captured.err

# === Тесты CLI команд (требуют больше усилий для настройки) ===

# Пример теста команды view через subprocess
@pytest.mark.skip(reason="CLI tests require careful environment setup")
def test_cli_view_with_file_key(yaml_file_factory, generated_key_file, unset_env_key, monkeypatch):
    """(Пример) Тестирование CLI команды 'view' с ключом из файла."""
    secret_value = "cli_secret"
    env_var = "CLI_TEST_VAR"
    env_val = "cli_env_val"
    monkeypatch.setenv(env_var, env_val)
    encrypted_tag = encrypt_string_value(secret_value, generated_key_file)
    yaml_content = f"password: {encrypted_tag}\napi_key: !ENV {env_var}"
    yaml_path = yaml_file_factory("cli_config.yaml", yaml_content)

    # Запускаем keylocker как подпроцесс
    # Важно: нужно убедиться, что keylocker установлен в окружении или путь к скрипту правильный
    result = subprocess.run(
        ['keylocker', 'view', yaml_path, '--key-file', generated_key_file], # Нужно добавить поддержку --key-file в CLI
        capture_output=True, text=True, check=True,
        # Передаем окружение, чтобы !ENV сработало
        env={**os.environ, ENV_VAR_NAME: ''} # Гарантируем, что env ключ не установлен
    )

    assert secret_value in result.stdout
    assert env_val in result.stdout
    assert '!SEC' not in result.stdout
    assert '!ENV' not in result.stdout

# Добавить аналогичный тест для CLI view с ключом из переменной окружения

# === Другие тесты ===
# - Тест сохранения YAML (потребует создания данных с SecureString/EnvVariable)
# - Тест невалидного ключа в файле / переменной окружения
# - Тест невалидного токена !SEC