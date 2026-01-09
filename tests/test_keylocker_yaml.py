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
    DEFAULT_KEY_FILE,
    ENV_VAR_NAME, # Имя переменной окружения с ключом
    # Кастомные исключения
    KeylockerFileError,
    KeylockerEncryptionError,
    KeylockerConfigError # Может понадобиться для ошибок конфигурации ключа
)

# --- Fixtures (остаются как есть, они хорошо написаны) ---

@pytest.fixture(scope="function")
def temp_dir(tmp_path_factory):
    """Создает временную директорию для каждого теста."""
    return tmp_path_factory.mktemp("keylocker_test_yaml") # Изменено имя для ясности

@pytest.fixture(scope="function")
def key_file_in_temp_dir(temp_dir):
    """Путь к файлу ключа во временной директории теста."""
    return temp_dir / DEFAULT_KEY_FILE

@pytest.fixture(scope="function")
def generated_key_file(key_file_in_temp_dir):
    """Фикстура для создания валидного файла ключа во временной директории."""
    # Убедимся, что переменная окружения не мешает генерации файла
    if ENV_VAR_NAME in os.environ:
        del os.environ[ENV_VAR_NAME]
    manager = Manager(key_file=str(key_file_in_temp_dir))
    manager.init(force=True) # force=True на случай, если файл остался от предыдущего запуска
    assert key_file_in_temp_dir.exists()
    return str(key_file_in_temp_dir)

@pytest.fixture(scope="function")
def valid_fernet_key_bytes(): # Переименовано для ясности, что это байты
    """Генерирует и возвращает валидный ключ Fernet в виде байтов."""
    return Fernet.generate_key()

@pytest.fixture(scope="function")
def set_env_key(monkeypatch, valid_fernet_key_bytes):
    """Фикстура для установки переменной окружения с ключом."""
    key_str = valid_fernet_key_bytes.decode('utf-8')
    monkeypatch.setenv(ENV_VAR_NAME, key_str)
    yield valid_fernet_key_bytes # Возвращаем байты ключа для использования в тесте
    monkeypatch.delenv(ENV_VAR_NAME, raising=False) # Явная очистка, хотя monkeypatch делает это

@pytest.fixture(scope="function")
def unset_env_key(monkeypatch):
    """Фикстура для гарантии, что переменная окружения НЕ установлена."""
    monkeypatch.delenv(ENV_VAR_NAME, raising=False)

@pytest.fixture
def yaml_file_factory(temp_dir):
    """Фабрика для создания временных YAML файлов с заданным содержимым."""
    def _create_yaml(filename="test_config.yaml", content=""):
        yaml_path = temp_dir / filename
        yaml_path.write_text(content, encoding='utf-8')
        return str(yaml_path)
    return _create_yaml

# --- Test Functions ---

# === Тесты команды init (остаются без изменений, т.к. тестируют CLI поведение) ===
def test_init_creates_key_file(key_file_in_temp_dir, unset_env_key):
    """Тест: keylocker init создает файл ключа."""
    assert not key_file_in_temp_dir.exists()
    manager = Manager(key_file=str(key_file_in_temp_dir))
    manager.init()
    assert key_file_in_temp_dir.exists()
    key_bytes = key_file_in_temp_dir.read_bytes()
    assert len(key_bytes) > 30 # Проверка на разумную длину ключа
    Fernet(key_bytes) # Должно работать без исключений

def test_init_does_not_overwrite_by_default(generated_key_file, unset_env_key):
    """Тест: keylocker init не перезаписывает существующий ключ без --force."""
    manager = Manager(key_file=generated_key_file)
    initial_content = open(generated_key_file, 'rb').read()
    # Захватываем stdout, чтобы проверить сообщение
    # Manager.init печатает сообщения, но не возвращает их напрямую для этого случая
    # Вместо этого можно проверить, что файл не изменился
    manager.init() # Без force
    assert open(generated_key_file, 'rb').read() == initial_content

def test_init_force_overwrites(generated_key_file, unset_env_key):
    """Тест: keylocker init --force перезаписывает существующий ключ."""
    manager = Manager(key_file=generated_key_file)
    initial_content = open(generated_key_file, 'rb').read()
    manager.init(force=True)
    assert open(generated_key_file, 'rb').read() != initial_content

# === Тесты шифрования (encrypt_string_value) ===
def test_encrypt_string_with_file_key(generated_key_file, unset_env_key):
    """Тест шифрования строки с использованием ключа из файла."""
    plain_text = "secret file data"
    encrypted_tag = encrypt_string_value(plain_text, generated_key_file)
    assert encrypted_tag is not None
    assert encrypted_tag.startswith("!SEC ")
    key_bytes = open(generated_key_file, 'rb').read()
    fernet = Fernet(key_bytes)
    decrypted = fernet.decrypt(encrypted_tag.split(" ", 1)[1].encode()).decode()
    assert decrypted == plain_text

def test_encrypt_string_with_env_key(set_env_key):
    """Тест шифрования строки с использованием ключа из переменной окружения."""
    env_key_bytes = set_env_key
    plain_text = "secret env data"
    # key_file_path не должен использоваться, если ключ есть в env
    encrypted_tag = encrypt_string_value(plain_text, "dummy_path.key")
    assert encrypted_tag is not None
    assert encrypted_tag.startswith("!SEC ")
    fernet = Fernet(env_key_bytes)
    decrypted = fernet.decrypt(encrypted_tag.split(" ", 1)[1].encode()).decode()
    assert decrypted == plain_text

def test_encrypt_string_no_key_raises_error(key_file_in_temp_dir, unset_env_key): # <--- ОБНОВЛЕНО
    """Тест: Шифрование возбуждает KeylockerFileError, если нет ключа."""
    assert not key_file_in_temp_dir.exists()
    with pytest.raises(KeylockerFileError) as excinfo:
        encrypt_string_value("data", str(key_file_in_temp_dir))
    assert f"Fernet key file '{str(key_file_in_temp_dir)}' not found" in str(excinfo.value)
    assert ENV_VAR_NAME in str(excinfo.value) # Проверка, что сообщение упоминает ENV_VAR_NAME

def test_encrypt_string_invalid_key_file_raises_error(yaml_file_factory, unset_env_key): # <--- НОВЫЙ ТЕСТ
    """Тест: Шифрование возбуждает KeylockerEncryptionError, если файл ключа поврежден."""
    invalid_key_file = yaml_file_factory("invalid.key", "this is not a valid key")
    with pytest.raises(KeylockerEncryptionError) as excinfo:
        encrypt_string_value("data", invalid_key_file)
    assert "Invalid key format in Fernet key file" in str(excinfo.value) or \
           "Failed to encrypt string value" in str(excinfo.value) # Сообщение от encrypt_string_value

def test_encrypt_string_invalid_env_key_raises_error(monkeypatch, unset_env_key): # <--- НОВЫЙ ТЕСТ
    """Тест: Шифрование возбуждает KeylockerEncryptionError, если ключ в env поврежден."""
    monkeypatch.setenv(ENV_VAR_NAME, "this-is-not-a-base64-fernet-key")
    with pytest.raises(KeylockerEncryptionError) as excinfo:
        encrypt_string_value("data", "dummy_path.key")
    assert "Invalid key format in environment variable" in str(excinfo.value) or \
           "Failed to encrypt string value" in str(excinfo.value)


# === Тесты загрузки YAML (load_yaml_secrets) ===
def test_load_yaml_with_file_key_success(yaml_file_factory, generated_key_file, unset_env_key, monkeypatch):
    """Тест загрузки YAML с !SEC и !ENV, используя ключ из файла (успех)."""
    secret_value = "file_key_secret"
    env_var = "TEST_VAR_FILE_YAML"
    env_val = "file_key_env_val_yaml"
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

def test_load_yaml_with_env_key_success(yaml_file_factory, set_env_key, key_file_in_temp_dir, monkeypatch):
    """Тест загрузки YAML с !SEC и !ENV, используя ключ из env (успех)."""
    env_key_bytes = set_env_key
    fernet = Fernet(env_key_bytes)

    secret_value = "env_key_secret"
    env_var = "TEST_VAR_ENV_YAML"
    env_val = "env_key_env_val_yaml"
    monkeypatch.setenv(env_var, env_val)

    encrypted_val = fernet.encrypt(secret_value.encode()).decode()
    encrypted_tag = f"!SEC {encrypted_val}"

    yaml_content = f"""
    db_pass: {encrypted_tag}
    api_key: !ENV {env_var}
    plain: value2
    """
    assert not key_file_in_temp_dir.exists() # Файл ключа не должен использоваться
    yaml_path = yaml_file_factory("config_env.yaml", yaml_content)

    loaded_data = load_yaml_secrets(yaml_path, str(key_file_in_temp_dir)) # Путь к файлу не важен, если есть env ключ
    assert loaded_data is not None
    assert loaded_data['db_pass'] == secret_value
    assert loaded_data['api_key'] == env_val
    assert loaded_data['plain'] == 'value2'

def test_load_yaml_no_key_for_sec_tag_raises_error(yaml_file_factory, key_file_in_temp_dir, unset_env_key, capsys): # <--- ОБНОВЛЕНО
    """Тест: Загрузка YAML с !SEC возбуждает KeylockerEncryptionError, если нет ключа."""
    yaml_content = """
    secret: !SEC GAAAAAB...any_encrypted_looking_string...
    plain: value
    """
    yaml_path = yaml_file_factory("config_no_key_sec.yaml", yaml_content)
    assert not key_file_in_temp_dir.exists()

    with pytest.raises(KeylockerEncryptionError) as excinfo:
        load_yaml_secrets(yaml_path, str(key_file_in_temp_dir))

    assert "Cannot decrypt !SEC value: Fernet encryption cipher not available" in str(excinfo.value)

    captured = capsys.readouterr()
    # _load_fernet_key (вызванный из keylocker_loader) напечатает INFO об отсутствии файла ключа
    assert f"INFO: Fernet key file '{str(key_file_in_temp_dir)}' not found" in captured.out
    assert ENV_VAR_NAME in captured.out # Сообщение INFO также упоминает ENV_VAR_NAME


def test_load_yaml_invalid_sec_token_raises_error(yaml_file_factory, generated_key_file, unset_env_key): # <--- НОВЫЙ ТЕСТ
    """Тест: Загрузка YAML с поврежденным !SEC токеном возбуждает KeylockerEncryptionError."""
    yaml_content = """
    secret: !SEC this_is_not_a_valid_fernet_token
    """
    yaml_path = yaml_file_factory("config_invalid_token.yaml", yaml_content)

    with pytest.raises(KeylockerEncryptionError) as excinfo:
        load_yaml_secrets(yaml_path, generated_key_file)
    assert "Failed to decrypt !SEC value: Invalid token or key mismatch" in str(excinfo.value)


def test_load_yaml_env_not_set_returns_none_with_warning(yaml_file_factory, generated_key_file, unset_env_key, capsys): # <--- Название уточнено
    """Тест: !ENV возвращает None и выводит предупреждение, если переменная не установлена."""
    env_var = "UNSET_TEST_VAR_YAML"
    # Убедимся, что переменная точно не установлена
    if env_var in os.environ:
        del os.environ[env_var]

    yaml_content = f"""
    config_val: !ENV {env_var}
    """
    yaml_path = yaml_file_factory("config_unset_env.yaml", yaml_content)

    loaded_data = load_yaml_secrets(yaml_path, generated_key_file)
    assert loaded_data is not None # Сам YAML загружается
    assert loaded_data['config_val'] is None # Ожидаем None для отсутствующей переменной

    captured = capsys.readouterr()
    # env_constructor печатает в stderr
    assert f"WARNING: Environment variable '{env_var}' (tagged !ENV) not found. Resolving to None." in captured.err


def test_load_yaml_file_itself_not_found_raises_error(unset_env_key): # <--- НОВЫЙ ТЕСТ (аналогичен из vault тестов)
    """Тест: Загрузка несуществующего YAML файла возбуждает KeylockerFileError."""
    with pytest.raises(KeylockerFileError) as excinfo:
        load_yaml_secrets("surely_this_file_does_not_exist.yaml", "dummy.key")
    assert "Input YAML file not found" in str(excinfo.value)
    assert "surely_this_file_does_not_exist.yaml" in str(excinfo.value)


def test_load_yaml_invalid_key_in_file_for_sec_tag_raises_error(yaml_file_factory, unset_env_key, capsys): # <--- НОВЫЙ ТЕСТ
    """Тест: Загрузка YAML с !SEC и невалидным файлом ключа возбуждает KeylockerConfigError."""
    invalid_key_file = yaml_file_factory("invalid_for_load.key", "this is not a valid key")
    yaml_content = """
    secret: !SEC ABCDEF...
    """
    yaml_path = yaml_file_factory("config_bad_key_load.yaml", yaml_content)

    with pytest.raises(KeylockerConfigError) as excinfo: # keylocker_loader оборачивает ошибку ключа в KeylockerConfigError
        load_yaml_secrets(yaml_path, invalid_key_file)

    assert "Failed to initialize Fernet cipher due to key error" in str(excinfo.value)
    assert "Invalid key format in Fernet key file" in str(excinfo.value) # Оригинальная причина

def test_load_main():
    from fire.core import FireExit
    try:
        from keylocker.__main__ import main
    except FireExit:
        pass