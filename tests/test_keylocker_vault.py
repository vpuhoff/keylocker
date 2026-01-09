import os
import pytest
import yaml
from unittest.mock import patch, MagicMock

# Импортируем тестируемые функции и классы исключений из вашего модуля
# Предполагается, что keylocker находится в PYTHONPATH или установлен
from keylocker import (
    load_yaml_secrets,
    VaultClientNotInitializedError,
    VaultInvalidFormatError,
    VaultSecretNotFoundError,
    VaultKeyNotFoundError,
    VaultInvalidPathError,
    VaultPermissionError,
    VaultGenericClientError,
    ENV_VAR_NAME,  # KEYLOCKER_SECRET_KEY
    VAULT_ADDR_ENV_VAR,
    VAULT_TOKEN_ENV_VAR
)
# Импортируем hvac.exceptions для мокирования специфичных ошибок hvac
import hvac.exceptions

# tests/test_keylocker_vault.py

import os
import pytest
import yaml # Убедитесь, что yaml импортирован
from unittest.mock import patch, MagicMock
from cryptography.fernet import Fernet

# Импортируем тестируемые функции и классы исключений из вашего модуля
from keylocker import (
    load_yaml_secrets,
    KeylockerFileError, # Для теста отсутствующего YAML файла
    KeylockerConfigError,
    VaultClientNotInitializedError,
    VaultInvalidFormatError,
    VaultSecretNotFoundError,
    VaultKeyNotFoundError,
    VaultInvalidPathError,
    VaultPermissionError,
    VaultGenericClientError,
    # ENV_VAR_NAME, # Не используется напрямую в этих тестах Vault
    VAULT_ADDR_ENV_VAR,
    VAULT_TOKEN_ENV_VAR
)
# Импортируем hvac.exceptions для мокирования специфичных ошибок hvac
import hvac.exceptions

# Фикстура для временных YAML файлов (без изменений)
@pytest.fixture
def create_yaml_file(tmp_path):
    def _create_yaml_file(content):
        file_path = tmp_path / "test.yaml"
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)
        return file_path
    return _create_yaml_file

# Фикстура для управления переменными окружения (без изменений)
@pytest.fixture
def mock_env_vars(mocker):
    def _mock_env_vars(env_vars_dict, clear_others=True): # clear=True по умолчанию
        return mocker.patch.dict(os.environ, env_vars_dict, clear=clear_others)
    return _mock_env_vars

# Фикстура для мокирования клиента HVAC (без изменений)
@pytest.fixture
def mock_hvac_client(mocker):
    mock_client_instance = MagicMock(spec=hvac.Client)
    mock_client_constructor = mocker.patch('hvac.Client', return_value=mock_client_instance)
    return mock_client_constructor, mock_client_instance

# --- Тесты ---

def test_load_yaml_file_not_found():
    """Тест: YAML файл не найден, ожидаем KeylockerFileError."""
    with pytest.raises(KeylockerFileError) as excinfo:
        load_yaml_secrets("non_existent_file.yaml")
    assert "Input YAML file not found: 'non_existent_file.yaml'" in str(excinfo.value)


def test_load_yaml_with_vault_success(create_yaml_file, mock_env_vars, mock_hvac_client):
    """Тест успешной загрузки секрета из Vault."""
    mock_env_vars({VAULT_ADDR_ENV_VAR: "http://fake-vault:8200", VAULT_TOKEN_ENV_VAR: "fake_token"})
    _, mock_client = mock_hvac_client # mock_client_constructor не используется здесь напрямую
    mock_client.is_authenticated.return_value = True
    mock_client.secrets.kv.v2.read_secret_version.return_value = {
        'data': {
            'data': {'db_password': 'supersecretpassword'}
        }
    }

    yaml_content = "config:\n  password: !VAULT kv/data/myapp/db:db_password"
    yaml_file = create_yaml_file(yaml_content)

    result = load_yaml_secrets(str(yaml_file))

    assert result['config']['password'] == 'supersecretpassword'
    mock_client.secrets.kv.v2.read_secret_version.assert_called_once_with(
        path='kv/data/myapp/db', raise_on_deleted_version=True
    )

def test_load_yaml_vault_addr_not_set_but_vault_tag_used(create_yaml_file, mock_env_vars, capsys):
    """
    Тест: VAULT_ADDR не установлен, но используется !VAULT.
    Ожидаем VaultClientNotInitializedError от vault_constructor.
    """
    mock_env_vars({}) # VAULT_ADDR и VAULT_TOKEN не установлены
    yaml_content = "config:\n  password: !VAULT kv/data/myapp/db:db_password"
    yaml_file = create_yaml_file(yaml_content)

    with pytest.raises(VaultClientNotInitializedError) as excinfo:
        load_yaml_secrets(str(yaml_file))

    # Это исключение возбуждается из vault_constructor
    assert "Vault client not available for !VAULT tag." in str(excinfo.value)

    captured = capsys.readouterr()
    # keylocker_loader напечатает INFO, т.к. _get_vault_client не будет вызван
    assert f"INFO: Environment variable '{VAULT_ADDR_ENV_VAR}' is not set." in captured.out
    assert "Vault client will not be initialized. !VAULT tags will fail if used." in captured.out


def test_load_yaml_vault_token_not_set(create_yaml_file, mock_env_vars, mock_hvac_client, capsys):
    """
    Тест: VAULT_ADDR установлен, но VAULT_TOKEN не установлен.
    _get_vault_client должен возбудить VaultClientNotInitializedError.
    (При условии, что _get_vault_client теперь требует токен, если VAULT_ADDR установлен).
    """
    mock_env_vars({VAULT_ADDR_ENV_VAR: "http://fake-vault:8200"}) # VAULT_TOKEN не установлен
    # Мокируем hvac.Client, т.к. _get_vault_client попытается его создать
    mock_constructor, _ = mock_hvac_client

    yaml_content = "config:\n  password: !VAULT kv/data/myapp/db:db_password"
    yaml_file = create_yaml_file(yaml_content)

    with pytest.raises(VaultClientNotInitializedError) as excinfo:
        load_yaml_secrets(str(yaml_file))

    assert f"Vault token environment variable '{VAULT_TOKEN_ENV_VAR}' not set" in str(excinfo.value)


def test_load_yaml_vault_auth_fails_in_get_client(create_yaml_file, mock_env_vars, mock_hvac_client):
    """
    Тест: Аутентификация Vault не удалась в _get_vault_client (is_authenticated => False).
    Ожидаем VaultClientNotInitializedError от _get_vault_client.
    """
    mock_env_vars({VAULT_ADDR_ENV_VAR: "http://fake-vault:8200", VAULT_TOKEN_ENV_VAR: "bad_token"})
    _, mock_client = mock_hvac_client
    mock_client.is_authenticated.return_value = False # Аутентификация не удалась

    yaml_content = "config:\n  password: !VAULT kv/data/myapp/db:db_password"
    yaml_file = create_yaml_file(yaml_content)

    with pytest.raises(VaultClientNotInitializedError) as excinfo:
        load_yaml_secrets(str(yaml_file))

    assert "Failed to authenticate to Vault at http://fake-vault:8200" in str(excinfo.value)


def test_load_yaml_vault_client_init_raises_hvac_vault_error(create_yaml_file, mock_env_vars, mocker):
    """
    Тест: hvac.Client() возбуждает hvac.exceptions.VaultError при инициализации.
    _get_vault_client должен поймать и возбудить VaultClientNotInitializedError.
    """
    mock_env_vars({VAULT_ADDR_ENV_VAR: "http://unreachable-vault:8200", VAULT_TOKEN_ENV_VAR: "any-token"})
    mocker.patch('hvac.Client', side_effect=hvac.exceptions.VaultError("Connection refused by mock"))

    yaml_content = "config:\n  password: !VAULT kv/data/myapp/db:db_password"
    yaml_file = create_yaml_file(yaml_content)

    with pytest.raises(VaultClientNotInitializedError) as excinfo:
        load_yaml_secrets(str(yaml_file))

    assert "Vault client setup/connection error for http://unreachable-vault:8200" in str(excinfo.value)
    assert "Connection refused by mock" in str(excinfo.value)


def test_load_yaml_vault_invalid_tag_format(create_yaml_file, mock_env_vars, mock_hvac_client):
    """Тест: неверный формат тега !VAULT."""
    mock_env_vars({VAULT_ADDR_ENV_VAR: "http://fake-vault:8200", VAULT_TOKEN_ENV_VAR: "fake_token"})
    _, mock_client = mock_hvac_client
    mock_client.is_authenticated.return_value = True

    yaml_content = "config:\n  password: !VAULT kv/data/myapp/db_NO_KEY_SEPARATOR"
    yaml_file = create_yaml_file(yaml_content)

    with pytest.raises(VaultInvalidFormatError) as excinfo:
        load_yaml_secrets(str(yaml_file))
    assert "Invalid !VAULT format 'kv/data/myapp/db_NO_KEY_SEPARATOR'" in str(excinfo.value)

def test_load_yaml_vault_key_not_found(create_yaml_file, mock_env_vars, mock_hvac_client):
    """Тест: ключ не найден в секрете Vault."""
    mock_env_vars({VAULT_ADDR_ENV_VAR: "http://fake-vault:8200", VAULT_TOKEN_ENV_VAR: "fake_token"})
    _, mock_client = mock_hvac_client
    mock_client.is_authenticated.return_value = True
    mock_client.secrets.kv.v2.read_secret_version.return_value = {
        'data': {
            'data': {'another_key': 'some_value'}
        }
    }
    yaml_content = "config:\n  password: !VAULT kv/data/myapp/db:missing_key"
    yaml_file = create_yaml_file(yaml_content)

    with pytest.raises(VaultKeyNotFoundError) as excinfo:
        load_yaml_secrets(str(yaml_file))
    assert "Key 'missing_key' not found" in str(excinfo.value)
    assert "Vault path 'kv/data/myapp/db'" in str(excinfo.value)


def test_load_yaml_vault_secret_not_found_empty_data(create_yaml_file, mock_env_vars, mock_hvac_client):
    """Тест: секрет не найден (ответ Vault пустой или без data.data)."""
    mock_env_vars({VAULT_ADDR_ENV_VAR: "http://fake-vault:8200", VAULT_TOKEN_ENV_VAR: "fake_token"})
    _, mock_client = mock_hvac_client
    mock_client.is_authenticated.return_value = True
    mock_client.secrets.kv.v2.read_secret_version.return_value = {'data': {}} # Не 'data' внутри 'data'

    yaml_content = "config:\n  password: !VAULT non/existent/path:some_key"
    yaml_file = create_yaml_file(yaml_content)

    with pytest.raises(VaultSecretNotFoundError) as excinfo:
        load_yaml_secrets(str(yaml_file))
    assert "Secret data malformed or not found at Vault path 'non/existent/path'" in str(excinfo.value)


def test_load_yaml_vault_api_raises_invalid_path(create_yaml_file, mock_env_vars, mock_hvac_client):
    """Тест: API Vault возвращает ошибку InvalidPath."""
    mock_env_vars({VAULT_ADDR_ENV_VAR: "http://fake-vault:8200", VAULT_TOKEN_ENV_VAR: "fake_token"})
    _, mock_client = mock_hvac_client
    mock_client.is_authenticated.return_value = True
    mock_client.secrets.kv.v2.read_secret_version.side_effect = hvac.exceptions.InvalidPath("Mocked InvalidPath from HVAC")

    yaml_content = "config:\n  password: !VAULT bad/path:some_key"
    yaml_file = create_yaml_file(yaml_content)

    with pytest.raises(VaultInvalidPathError) as excinfo:
        load_yaml_secrets(str(yaml_file))
    assert "Invalid path for secret in Vault: 'bad/path'" in str(excinfo.value)
    assert "Mocked InvalidPath from HVAC" in str(excinfo.value) # Проверяем, что оригинальное сообщение hvac включено


def test_load_yaml_vault_api_raises_forbidden(create_yaml_file, mock_env_vars, mock_hvac_client):
    """Тест: API Vault возвращает ошибку Forbidden."""
    mock_env_vars({VAULT_ADDR_ENV_VAR: "http://fake-vault:8200", VAULT_TOKEN_ENV_VAR: "fake_token"})
    _, mock_client = mock_hvac_client
    mock_client.is_authenticated.return_value = True
    mock_client.secrets.kv.v2.read_secret_version.side_effect = hvac.exceptions.Forbidden("Mocked Forbidden from HVAC")

    yaml_content = "config:\n  password: !VAULT forbidden/path:some_key"
    yaml_file = create_yaml_file(yaml_content)

    with pytest.raises(VaultPermissionError) as excinfo:
        load_yaml_secrets(str(yaml_file))
    assert "Permission denied for secret in Vault: 'forbidden/path'" in str(excinfo.value)
    assert "Mocked Forbidden from HVAC" in str(excinfo.value)


def test_load_yaml_vault_api_raises_generic_vault_error(create_yaml_file, mock_env_vars, mock_hvac_client):
    """Тест: API Vault возвращает общую ошибку VaultError."""
    mock_env_vars({VAULT_ADDR_ENV_VAR: "http://fake-vault:8200", VAULT_TOKEN_ENV_VAR: "fake_token"})
    _, mock_client = mock_hvac_client
    mock_client.is_authenticated.return_value = True
    mock_client.secrets.kv.v2.read_secret_version.side_effect = hvac.exceptions.VaultError("Mocked Generic VaultError from HVAC")

    yaml_content = "config:\n  password: !VAULT some/path:some_key"
    yaml_file = create_yaml_file(yaml_content)

    with pytest.raises(VaultGenericClientError) as excinfo:
        load_yaml_secrets(str(yaml_file))
    assert "Vault API error when reading secret 'some/path'" in str(excinfo.value)
    assert "Mocked Generic VaultError from HVAC" in str(excinfo.value)


def test_load_yaml_with_env_and_vault_success(create_yaml_file, mock_env_vars, mock_hvac_client):
    """Тест совместной работы !ENV и !VAULT при успешном выполнении."""
    mock_env_vars({
        VAULT_ADDR_ENV_VAR: "http://fake-vault:8200",
        VAULT_TOKEN_ENV_VAR: "fake_token",
        "MY_ENV_VAR_FOR_TEST": "env_value_123"  # Уникальное имя для переменной окружения
    })
    _, mock_client = mock_hvac_client
    mock_client.is_authenticated.return_value = True
    mock_client.secrets.kv.v2.read_secret_version.return_value = {
        'data': {'data': {'secret_key': 'vault_value_456'}}
    }

    yaml_content = (
        "app:\n"
        "  setting1: !ENV MY_ENV_VAR_FOR_TEST\n"
        "  setting2: !VAULT my/vault/path:secret_key"
    )
    yaml_file = create_yaml_file(yaml_content)
    result = load_yaml_secrets(str(yaml_file))

    assert result['app']['setting1'] == 'env_value_123'
    assert result['app']['setting2'] == 'vault_value_456'

# --- Тесты для Fernet ключей и !SEC (примеры, можно вынести в отдельный файл) ---

@pytest.fixture
def mock_fernet_key_env(mock_env_vars):
    """Мокирует валидный Fernet ключ в переменной окружения."""
    # Этот ключ сгенерирован Fernet.generate_key().decode()
    valid_key_str = Fernet.generate_key().decode()
    mock_env_vars({ENV_VAR_NAME: valid_key_str}, clear_others=False) # Добавляем, не очищая другие
    return valid_key_str

@pytest.fixture
def create_fernet_key_file(tmp_path):
    """Создает валидный файл Fernet ключа."""
    key_file = tmp_path / "test_storage.key"
    key = Fernet.generate_key()
    with open(key_file, "wb") as f:
        f.write(key)
    return str(key_file), key.decode()


def test_load_yaml_sec_tag_success_with_env_key(create_yaml_file, mock_fernet_key_env, capsys):
    """Тест успешной расшифровки !SEC тега с ключом из переменной окружения."""
    key_str = mock_fernet_key_env
    fernet = Fernet(key_str.encode())
    original_value = "my_secret_data"
    encrypted_value = fernet.encrypt(original_value.encode()).decode()

    yaml_content = f"secret_data: !SEC {encrypted_value}"
    yaml_file = create_yaml_file(yaml_content)

    # Убедимся, что VAULT_ADDR не установлен, чтобы не мешать тесту !SEC
    with patch.dict(os.environ, {VAULT_ADDR_ENV_VAR: ""}, clear=False):
        if VAULT_ADDR_ENV_VAR in os.environ: # Доп. проверка для очистки если он был установлен ранее в сессии
            del os.environ[VAULT_ADDR_ENV_VAR]

        result = load_yaml_secrets(str(yaml_file)) # Используем ключ по умолчанию, т.к. _load_fernet_key проверит env

    assert result['secret_data'] == original_value
    captured = capsys.readouterr()
    assert f"INFO: Using encryption key from environment variable {ENV_VAR_NAME}" in captured.out

# Добавьте больше тестов для !SEC, !ENV, ошибок Fernet ключей, и т.д.