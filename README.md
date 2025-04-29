# Keylocker CLI (YAML Edition)

Инструмент командной строки (CLI) и библиотека Python для управления секретами непосредственно в YAML файлах конфигурации. Позволяет шифровать отдельные значения с помощью тега `!SEC` и загружать значения из переменных окружения с помощью тега `!ENV`.

## Пример YAML файла (`config.yaml`):

```yaml
# config.yaml
database:
  host: db.example.com
  username: user
  # Зашифрованный пароль с помощью keylocker encrypt
  password: !SEC gAAAAABh...[rest of encrypted data]...
api:
  endpoint: [https://api.example.com](https://api.example.com)
  # Загрузка ключа из переменной окружения API_KEY
  key: !ENV API_KEY
deployment:
  region: us-east-1
  # Еще один секрет
  ssh_key_pass: !SEC gAAAAABh...[another encrypted data]...
````

## Использование в CLI:

1.  **Инициализация (создание ключа):**

    ```bash
    keylocker init
    # Будет создан файл storage.key (если не существует)
    ```

2.  **Шифрование значения для вставки в YAML:**

    ```bash
    keylocker encrypt "my_secret_value"
    # Вывод:
    # Add the following line to your YAML file:
    # !SEC gAAAAABh...[encrypted data]...

    # Скопируйте строку !SEC ... в ваш YAML файл
    ```

3.  **Просмотр расшифрованного YAML:**

    ```bash
    # Установите переменную окружения (если используется !ENV)
    export API_KEY="your_actual_api_key"

    keylocker view config.yaml
    # Выведет YAML с расшифрованными значениями !SEC
    # и подставленными значениями !ENV
    # Пример вывода:
    # database:
    #   host: db.example.com
    #   username: user
    #   password: my_secret_value # Расшифровано!
    # api:
    #   endpoint: [https://api.example.com](https://api.example.com)
    #   key: your_actual_api_key  # Подставлено из env!
    # deployment:
    #   region: us-east-1
    #   ssh_key_pass: decrypted_pass # Расшифровано!
    ```

    *(Примечание: Команда `edit` может быть добавлена в будущем для интерактивного редактирования)*

## Использование в коде Python:

```python
import os
from keylocker import load_yaml_secrets

# Установите переменные окружения, если нужно
os.environ['API_KEY'] = 'your_actual_api_key_for_python'

config_file = 'config.yaml'
key_file = 'storage.key' # Убедитесь, что ключ существует

try:
    # Загрузка и автоматическая расшифровка/подстановка
    secrets = load_yaml_secrets(config_file, key_file)

    if secrets:
        db_password = secrets.get('database', {}).get('password')
        api_key = secrets.get('api', {}).get('key')

        print(f"Database Password: {db_password}")
        print(f"API Key: {api_key}")

except Exception as e:
    print(f"An error occurred: {e}")

```

## Использование в Bash:

Для извлечения конкретных значений из расшифрованного YAML можно использовать утилиты вроде `yq` или стандартные инструменты Unix.

```bash
#!/bin/bash

# Убедитесь, что переменная окружения установлена, если она нужна
export API_KEY="your_bash_api_key"

# Получаем расшифрованный YAML
CONFIG_YAML=$(keylocker view config.yaml)

# Проверка, что команда выполнилась успешно
if [ $? -ne 0 ]; then
  echo "Ошибка при выполнении keylocker view"
  exit 1
fi

# Пример извлечения с помощью yq (требует установки yq)
# DB_PASS=$(echo "$CONFIG_YAML" | yq e '.database.password' -)
# API_KEY_FROM_YAML=$(echo "$CONFIG_YAML" | yq e '.api.key' -)

# Пример извлечения с помощью grep/sed (менее надежно)
DB_PASS=$(echo "$CONFIG_YAML" | grep -A 1 'database:' | grep 'password:' | awk '{print $2}')
API_KEY_FROM_YAML=$(echo "$CONFIG_YAML" | grep -A 1 'api:' | grep 'key:' | awk '{print $2}')


echo "Извлеченный пароль БД: $DB_PASS"
echo "Извлеченный API ключ: $API_KEY_FROM_YAML"

# Дальнейшее использование переменных...
# poetry publish --username user --password "${DB_PASS}" --build
```


## Source Code:
* [https://github.com/vpuhoff/keylocker](https://github.com/vpuhoff/keylocker)

## Travis CI Deploys:
* [https://travis-ci.com/vpuhoff/keylocker](https://travis-ci.com/vpuhoff/keylocker) [![Build Status](https://travis-ci.com/vpuhoff/keylocker.svg?branch=master)](https://travis-ci.com/vpuhoff/keylocker)
