# Keylocker CLI
Library with the CLI to save the encrypted secrets in the configuration file, but a transparent read and write the new settings in the app.

## Simple usage in CLI:
```
keylocker init
keylocker list
keylocker read <keyname>
keylocker remove <keyname>
keylocker write <keyname> <value>
```

## Simple usage in code:
```
from keylocker import Storage
secrets = Storage()
print(secrets['test'])
```

## Simple usage in bash:
```
PYPIPASS="$(keylocker read pypi_password)"
PYPIUSER="$(keylocker read pypi_user)"
poetry publish --username "${PYPIUSER}" --password "${PYPIPASS}" --build
```

