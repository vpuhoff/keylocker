
PYPIPASS="$(keylocker read pypi_password)"
poetry publish --username ailab --password "${PYPIPASS}" --build

