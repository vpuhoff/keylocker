
PYPIPASS="$(python -m keylocker read pypi_password)"
poetry publish --username ailab --password "${PYPIPASS}" --build

