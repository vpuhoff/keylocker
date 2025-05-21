# Use an official Python runtime as a parent image
FROM python:3.9-slim

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file into the container at /app
COPY requirements.txt /app/

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy the entire keylocker package into the container at /app/keylocker
COPY keylocker /app/keylocker

# Copy Pipfile and Pipfile.lock (optional, if you decide to use pipenv later)
COPY Pipfile Pipfile.lock /app/

# This environment variable can be used to set the default key file path if needed
ENV KEYLOCKER_KEY_FILE_PATH /app/storage.key

# Default command can be overridden.
# For example, to run keylocker CLI:
# CMD ["python", "-m", "keylocker.keylocker", "view", "config/config.yaml"]
# Or to run a custom script:
# CMD ["python", "my_custom_script.py"]
# For now, we provide a simple default command.
CMD ["python"]
