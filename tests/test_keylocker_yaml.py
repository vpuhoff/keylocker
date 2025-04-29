import pytest
import os
import yaml
from cryptography.fernet import Fernet # Needed for direct key manipulation/checking if required

# Assuming your updated keylocker code is in the 'keylocker' directory
# Adjust the import path if your structure is different
from keylocker import (
    Manager,
    load_yaml_secrets,
    encrypt_string_value,
    SecureString, # Import if needed for testing saving
    EnvVariable   # Import if needed for testing saving
)

# --- Fixtures ---

# Pytest fixture to create a temporary key file for tests
@pytest.fixture(scope="function") # 'function' scope runs this for each test
def temp_key_file(tmp_path):
    key_path = tmp_path / "test_storage.key"
    # Use the Manager's init logic to create a valid key file
    manager = Manager(key_file=str(key_path))
    manager.init(force=True) # Force creation in temp dir
    assert key_path.exists() # Ensure key was created
    yield str(key_path) # Provide the path to the test function
    # Teardown (happens after yield): tmp_path fixture handles cleanup

# Pytest fixture to create a sample YAML file with tags
@pytest.fixture
def sample_yaml_file(tmp_path, temp_key_file):
    yaml_path = tmp_path / "test_config.yaml"
    secret_value = "my_super_secret_password"
    # Encrypt the value using the temporary key
    encrypted_tag = encrypt_string_value(secret_value, temp_key_file)
    assert encrypted_tag is not None

    # Set an environment variable for the !ENV test
    test_env_var = "KEYLOCKER_TEST_VAR"
    test_env_value = "value_from_environment"
    os.environ[test_env_var] = test_env_value

    yaml_content = f"""
plain_key: plain_value
database:
  user: db_user
  # Use the generated encrypted tag here
  password: {encrypted_tag}
api_details:
  endpoint: https://example.com
  # Use the environment variable tag
  api_key: !ENV {test_env_var}
other_secret: !SEC GAAAAAB... # Placeholder for another potential secret
unresolvable_env: !ENV NON_EXISTENT_VAR
"""
    yaml_path.write_text(yaml_content)
    yield str(yaml_path)
    # Cleanup environment variable
    del os.environ[test_env_var]

# --- Test Functions ---

def test_key_initialization(tmp_path):
    """Tests if the Manager.init() creates a key file."""
    key_path = tmp_path / "init_test.key"
    manager = Manager(key_file=str(key_path))
    assert not key_path.exists()
    manager.init()
    assert key_path.exists()
    # Optional: Check key file content validity (e.g., size, base64)
    key_content = key_path.read_bytes()
    assert len(key_content) > 30 # Basic check

def test_encrypt_string(temp_key_file):
    """Tests the basic encryption utility."""
    plain_text = "encrypt me"
    encrypted_tag = encrypt_string_value(plain_text, temp_key_file)
    assert encrypted_tag is not None
    assert encrypted_tag.startswith("!SEC ")
    # Further checks could involve trying to decrypt it back if needed

def test_load_yaml_with_secrets(sample_yaml_file, temp_key_file):
    """Tests loading YAML with !SEC and !ENV tags."""
    loaded_data = load_yaml_secrets(sample_yaml_file, temp_key_file)

    assert loaded_data is not None
    assert loaded_data['plain_key'] == 'plain_value'
    assert loaded_data['database']['user'] == 'db_user'
    # Check decrypted secret
    assert loaded_data['database']['password'] == "my_super_secret_password"
    # Check resolved environment variable
    assert loaded_data['api_details']['api_key'] == "value_from_environment"
    # Check unresolvable env var (should be None based on current implementation)
    assert loaded_data['unresolvable_env'] is None
    # Add check for 'other_secret' if you have a valid encrypted string for it
    # assert loaded_data['other_secret'] == "expected_decrypted_value"

def test_manager_view_command(capsys, sample_yaml_file, temp_key_file):
    """Tests the 'view' command output."""
    # Note: Testing CLI commands often involves subprocess or Click's/Fire's test runners.
    # This is a simplified check by calling the underlying function.
    manager = Manager(key_file=temp_key_file)
    # We check if loading works, the view command essentially loads and dumps
    data = load_yaml_secrets(sample_yaml_file, temp_key_file)
    assert data is not None
    # We can't easily capture Fire's output here without more complex testing setup.
    # A basic check is that the loading function worked as expected.
    print(f"\nLoaded data for view test:\n{data}") # Print for visibility during test run

# --- Add More Tests ---
# - Test edge cases (empty file, invalid YAML, missing key file, invalid key)
# - Test !ENV variable not set behavior explicitly
# - Test !SEC decryption failure (e.g., using wrong key)
# - Test saving YAML (requires representing SecureString/EnvVariable in data)
#   def test_save_yaml_with_secrets(...)

