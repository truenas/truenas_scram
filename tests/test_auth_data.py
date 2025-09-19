"""Test SCRAM auth data generation functionality."""

import pytest
import truenas_pyscram


def test_generate_scram_auth_data_returns_scram_auth_data():
    """Test that generate_scram_auth_data returns a ScramAuthData object."""
    auth_data = truenas_pyscram.generate_scram_auth_data()
    assert type(auth_data).__name__ == "ScramAuthData"


def test_generate_scram_auth_data_default_iterations():
    """Test that default iterations match SCRAM_DEFAULT_ITERS."""
    auth_data = truenas_pyscram.generate_scram_auth_data()
    assert auth_data.iterations == truenas_pyscram.SCRAM_DEFAULT_ITERS


def test_generate_scram_auth_data_custom_iterations():
    """Test that custom iterations are used when provided."""
    custom_iters = 100000
    auth_data = truenas_pyscram.generate_scram_auth_data(iterations=custom_iters)
    assert auth_data.iterations == custom_iters


@pytest.mark.parametrize("attr_name", [
    "salt",
    "salted_password",
    "client_key",
    "stored_key",
    "server_key",
])
def test_auth_data_attributes_are_crypto_datum(attr_name):
    """Test that auth data crypto attributes are CryptoDatum objects."""
    auth_data = truenas_pyscram.generate_scram_auth_data()
    attr_value = getattr(auth_data, attr_name)
    assert isinstance(attr_value, truenas_pyscram.CryptoDatum)


@pytest.mark.parametrize("attr_name,expected_length", [
    ("salt", 16),
    ("salted_password", 64),
    ("client_key", 64),
    ("stored_key", 64),
    ("server_key", 64),
])
def test_auth_data_crypto_lengths(attr_name, expected_length):
    """Test that auth data crypto attributes have expected lengths."""
    auth_data = truenas_pyscram.generate_scram_auth_data()
    attr_value = getattr(auth_data, attr_name)
    assert len(attr_value) == expected_length


def test_generate_scram_auth_data_randomness():
    """Test that generated auth data is different between calls."""
    auth_data1 = truenas_pyscram.generate_scram_auth_data()
    auth_data2 = truenas_pyscram.generate_scram_auth_data()

    # Salt should be different (randomly generated)
    assert auth_data1.salt != auth_data2.salt

    # All derived keys should be different due to different salts
    assert auth_data1.salted_password != auth_data2.salted_password
    assert auth_data1.client_key != auth_data2.client_key
    assert auth_data1.stored_key != auth_data2.stored_key
    assert auth_data1.server_key != auth_data2.server_key


def test_generate_scram_auth_data_with_salt():
    """Test generating auth data with provided salt."""
    salt_bytes = truenas_pyscram.generate_nonce()[:16]  # Use 16 bytes for salt
    salt = truenas_pyscram.CryptoDatum(salt_bytes)
    auth_data = truenas_pyscram.generate_scram_auth_data(salt=salt)
    assert auth_data.salt == salt


def test_generate_scram_auth_data_with_salted_password():
    """Test generating auth data with provided salted password."""
    # First generate auth data normally to get salt and iterations
    initial_auth = truenas_pyscram.generate_scram_auth_data()

    # Use the same salted password, salt, and iterations
    auth_data = truenas_pyscram.generate_scram_auth_data(
        salted_password=initial_auth.salted_password,
        salt=initial_auth.salt,
        iterations=initial_auth.iterations
    )

    # All crypto data should match when using same salted password
    assert auth_data.salt == initial_auth.salt
    assert auth_data.iterations == initial_auth.iterations
    assert auth_data.salted_password == initial_auth.salted_password
    assert auth_data.client_key == initial_auth.client_key
    assert auth_data.stored_key == initial_auth.stored_key
    assert auth_data.server_key == initial_auth.server_key


def test_generate_scram_auth_data_invalid_salted_password_without_salt():
    """Test that providing salted_password without salt raises TypeError."""
    salted_password = truenas_pyscram.generate_nonce()
    with pytest.raises(truenas_pyscram.ScramError):
        truenas_pyscram.generate_scram_auth_data(salted_password=salted_password)


def test_generate_scram_auth_data_invalid_salted_password_without_iterations():
    """Test that providing salted_password without iterations raises TypeError."""
    salted_password = truenas_pyscram.generate_nonce()
    salt_bytes = truenas_pyscram.generate_nonce()[:16]
    salt = truenas_pyscram.CryptoDatum(salt_bytes)
    with pytest.raises(truenas_pyscram.ScramError):
        truenas_pyscram.generate_scram_auth_data(
            salted_password=salted_password,
            salt=salt
        )


def test_scram_auth_data_repr():
    """Test that ScramAuthData has a useful repr."""
    auth_data = truenas_pyscram.generate_scram_auth_data()
    repr_str = repr(auth_data)
    assert "ScramAuthData" in repr_str
    assert str(auth_data.iterations) in repr_str
