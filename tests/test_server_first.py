"""Test SCRAM server first message functionality."""

import base64
import re

import pytest
import truenas_pyscram


@pytest.fixture
def auth_data():
    """Generate SCRAM auth data for testing."""
    return truenas_pyscram.generate_scram_auth_data()


@pytest.fixture
def client_first():
    """Generate a client first message for testing."""
    return truenas_pyscram.ClientFirstMessage("testuser")


def test_server_first_message_creation(client_first, auth_data):
    """Test that ServerFirstMessage can be created."""
    msg = truenas_pyscram.ServerFirstMessage(
        client_first,
        auth_data.salt,
        auth_data.iterations
    )
    assert isinstance(msg.salt, truenas_pyscram.CryptoDatum)
    assert isinstance(msg.nonce, truenas_pyscram.CryptoDatum)
    assert isinstance(msg.iterations, int)


@pytest.mark.parametrize("property_name,expected_type", [
    ("salt", truenas_pyscram.CryptoDatum),
    ("nonce", truenas_pyscram.CryptoDatum),
    ("iterations", int),
])
def test_server_first_message_property_types(client_first, auth_data,
                                             property_name, expected_type):
    """Test that ServerFirstMessage properties have correct types."""
    msg = truenas_pyscram.ServerFirstMessage(
        client_first,
        auth_data.salt,
        auth_data.iterations
    )
    assert isinstance(getattr(msg, property_name), expected_type)


def test_server_first_message_salt_property(client_first, auth_data):
    """Test that salt property returns the correct CryptoDatum."""
    msg = truenas_pyscram.ServerFirstMessage(
        client_first,
        auth_data.salt,
        auth_data.iterations
    )
    assert isinstance(msg.salt, truenas_pyscram.CryptoDatum)
    assert bytes(msg.salt) == bytes(auth_data.salt)


def test_server_first_message_iterations_property(client_first, auth_data):
    """Test that iterations property returns the correct value."""
    msg = truenas_pyscram.ServerFirstMessage(
        client_first,
        auth_data.salt,
        auth_data.iterations
    )
    assert msg.iterations == auth_data.iterations


def test_server_first_message_nonce_property(client_first, auth_data):
    """Test that nonce is a CryptoDatum and contains client nonce."""
    msg = truenas_pyscram.ServerFirstMessage(
        client_first,
        auth_data.salt,
        auth_data.iterations
    )
    assert isinstance(msg.nonce, truenas_pyscram.CryptoDatum)

    # Combined nonce should start with client nonce
    client_nonce_bytes = bytes(client_first.nonce)
    combined_nonce_bytes = bytes(msg.nonce)
    assert combined_nonce_bytes.startswith(client_nonce_bytes)

    # Combined nonce should be longer than client nonce
    assert len(combined_nonce_bytes) > len(client_nonce_bytes)


def test_server_first_message_nonce_length(client_first, auth_data):
    """Test that combined nonce has expected length."""
    msg = truenas_pyscram.ServerFirstMessage(
        client_first,
        auth_data.salt,
        auth_data.iterations
    )

    # Combined nonce should be client nonce + server nonce
    # Both nonces should be 24 bytes each, so combined = 48 bytes
    expected_length = len(bytes(client_first.nonce)) * 2
    assert len(bytes(msg.nonce)) == expected_length


def test_server_first_message_str_format(client_first, auth_data):
    """Test that str() returns RFC 5802 formatted message."""
    msg = truenas_pyscram.ServerFirstMessage(
        client_first,
        auth_data.salt,
        auth_data.iterations
    )

    msg_str = str(msg)

    # Should match RFC 5802 server-first-message format: r=nonce,s=salt,i=iter
    pattern = r'^r=[A-Za-z0-9+/=]+,s=[A-Za-z0-9+/=]+,i=\d+$'
    assert re.match(pattern, msg_str)


def test_server_first_message_str_components(client_first, auth_data):
    """Test that str() contains correct base64-encoded components."""
    msg = truenas_pyscram.ServerFirstMessage(
        client_first,
        auth_data.salt,
        auth_data.iterations
    )

    msg_str = str(msg)

    # Parse the components
    parts = msg_str.split(',')
    assert len(parts) == 3

    # Extract nonce (r=...)
    nonce_part = parts[0]
    assert nonce_part.startswith('r=')
    nonce_b64 = nonce_part[2:]  # Remove "r="
    nonce_decoded = base64.b64decode(nonce_b64)
    assert nonce_decoded == bytes(msg.nonce)

    # Extract salt (s=...)
    salt_part = parts[1]
    assert salt_part.startswith('s=')
    salt_b64 = salt_part[2:]  # Remove "s="
    salt_decoded = base64.b64decode(salt_b64)
    assert salt_decoded == bytes(msg.salt)

    # Extract iterations (i=...)
    iter_part = parts[2]
    assert iter_part.startswith('i=')
    iter_value = int(iter_part[2:])  # Remove "i="
    assert iter_value == msg.iterations


@pytest.mark.parametrize("iterations", [50000, 100000, 250000, 500000])
def test_server_first_message_different_iterations(client_first, auth_data,
                                                   iterations):
    """Test ServerFirstMessage with different iteration counts."""
    msg = truenas_pyscram.ServerFirstMessage(
        client_first,
        auth_data.salt,
        iterations
    )
    assert msg.iterations == iterations

    msg_str = str(msg)
    assert f"i={iterations}" in msg_str


@pytest.mark.parametrize("invalid_client_first,expected_error", [
    ("not_a_client_first",
     "client_first must be a ClientFirstMessage instance"),
    (123, "client_first must be a ClientFirstMessage instance"),
    (None, "client_first must be a ClientFirstMessage instance"),
])
def test_server_first_message_invalid_client_first(auth_data,
                                                   invalid_client_first,
                                                   expected_error):
    """Test ServerFirstMessage with invalid client_first parameter."""
    with pytest.raises(TypeError, match=expected_error):
        truenas_pyscram.ServerFirstMessage(
            invalid_client_first,
            auth_data.salt,
            auth_data.iterations
        )


@pytest.mark.parametrize("invalid_salt,expected_error", [
    ("not_a_crypto_datum", "salt must be a CryptoDatum instance"),
    (b"bytes_salt", "salt must be a CryptoDatum instance"),
    (123, "salt must be a CryptoDatum instance"),
    (None, "salt must be a CryptoDatum instance"),
])
def test_server_first_message_invalid_salt(client_first, auth_data,
                                           invalid_salt, expected_error):
    """Test ServerFirstMessage with invalid salt parameter."""
    with pytest.raises(TypeError, match=expected_error):
        truenas_pyscram.ServerFirstMessage(
            client_first,
            invalid_salt,
            auth_data.iterations
        )


@pytest.mark.parametrize("invalid_iterations", [
    1000,      # Below SCRAM_MIN_ITERS (50000)
    6000000,   # Above SCRAM_MAX_ITERS (5000000)
    0,         # Zero iterations
    -1,        # Negative iterations
])
def test_server_first_message_invalid_iterations(client_first, auth_data,
                                                 invalid_iterations):
    """Test ServerFirstMessage with invalid iteration values."""
    with pytest.raises(RuntimeError):
        truenas_pyscram.ServerFirstMessage(
            client_first,
            auth_data.salt,
            invalid_iterations
        )


def test_server_first_message_reproducible_with_same_client(auth_data):
    """Test that ServerFirstMessage is deterministic for same client nonce."""
    # Create two client messages with same parameters
    client1 = truenas_pyscram.ClientFirstMessage("testuser")
    client2 = truenas_pyscram.ClientFirstMessage("testuser")

    # They should have different nonces (random generation)
    assert bytes(client1.nonce) != bytes(client2.nonce)

    # Server first messages should be different due to different client nonces
    msg1 = truenas_pyscram.ServerFirstMessage(
        client1,
        auth_data.salt,
        auth_data.iterations
    )
    msg2 = truenas_pyscram.ServerFirstMessage(
        client2,
        auth_data.salt,
        auth_data.iterations
    )

    assert str(msg1) != str(msg2)
    assert bytes(msg1.nonce) != bytes(msg2.nonce)


def test_server_first_message_unique_server_nonces(client_first, auth_data):
    """Test that ServerFirstMessage generates unique server nonces."""
    # Create multiple server first messages with same client
    messages = []
    for _ in range(5):
        msg = truenas_pyscram.ServerFirstMessage(
            client_first,
            auth_data.salt,
            auth_data.iterations
        )
        messages.append(msg)

    # All combined nonces should be different (due to random server nonce)
    nonces = [bytes(msg.nonce) for msg in messages]
    assert len(set(nonces)) == len(nonces)  # All unique


@pytest.mark.parametrize("username,api_key_id", [
    ("user1", 0),
    ("user2", 12345),
    ("admin", 999),
])
def test_server_first_message_with_different_clients(auth_data, username,
                                                     api_key_id):
    """Test ServerFirstMessage with different client configurations."""
    client = truenas_pyscram.ClientFirstMessage(username,
                                                api_key_id=api_key_id)
    msg = truenas_pyscram.ServerFirstMessage(
        client,
        auth_data.salt,
        auth_data.iterations
    )

    # Should create valid message regardless of client configuration
    assert isinstance(msg.salt, truenas_pyscram.CryptoDatum)
    assert isinstance(msg.nonce, truenas_pyscram.CryptoDatum)
    assert msg.iterations == auth_data.iterations

    # Combined nonce should still contain client nonce
    client_nonce_bytes = bytes(client.nonce)
    combined_nonce_bytes = bytes(msg.nonce)
    assert combined_nonce_bytes.startswith(client_nonce_bytes)
