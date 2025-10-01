"""Test SCRAM client final message functionality."""

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
    return truenas_pyscram.ClientFirstMessage(username="testuser")


@pytest.fixture
def client_first_with_gs2():
    """Generate a client first message with GS2 header for testing."""
    return truenas_pyscram.ClientFirstMessage(username="testuser",
                                              gs2_header="p=tls-unique")


@pytest.fixture
def server_first(client_first, auth_data):
    """Generate a server first message for testing."""
    return truenas_pyscram.ServerFirstMessage(client_first=client_first,
                                              salt=auth_data.salt,
                                              iterations=auth_data.iterations)


@pytest.fixture
def server_first_with_gs2(client_first_with_gs2, auth_data):
    """Generate a server first message for GS2 client for testing."""
    return truenas_pyscram.ServerFirstMessage(client_first=client_first_with_gs2,
                                              salt=auth_data.salt,
                                              iterations=auth_data.iterations)


@pytest.fixture
def channel_binding():
    """Generate channel binding data for testing."""
    return truenas_pyscram.CryptoDatum(b"fake_channel_binding_data")


def test_client_final_message_creation(client_first, server_first, auth_data):
    """Test that ClientFinalMessage can be created."""
    msg = truenas_pyscram.ClientFinalMessage(
        client_first=client_first,
        server_first=server_first,
        client_key=auth_data.client_key,
        stored_key=auth_data.stored_key
    )
    assert isinstance(msg.nonce, truenas_pyscram.CryptoDatum)
    assert isinstance(msg.client_proof, truenas_pyscram.CryptoDatum)
    assert msg.gs2_header is None
    assert msg.channel_binding is None


@pytest.mark.parametrize("property_name,expected_type", [
    ("nonce", truenas_pyscram.CryptoDatum),
    ("client_proof", truenas_pyscram.CryptoDatum),
    ("gs2_header", (type(None), str)),
    ("channel_binding", (type(None), truenas_pyscram.CryptoDatum)),
])
def test_client_final_message_property_types(client_first, server_first,
                                             auth_data, property_name,
                                             expected_type):
    """Test that ClientFinalMessage properties have correct types."""
    msg = truenas_pyscram.ClientFinalMessage(
        client_first=client_first,
        server_first=server_first,
        client_key=auth_data.client_key,
        stored_key=auth_data.stored_key
    )
    prop_value = getattr(msg, property_name)
    if isinstance(expected_type, tuple):
        assert isinstance(prop_value, expected_type)
    else:
        assert isinstance(prop_value, expected_type)


def test_client_final_message_with_channel_binding(client_first_with_gs2,
                                                   server_first_with_gs2,
                                                   auth_data, channel_binding):
    """Test ClientFinalMessage creation with channel binding."""
    msg = truenas_pyscram.ClientFinalMessage(
        client_first=client_first_with_gs2,
        server_first=server_first_with_gs2,
        client_key=auth_data.client_key,
        stored_key=auth_data.stored_key,
        channel_binding=channel_binding
    )
    assert isinstance(msg.nonce, truenas_pyscram.CryptoDatum)
    assert isinstance(msg.client_proof, truenas_pyscram.CryptoDatum)
    assert msg.gs2_header == "p=tls-unique"
    assert isinstance(msg.channel_binding, truenas_pyscram.CryptoDatum)
    assert bytes(msg.channel_binding) == b"fake_channel_binding_data"


def test_client_final_message_nonce_property(client_first, server_first,
                                             auth_data):
    """Test that nonce property returns correct combined nonce."""
    msg = truenas_pyscram.ClientFinalMessage(
        client_first=client_first,
        server_first=server_first,
        client_key=auth_data.client_key,
        stored_key=auth_data.stored_key
    )
    assert isinstance(msg.nonce, truenas_pyscram.CryptoDatum)
    # Nonce should match the server first message nonce
    assert bytes(msg.nonce) == bytes(server_first.nonce)


def test_client_final_message_client_proof_property(client_first, server_first,
                                                    auth_data):
    """Test that client_proof property returns valid proof."""
    msg = truenas_pyscram.ClientFinalMessage(
        client_first=client_first,
        server_first=server_first,
        client_key=auth_data.client_key,
        stored_key=auth_data.stored_key
    )
    assert isinstance(msg.client_proof, truenas_pyscram.CryptoDatum)
    # Client proof should be 64 bytes (SHA-512)
    assert len(bytes(msg.client_proof)) == 64


def test_client_final_message_str_format(client_first, server_first,
                                         auth_data):
    """Test that str() returns RFC 5802 formatted message."""
    msg = truenas_pyscram.ClientFinalMessage(
        client_first=client_first,
        server_first=server_first,
        client_key=auth_data.client_key,
        stored_key=auth_data.stored_key
    )

    msg_str = str(msg)

    # Should match RFC 5802 client-final-message format: c=<cb>,r=<nonce>,p=<proof>  # noqa: E501
    pattern = r'^c=[A-Za-z0-9+/=]+,r=[A-Za-z0-9+/=]+,p=[A-Za-z0-9+/=]+$'
    assert re.match(pattern, msg_str)


def test_client_final_message_str_components(client_first, server_first,
                                             auth_data):
    """Test that str() contains correct base64-encoded components."""
    msg = truenas_pyscram.ClientFinalMessage(
        client_first=client_first,
        server_first=server_first,
        client_key=auth_data.client_key,
        stored_key=auth_data.stored_key
    )

    msg_str = str(msg)

    # Parse the components
    parts = msg_str.split(',')
    assert len(parts) == 3

    # Extract channel binding (c=...)
    cb_part = parts[0]
    assert cb_part.startswith('c=')
    cb_b64 = cb_part[2:]  # Remove "c="
    cb_decoded = base64.b64decode(cb_b64)
    # Should be base64 encoding of GS2 header + channel binding
    # For no channel binding, should be "biws" (base64 of "n,,")
    assert cb_b64 == "biws"
    assert cb_decoded == b"n,,"  # Verify decoded content

    # Extract nonce (r=...)
    nonce_part = parts[1]
    assert nonce_part.startswith('r=')
    nonce_b64 = nonce_part[2:]  # Remove "r="
    nonce_decoded = base64.b64decode(nonce_b64)
    assert nonce_decoded == bytes(msg.nonce)

    # Extract client proof (p=...)
    proof_part = parts[2]
    assert proof_part.startswith('p=')
    proof_b64 = proof_part[2:]  # Remove "p="
    proof_decoded = base64.b64decode(proof_b64)
    assert proof_decoded == bytes(msg.client_proof)


def test_client_final_message_str_with_channel_binding(client_first_with_gs2,
                                                       server_first_with_gs2,
                                                       auth_data,
                                                       channel_binding):
    """Test str() format with channel binding."""
    msg = truenas_pyscram.ClientFinalMessage(
        client_first=client_first_with_gs2,
        server_first=server_first_with_gs2,
        client_key=auth_data.client_key,
        stored_key=auth_data.stored_key,
        channel_binding=channel_binding
    )

    msg_str = str(msg)
    parts = msg_str.split(',')

    # Channel binding part should be different from "biws"
    cb_part = parts[0]
    assert cb_part.startswith('c=')
    cb_b64 = cb_part[2:]
    assert cb_b64 != "biws"  # Should include actual channel binding data


@pytest.mark.parametrize("invalid_client_first,expected_error", [
    ("not_a_client_first",
     "client_first must be a ClientFirstMessage instance"),
    (123, "client_first must be a ClientFirstMessage instance"),
    (None, "client_first must be a ClientFirstMessage instance"),
])
def test_client_final_message_invalid_client_first(server_first, auth_data,
                                                   invalid_client_first,
                                                   expected_error):
    """Test ClientFinalMessage with invalid client_first parameter."""
    with pytest.raises(TypeError, match=expected_error):
        truenas_pyscram.ClientFinalMessage(
            client_first=invalid_client_first,
            server_first=server_first,
            client_key=auth_data.client_key,
            stored_key=auth_data.stored_key
        )


@pytest.mark.parametrize("invalid_server_first,expected_error", [
    ("not_a_server_first",
     "server_first must be a ServerFirstMessage instance"),
    (123, "server_first must be a ServerFirstMessage instance"),
    (None, "server_first must be a ServerFirstMessage instance"),
])
def test_client_final_message_invalid_server_first(client_first, auth_data,
                                                   invalid_server_first,
                                                   expected_error):
    """Test ClientFinalMessage with invalid server_first parameter."""
    with pytest.raises(TypeError, match=expected_error):
        truenas_pyscram.ClientFinalMessage(
            client_first=client_first,
            server_first=invalid_server_first,
            client_key=auth_data.client_key,
            stored_key=auth_data.stored_key
        )


@pytest.mark.parametrize("invalid_key,key_param,expected_error", [
    ("not_a_crypto_datum", "client_key",
     "client_key must be a CryptoDatum instance"),
    (123, "client_key", "client_key must be a CryptoDatum instance"),
    (None, "client_key", "client_key must be a CryptoDatum instance"),
    ("not_a_crypto_datum", "stored_key",
     "stored_key must be a CryptoDatum instance"),
    (123, "stored_key", "stored_key must be a CryptoDatum instance"),
    (None, "stored_key", "stored_key must be a CryptoDatum instance"),
])
def test_client_final_message_invalid_keys(client_first, server_first,
                                           auth_data, invalid_key, key_param,
                                           expected_error):
    """Test ClientFinalMessage with invalid key parameters."""
    kwargs = {
        "client_first": client_first,
        "server_first": server_first,
        "client_key": auth_data.client_key,
        "stored_key": auth_data.stored_key,
    }
    kwargs[key_param] = invalid_key

    with pytest.raises(TypeError, match=expected_error):
        truenas_pyscram.ClientFinalMessage(**kwargs)


@pytest.mark.parametrize("invalid_channel_binding,expected_error", [
    ("not_a_crypto_datum",
     "channel_binding must be a CryptoDatum instance or None"),
    (123, "channel_binding must be a CryptoDatum instance or None"),
    (b"bytes_data", "channel_binding must be a CryptoDatum instance or None"),
])
def test_client_final_message_invalid_channel_binding(client_first,
                                                      server_first, auth_data,
                                                      invalid_channel_binding,
                                                      expected_error):
    """Test ClientFinalMessage with invalid channel_binding parameter."""
    with pytest.raises(TypeError, match=expected_error):
        truenas_pyscram.ClientFinalMessage(
            client_first=client_first,
            server_first=server_first,
            client_key=auth_data.client_key,
            stored_key=auth_data.stored_key,
            channel_binding=invalid_channel_binding
        )


def test_client_final_message_different_auth_data(client_first, server_first):
    """Test ClientFinalMessage with different auth data."""
    # Generate multiple auth data sets
    auth_data_sets = [truenas_pyscram.generate_scram_auth_data()
                      for _ in range(3)]

    messages = []
    for auth_data in auth_data_sets:
        msg = truenas_pyscram.ClientFinalMessage(
            client_first=client_first,
            server_first=server_first,
            client_key=auth_data.client_key,
            stored_key=auth_data.stored_key
        )
        messages.append(msg)

    # All messages should have different client proofs
    proofs = [bytes(msg.client_proof) for msg in messages]
    assert len(set(proofs)) == len(proofs)  # All unique

    # But same nonce (from server_first)
    nonces = [bytes(msg.nonce) for msg in messages]
    assert len(set(nonces)) == 1  # All same


def test_client_final_message_consistent_nonce(auth_data):
    """Test that ClientFinalMessage uses consistent nonce from server."""
    client1 = truenas_pyscram.ClientFirstMessage(username="user1")
    client2 = truenas_pyscram.ClientFirstMessage(username="user2")

    server1 = truenas_pyscram.ServerFirstMessage(client_first=client1,
                                                 salt=auth_data.salt,
                                                 iterations=auth_data.iterations)
    server2 = truenas_pyscram.ServerFirstMessage(client_first=client2,
                                                 salt=auth_data.salt,
                                                 iterations=auth_data.iterations)

    final1 = truenas_pyscram.ClientFinalMessage(
        client_first=client1, server_first=server1,
        client_key=auth_data.client_key, stored_key=auth_data.stored_key)
    final2 = truenas_pyscram.ClientFinalMessage(
        client_first=client2, server_first=server2,
        client_key=auth_data.client_key, stored_key=auth_data.stored_key)

    # Each final message should use its corresponding server's nonce
    assert bytes(final1.nonce) == bytes(server1.nonce)
    assert bytes(final2.nonce) == bytes(server2.nonce)

    # But server nonces should be different (different clients)
    assert bytes(server1.nonce) != bytes(server2.nonce)


@pytest.mark.parametrize("username,api_key_id", [
    ("user1", 0),
    ("user2", 12345),
    ("admin", 999),
])
def test_client_final_message_with_different_clients(auth_data, username,
                                                     api_key_id):
    """Test ClientFinalMessage with different client configurations."""
    client = truenas_pyscram.ClientFirstMessage(username=username,
                                                api_key_id=api_key_id)
    server = truenas_pyscram.ServerFirstMessage(client_first=client,
                                                salt=auth_data.salt,
                                                iterations=auth_data.iterations)
    msg = truenas_pyscram.ClientFinalMessage(
        client_first=client,
        server_first=server,
        client_key=auth_data.client_key,
        stored_key=auth_data.stored_key
    )

    # Should create valid message regardless of client configuration
    assert isinstance(msg.nonce, truenas_pyscram.CryptoDatum)
    assert isinstance(msg.client_proof, truenas_pyscram.CryptoDatum)
    assert msg.gs2_header is None  # No GS2 header specified
    assert msg.channel_binding is None  # No channel binding


def test_client_final_message_none_channel_binding(client_first, server_first,
                                                   auth_data):
    """Test ClientFinalMessage with explicit None channel binding."""
    msg = truenas_pyscram.ClientFinalMessage(
        client_first=client_first,
        server_first=server_first,
        client_key=auth_data.client_key,
        stored_key=auth_data.stored_key,
        channel_binding=None  # Explicit None
    )

    assert isinstance(msg.nonce, truenas_pyscram.CryptoDatum)
    assert isinstance(msg.client_proof, truenas_pyscram.CryptoDatum)
    assert msg.channel_binding is None
