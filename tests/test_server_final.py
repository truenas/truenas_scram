"""Test SCRAM server final message functionality."""

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


@pytest.fixture
def server_first(client_first, auth_data):
    """Generate a server first message for testing."""
    return truenas_pyscram.ServerFirstMessage(client_first, auth_data.salt,
                                              auth_data.iterations)


@pytest.fixture
def client_final(client_first, server_first, auth_data):
    """Generate a client final message for testing."""
    return truenas_pyscram.ClientFinalMessage(client_first, server_first,
                                              auth_data.client_key,
                                              auth_data.stored_key)


def test_server_final_message_creation(client_first, server_first,
                                       client_final, auth_data):
    """Test that ServerFinalMessage can be created."""
    msg = truenas_pyscram.ServerFinalMessage(
        client_first,
        server_first,
        client_final,
        auth_data.stored_key,
        auth_data.server_key
    )
    assert isinstance(msg.signature, truenas_pyscram.CryptoDatum)


def test_server_final_message_signature_property(client_first, server_first,
                                                 client_final, auth_data):
    """Test that signature property returns valid server signature."""
    msg = truenas_pyscram.ServerFinalMessage(
        client_first,
        server_first,
        client_final,
        auth_data.stored_key,
        auth_data.server_key
    )
    assert isinstance(msg.signature, truenas_pyscram.CryptoDatum)
    # Server signature should be 64 bytes (SHA-512)
    assert len(bytes(msg.signature)) == 64


def test_server_final_message_str_format(client_first, server_first,
                                         client_final, auth_data):
    """Test that str() returns RFC 5802 formatted message."""
    msg = truenas_pyscram.ServerFinalMessage(
        client_first,
        server_first,
        client_final,
        auth_data.stored_key,
        auth_data.server_key
    )

    msg_str = str(msg)

    # Should match RFC 5802 server-final-message format: v=<signature>
    pattern = r'^v=[A-Za-z0-9+/=]+$'
    assert re.match(pattern, msg_str)


def test_server_final_message_str_components(client_first, server_first,
                                             client_final, auth_data):
    """Test that str() contains correct base64-encoded signature."""
    msg = truenas_pyscram.ServerFinalMessage(
        client_first,
        server_first,
        client_final,
        auth_data.stored_key,
        auth_data.server_key
    )

    msg_str = str(msg)

    # Should start with "v="
    assert msg_str.startswith('v=')

    # Extract and decode signature
    sig_b64 = msg_str[2:]  # Remove "v="
    sig_decoded = base64.b64decode(sig_b64)
    assert sig_decoded == bytes(msg.signature)


@pytest.mark.parametrize("invalid_client_first,expected_error", [
    ("not_a_client_first",
     "client_first must be a ClientFirstMessage instance"),
    (123, "client_first must be a ClientFirstMessage instance"),
    (None, "client_first must be a ClientFirstMessage instance"),
])
def test_server_final_message_invalid_client_first(server_first, client_final,
                                                   auth_data,
                                                   invalid_client_first,
                                                   expected_error):
    """Test ServerFinalMessage with invalid client_first parameter."""
    with pytest.raises(TypeError, match=expected_error):
        truenas_pyscram.ServerFinalMessage(
            invalid_client_first,
            server_first,
            client_final,
            auth_data.stored_key,
            auth_data.server_key
        )


@pytest.mark.parametrize("invalid_server_first,expected_error", [
    ("not_a_server_first",
     "server_first must be a ServerFirstMessage instance"),
    (123, "server_first must be a ServerFirstMessage instance"),
    (None, "server_first must be a ServerFirstMessage instance"),
])
def test_server_final_message_invalid_server_first(client_first, client_final,
                                                   auth_data,
                                                   invalid_server_first,
                                                   expected_error):
    """Test ServerFinalMessage with invalid server_first parameter."""
    with pytest.raises(TypeError, match=expected_error):
        truenas_pyscram.ServerFinalMessage(
            client_first,
            invalid_server_first,
            client_final,
            auth_data.stored_key,
            auth_data.server_key
        )


@pytest.mark.parametrize("invalid_client_final,expected_error", [
    ("not_a_client_final",
     "client_final must be a ClientFinalMessage instance"),
    (123, "client_final must be a ClientFinalMessage instance"),
    (None, "client_final must be a ClientFinalMessage instance"),
])
def test_server_final_message_invalid_client_final(client_first, server_first,
                                                   auth_data,
                                                   invalid_client_final,
                                                   expected_error):
    """Test ServerFinalMessage with invalid client_final parameter."""
    with pytest.raises(TypeError, match=expected_error):
        truenas_pyscram.ServerFinalMessage(
            client_first,
            server_first,
            invalid_client_final,
            auth_data.stored_key,
            auth_data.server_key
        )


@pytest.mark.parametrize("invalid_key,key_param,expected_error", [
    ("not_a_crypto_datum", "stored_key",
     "stored_key must be a CryptoDatum instance"),
    (123, "stored_key", "stored_key must be a CryptoDatum instance"),
    (None, "stored_key", "stored_key must be a CryptoDatum instance"),
    ("not_a_crypto_datum", "server_key",
     "server_key must be a CryptoDatum instance"),
    (123, "server_key", "server_key must be a CryptoDatum instance"),
    (None, "server_key", "server_key must be a CryptoDatum instance"),
])
def test_server_final_message_invalid_keys(client_first, server_first,
                                           client_final, auth_data,
                                           invalid_key, key_param,
                                           expected_error):
    """Test ServerFinalMessage with invalid key parameters."""
    kwargs = {
        "client_first": client_first,
        "server_first": server_first,
        "client_final": client_final,
        "stored_key": auth_data.stored_key,
        "server_key": auth_data.server_key,
    }
    kwargs[key_param] = invalid_key

    with pytest.raises(TypeError, match=expected_error):
        truenas_pyscram.ServerFinalMessage(**kwargs)


def test_server_final_message_different_auth_data(client_first, server_first,
                                                  client_final):
    """Test ServerFinalMessage with different auth data."""
    # Generate multiple auth data sets
    auth_data_sets = [truenas_pyscram.generate_scram_auth_data()
                      for _ in range(3)]

    messages = []
    for auth_data in auth_data_sets:
        msg = truenas_pyscram.ServerFinalMessage(
            client_first,
            server_first,
            client_final,
            auth_data.stored_key,
            auth_data.server_key
        )
        messages.append(msg)

    # All messages should have different server signatures
    signatures = [bytes(msg.signature) for msg in messages]
    assert len(set(signatures)) == len(signatures)  # All unique


def test_server_final_message_consistent_with_same_auth(client_first,
                                                        server_first,
                                                        auth_data):
    """Test that ServerFinalMessage is consistent with same auth data."""
    # Create two client final messages with same auth data
    client_final1 = truenas_pyscram.ClientFinalMessage(
        client_first, server_first, auth_data.client_key, auth_data.stored_key)
    client_final2 = truenas_pyscram.ClientFinalMessage(
        client_first, server_first, auth_data.client_key, auth_data.stored_key)

    # Create server final messages
    server_final1 = truenas_pyscram.ServerFinalMessage(
        client_first, server_first, client_final1,
        auth_data.stored_key, auth_data.server_key)
    server_final2 = truenas_pyscram.ServerFinalMessage(
        client_first, server_first, client_final2,
        auth_data.stored_key, auth_data.server_key)

    # Server signatures should be the same (same auth message)
    assert bytes(server_final1.signature) == bytes(server_final2.signature)


def test_server_final_message_different_clients(auth_data):
    """Test ServerFinalMessage with different client configurations."""
    # Create different clients
    clients = [
        truenas_pyscram.ClientFirstMessage("user1"),
        truenas_pyscram.ClientFirstMessage("user2", api_key_id=123),
        truenas_pyscram.ClientFirstMessage("admin", api_key_id=999),
    ]

    messages = []
    for client in clients:
        server_first = truenas_pyscram.ServerFirstMessage(
            client, auth_data.salt, auth_data.iterations)
        client_final = truenas_pyscram.ClientFinalMessage(
            client, server_first, auth_data.client_key, auth_data.stored_key)
        server_final = truenas_pyscram.ServerFinalMessage(
            client, server_first, client_final,
            auth_data.stored_key, auth_data.server_key)
        messages.append(server_final)

    # All should be valid but have different signatures (different auth messages)  # noqa: E501
    for msg in messages:
        assert isinstance(msg.signature, truenas_pyscram.CryptoDatum)
        assert len(bytes(msg.signature)) == 64

    # Signatures should be different (different client nonces/messages)
    signatures = [bytes(msg.signature) for msg in messages]
    assert len(set(signatures)) == len(signatures)  # All unique


def test_server_final_message_with_channel_binding(auth_data):
    """Test ServerFinalMessage with channel binding."""
    # Create client with channel binding
    client_first = truenas_pyscram.ClientFirstMessage(
        "testuser", gs2_header="p=tls-unique")
    server_first = truenas_pyscram.ServerFirstMessage(
        client_first, auth_data.salt, auth_data.iterations)

    # Create channel binding data
    channel_binding = truenas_pyscram.CryptoDatum(b"fake_channel_binding_data")

    client_final = truenas_pyscram.ClientFinalMessage(
        client_first, server_first, auth_data.client_key,
        auth_data.stored_key, channel_binding)
    server_final = truenas_pyscram.ServerFinalMessage(
        client_first, server_first, client_final,
        auth_data.stored_key, auth_data.server_key)

    assert isinstance(server_final.signature, truenas_pyscram.CryptoDatum)
    assert len(bytes(server_final.signature)) == 64

    # Should produce different signature than without channel binding
    client_final_no_cb = truenas_pyscram.ClientFinalMessage(
        client_first, server_first, auth_data.client_key, auth_data.stored_key)
    server_final_no_cb = truenas_pyscram.ServerFinalMessage(
        client_first, server_first, client_final_no_cb,
        auth_data.stored_key, auth_data.server_key)

    assert bytes(server_final.signature) != bytes(server_final_no_cb.signature)


def test_server_final_message_full_scram_flow(auth_data):
    """Test ServerFinalMessage in complete SCRAM authentication flow."""
    # Complete SCRAM flow
    client_first = truenas_pyscram.ClientFirstMessage("testuser")
    server_first = truenas_pyscram.ServerFirstMessage(
        client_first, auth_data.salt, auth_data.iterations)
    client_final = truenas_pyscram.ClientFinalMessage(
        client_first, server_first, auth_data.client_key, auth_data.stored_key)
    server_final = truenas_pyscram.ServerFinalMessage(
        client_first, server_first, client_final,
        auth_data.stored_key, auth_data.server_key)

    # Verify all messages are properly formatted
    assert str(client_first).startswith("n,,n=testuser,r=")
    assert re.match(r'^r=[A-Za-z0-9+/=]+,s=[A-Za-z0-9+/=]+,i=\d+$',
                    str(server_first))
    assert re.match(r'^c=[A-Za-z0-9+/=]+,r=[A-Za-z0-9+/=]+,p=[A-Za-z0-9+/=]+$',
                    str(client_final))
    assert re.match(r'^v=[A-Za-z0-9+/=]+$', str(server_final))

    # Verify signature is valid length
    assert len(bytes(server_final.signature)) == 64


@pytest.mark.parametrize("username,api_key_id", [
    ("user1", 0),
    ("user2", 12345),
    ("admin", 999),
])
def test_server_final_message_parametrized_clients(auth_data, username,
                                                   api_key_id):
    """Test ServerFinalMessage with parametrized client configurations."""
    client = truenas_pyscram.ClientFirstMessage(username,
                                                api_key_id=api_key_id)
    server_first = truenas_pyscram.ServerFirstMessage(
        client, auth_data.salt, auth_data.iterations)
    client_final = truenas_pyscram.ClientFinalMessage(
        client, server_first, auth_data.client_key, auth_data.stored_key)
    msg = truenas_pyscram.ServerFinalMessage(
        client, server_first, client_final,
        auth_data.stored_key, auth_data.server_key)

    # Should create valid message regardless of client configuration
    assert isinstance(msg.signature, truenas_pyscram.CryptoDatum)
    assert len(bytes(msg.signature)) == 64

    # String format should be valid
    msg_str = str(msg)
    assert msg_str.startswith('v=')
    assert len(msg_str) > 3  # More than just "v="
