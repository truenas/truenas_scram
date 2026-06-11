"""Test SCRAM verification functionality."""

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
def server_first(client_first, auth_data):
    """Generate a server first message for testing."""
    return truenas_pyscram.ServerFirstMessage(client_first=client_first,
                                              salt=auth_data.salt,
                                              iterations=auth_data.iterations)


@pytest.fixture
def client_final(client_first, server_first, auth_data):
    """Generate a client final message for testing."""
    return truenas_pyscram.ClientFinalMessage(client_first=client_first,
                                              server_first=server_first,
                                              client_key=auth_data.client_key,
                                              stored_key=auth_data.stored_key)


@pytest.fixture
def server_final(client_first, server_first, client_final, auth_data):
    """Generate a server final message for testing."""
    return truenas_pyscram.ServerFinalMessage(
        client_first=client_first,
        server_first=server_first,
        client_final=client_final,
        stored_key=auth_data.stored_key,
        server_key=auth_data.server_key
    )


def test_verify_client_final_message_success(client_first, server_first,
                                             client_final, auth_data):
    """Test successful client final message verification."""
    # Should not raise an exception
    truenas_pyscram.verify_client_final_message(
        client_first=client_first, server_first=server_first,
        client_final=client_final, stored_key=auth_data.stored_key)


def test_verify_server_signature_success(client_first, server_first,
                                        client_final, server_final, auth_data):
    """Test successful server signature verification."""
    # Should not raise an exception
    truenas_pyscram.verify_server_signature(
        client_first=client_first, server_first=server_first,
        client_final=client_final, server_final=server_final,
        server_key=auth_data.server_key)


def test_verify_client_final_message_with_wrong_key(client_first, server_first,
                                                   client_final):
    """Test client final message verification with wrong stored key."""
    wrong_auth_data = truenas_pyscram.generate_scram_auth_data()

    with pytest.raises(truenas_pyscram.ScramError, match="SCRAM_E_AUTH_FAILED"):
        truenas_pyscram.verify_client_final_message(
            client_first=client_first, server_first=server_first,
            client_final=client_final, stored_key=wrong_auth_data.stored_key)


def test_verify_server_signature_with_wrong_key(client_first, server_first,
                                               client_final, server_final):
    """Test server signature verification with wrong server key."""
    wrong_auth_data = truenas_pyscram.generate_scram_auth_data()

    with pytest.raises(truenas_pyscram.ScramError, match="SCRAM_E_AUTH_FAILED"):
        truenas_pyscram.verify_server_signature(
            client_first=client_first, server_first=server_first,
            client_final=client_final, server_final=server_final,
            server_key=wrong_auth_data.server_key)


@pytest.mark.parametrize("invalid_param,param_name,expected_error", [
    ("not_a_client_first", "client_first",
     "client_first must be a ClientFirstMessage instance"),
    (123, "client_first", "client_first must be a ClientFirstMessage instance"),
    (None, "client_first", "client_first must be a ClientFirstMessage instance"),
])
def test_verify_client_final_message_invalid_client_first(server_first,
                                                         client_final,
                                                         auth_data,
                                                         invalid_param,
                                                         param_name,
                                                         expected_error):
    """Test client final message verification with invalid client_first."""
    with pytest.raises(TypeError, match=expected_error):
        truenas_pyscram.verify_client_final_message(
            client_first=invalid_param, server_first=server_first,
            client_final=client_final, stored_key=auth_data.stored_key)


@pytest.mark.parametrize("invalid_param,param_name,expected_error", [
    ("not_a_server_first", "server_first",
     "server_first must be a ServerFirstMessage instance"),
    (123, "server_first", "server_first must be a ServerFirstMessage instance"),
    (None, "server_first", "server_first must be a ServerFirstMessage instance"),
])
def test_verify_client_final_message_invalid_server_first(client_first,
                                                         client_final,
                                                         auth_data,
                                                         invalid_param,
                                                         param_name,
                                                         expected_error):
    """Test client final message verification with invalid server_first."""
    with pytest.raises(TypeError, match=expected_error):
        truenas_pyscram.verify_client_final_message(
            client_first=client_first, server_first=invalid_param,
            client_final=client_final, stored_key=auth_data.stored_key)


@pytest.mark.parametrize("invalid_param,param_name,expected_error", [
    ("not_a_client_final", "client_final",
     "client_final must be a ClientFinalMessage instance"),
    (123, "client_final", "client_final must be a ClientFinalMessage instance"),
    (None, "client_final", "client_final must be a ClientFinalMessage instance"),
])
def test_verify_client_final_message_invalid_client_final(client_first,
                                                         server_first,
                                                         auth_data,
                                                         invalid_param,
                                                         param_name,
                                                         expected_error):
    """Test client final message verification with invalid client_final."""
    with pytest.raises(TypeError, match=expected_error):
        truenas_pyscram.verify_client_final_message(
            client_first=client_first, server_first=server_first,
            client_final=invalid_param, stored_key=auth_data.stored_key)


@pytest.mark.parametrize("invalid_param,param_name,expected_error", [
    ("not_a_crypto_datum", "stored_key",
     "stored_key must be a CryptoDatum instance"),
    (123, "stored_key", "stored_key must be a CryptoDatum instance"),
    (None, "stored_key", "stored_key must be a CryptoDatum instance"),
])
def test_verify_client_final_message_invalid_stored_key(client_first,
                                                       server_first,
                                                       client_final,
                                                       invalid_param,
                                                       param_name,
                                                       expected_error):
    """Test client final message verification with invalid stored_key."""
    with pytest.raises(TypeError, match=expected_error):
        truenas_pyscram.verify_client_final_message(
            client_first=client_first, server_first=server_first,
            client_final=client_final, stored_key=invalid_param)


@pytest.mark.parametrize("invalid_param,param_name,expected_error", [
    ("not_a_client_first", "client_first",
     "client_first must be a ClientFirstMessage instance"),
    (123, "client_first", "client_first must be a ClientFirstMessage instance"),
    (None, "client_first", "client_first must be a ClientFirstMessage instance"),
])
def test_verify_server_signature_invalid_client_first(server_first,
                                                     client_final,
                                                     server_final,
                                                     auth_data,
                                                     invalid_param,
                                                     param_name,
                                                     expected_error):
    """Test server signature verification with invalid client_first."""
    with pytest.raises(TypeError, match=expected_error):
        truenas_pyscram.verify_server_signature(
            client_first=invalid_param, server_first=server_first,
            client_final=client_final, server_final=server_final,
            server_key=auth_data.server_key)


@pytest.mark.parametrize("invalid_param,param_name,expected_error", [
    ("not_a_server_first", "server_first",
     "server_first must be a ServerFirstMessage instance"),
    (123, "server_first", "server_first must be a ServerFirstMessage instance"),
    (None, "server_first", "server_first must be a ServerFirstMessage instance"),
])
def test_verify_server_signature_invalid_server_first(client_first,
                                                     client_final,
                                                     server_final,
                                                     auth_data,
                                                     invalid_param,
                                                     param_name,
                                                     expected_error):
    """Test server signature verification with invalid server_first."""
    with pytest.raises(TypeError, match=expected_error):
        truenas_pyscram.verify_server_signature(
            client_first=client_first, server_first=invalid_param,
            client_final=client_final, server_final=server_final,
            server_key=auth_data.server_key)


@pytest.mark.parametrize("invalid_param,param_name,expected_error", [
    ("not_a_client_final", "client_final",
     "client_final must be a ClientFinalMessage instance"),
    (123, "client_final", "client_final must be a ClientFinalMessage instance"),
    (None, "client_final", "client_final must be a ClientFinalMessage instance"),
])
def test_verify_server_signature_invalid_client_final(client_first,
                                                     server_first,
                                                     server_final,
                                                     auth_data,
                                                     invalid_param,
                                                     param_name,
                                                     expected_error):
    """Test server signature verification with invalid client_final."""
    with pytest.raises(TypeError, match=expected_error):
        truenas_pyscram.verify_server_signature(
            client_first=client_first, server_first=server_first,
            client_final=invalid_param, server_final=server_final,
            server_key=auth_data.server_key)


@pytest.mark.parametrize("invalid_param,param_name,expected_error", [
    ("not_a_server_final", "server_final",
     "server_final must be a ServerFinalMessage instance"),
    (123, "server_final", "server_final must be a ServerFinalMessage instance"),
    (None, "server_final", "server_final must be a ServerFinalMessage instance"),
])
def test_verify_server_signature_invalid_server_final(client_first,
                                                     server_first,
                                                     client_final,
                                                     auth_data,
                                                     invalid_param,
                                                     param_name,
                                                     expected_error):
    """Test server signature verification with invalid server_final."""
    with pytest.raises(TypeError, match=expected_error):
        truenas_pyscram.verify_server_signature(
            client_first=client_first, server_first=server_first,
            client_final=client_final, server_final=invalid_param,
            server_key=auth_data.server_key)


@pytest.mark.parametrize("invalid_param,param_name,expected_error", [
    ("not_a_crypto_datum", "server_key",
     "server_key must be a CryptoDatum instance"),
    (123, "server_key", "server_key must be a CryptoDatum instance"),
    (None, "server_key", "server_key must be a CryptoDatum instance"),
])
def test_verify_server_signature_invalid_server_key(client_first,
                                                   server_first,
                                                   client_final,
                                                   server_final,
                                                   invalid_param,
                                                   param_name,
                                                   expected_error):
    """Test server signature verification with invalid server_key."""
    with pytest.raises(TypeError, match=expected_error):
        truenas_pyscram.verify_server_signature(
            client_first=client_first, server_first=server_first,
            client_final=client_final, server_final=server_final,
            server_key=invalid_param)


def test_verification_functions_with_channel_binding(auth_data):
    """Test verification functions with channel binding."""
    # Create client with channel binding
    client_first = truenas_pyscram.ClientFirstMessage(
        username="testuser", gs2_header="p=x-test-binding")
    server_first = truenas_pyscram.ServerFirstMessage(
        client_first=client_first, salt=auth_data.salt,
        iterations=auth_data.iterations)

    # Create channel binding data
    channel_binding = truenas_pyscram.CryptoDatum(b"fake_channel_binding_data")

    client_final = truenas_pyscram.ClientFinalMessage(
        client_first=client_first, server_first=server_first,
        client_key=auth_data.client_key, stored_key=auth_data.stored_key,
        channel_binding=channel_binding)
    server_final = truenas_pyscram.ServerFinalMessage(
        client_first=client_first, server_first=server_first,
        client_final=client_final, stored_key=auth_data.stored_key,
        server_key=auth_data.server_key)

    # Both verifications should succeed
    truenas_pyscram.verify_client_final_message(
        client_first=client_first, server_first=server_first,
        client_final=client_final, stored_key=auth_data.stored_key)
    truenas_pyscram.verify_server_signature(
        client_first=client_first, server_first=server_first,
        client_final=client_final, server_final=server_final,
        server_key=auth_data.server_key)


def test_full_scram_flow_with_verification(auth_data):
    """Test complete SCRAM flow with verification."""
    # Complete SCRAM flow
    client_first = truenas_pyscram.ClientFirstMessage(username="testuser")
    server_first = truenas_pyscram.ServerFirstMessage(
        client_first=client_first, salt=auth_data.salt,
        iterations=auth_data.iterations)
    client_final = truenas_pyscram.ClientFinalMessage(
        client_first=client_first, server_first=server_first,
        client_key=auth_data.client_key, stored_key=auth_data.stored_key)
    server_final = truenas_pyscram.ServerFinalMessage(
        client_first=client_first, server_first=server_first,
        client_final=client_final, stored_key=auth_data.stored_key,
        server_key=auth_data.server_key)

    # Server verifies client final message (server-side verification)
    truenas_pyscram.verify_client_final_message(
        client_first=client_first, server_first=server_first,
        client_final=client_final, stored_key=auth_data.stored_key)

    # Client verifies server signature (client-side verification)
    truenas_pyscram.verify_server_signature(
        client_first=client_first, server_first=server_first,
        client_final=client_final, server_final=server_final,
        server_key=auth_data.server_key)


@pytest.mark.parametrize("username,api_key_id", [
    ("user1", 0),
    ("user2", 12345),
    ("admin", 999),
])
def test_verification_with_parametrized_clients(auth_data, username,
                                               api_key_id):
    """Test verification functions with parametrized client configurations."""
    client = truenas_pyscram.ClientFirstMessage(username=username,
                                                api_key_id=api_key_id)
    server_first = truenas_pyscram.ServerFirstMessage(
        client_first=client, salt=auth_data.salt,
        iterations=auth_data.iterations)
    client_final = truenas_pyscram.ClientFinalMessage(
        client_first=client, server_first=server_first,
        client_key=auth_data.client_key, stored_key=auth_data.stored_key)
    server_final = truenas_pyscram.ServerFinalMessage(
        client_first=client, server_first=server_first,
        client_final=client_final, stored_key=auth_data.stored_key,
        server_key=auth_data.server_key)

    # Both verifications should succeed regardless of client configuration
    truenas_pyscram.verify_client_final_message(
        client_first=client, server_first=server_first,
        client_final=client_final, stored_key=auth_data.stored_key)
    truenas_pyscram.verify_server_signature(
        client_first=client, server_first=server_first,
        client_final=client_final, server_final=server_final,
        server_key=auth_data.server_key)


def test_verification_functions_return_none():
    """Test that verification functions return None on success."""
    auth_data = truenas_pyscram.generate_scram_auth_data()
    client_first = truenas_pyscram.ClientFirstMessage(username="testuser")
    server_first = truenas_pyscram.ServerFirstMessage(
        client_first=client_first, salt=auth_data.salt,
        iterations=auth_data.iterations)
    client_final = truenas_pyscram.ClientFinalMessage(
        client_first=client_first, server_first=server_first,
        client_key=auth_data.client_key, stored_key=auth_data.stored_key)
    server_final = truenas_pyscram.ServerFinalMessage(
        client_first=client_first, server_first=server_first,
        client_final=client_final, stored_key=auth_data.stored_key,
        server_key=auth_data.server_key)

    # Both functions should return None on success
    result1 = truenas_pyscram.verify_client_final_message(
        client_first=client_first, server_first=server_first,
        client_final=client_final, stored_key=auth_data.stored_key)
    result2 = truenas_pyscram.verify_server_signature(
        client_first=client_first, server_first=server_first,
        client_final=client_final, server_final=server_final,
        server_key=auth_data.server_key)

    assert result1 is None
    assert result2 is None


def test_scram_error_properties():
    """Test that ScramError has correct properties."""
    auth_data = truenas_pyscram.generate_scram_auth_data()
    client_first = truenas_pyscram.ClientFirstMessage(username="testuser")
    server_first = truenas_pyscram.ServerFirstMessage(
        client_first=client_first, salt=auth_data.salt,
        iterations=auth_data.iterations)
    client_final = truenas_pyscram.ClientFinalMessage(
        client_first=client_first, server_first=server_first,
        client_key=auth_data.client_key, stored_key=auth_data.stored_key)

    # Use wrong key to trigger SCRAM authentication failure
    wrong_auth = truenas_pyscram.generate_scram_auth_data()

    with pytest.raises(truenas_pyscram.ScramError) as exc_info:
        truenas_pyscram.verify_client_final_message(
            client_first=client_first, server_first=server_first,
            client_final=client_final, stored_key=wrong_auth.stored_key)

    # Check that the exception has the expected attributes
    exc = exc_info.value
    assert hasattr(exc, 'code')
    assert exc.code == truenas_pyscram.SCRAM_E_AUTH_FAILED
    assert "SCRAM_E_AUTH_FAILED" in str(exc)
    assert "client proof verification failed" in str(exc).lower()


def _self_signed_cert_der():
    """A minimal self-signed leaf certificate (DER) for tls-server-end-point."""
    pytest.importorskip("cryptography")
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import Encoding
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "scram-test")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2020, 1, 1))
        .not_valid_after(datetime.datetime(2035, 1, 1))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(Encoding.DER)


def _channel_bound_client(auth_data, binding):
    """Build a (client_first, server_first, client_final) bound to `binding`."""
    client_first = truenas_pyscram.ClientFirstMessage(
        username="testuser",
        channel_binding_type=truenas_pyscram.CB_TLS_SERVER_END_POINT)
    server_first = truenas_pyscram.ServerFirstMessage(
        client_first=client_first, salt=auth_data.salt,
        iterations=auth_data.iterations)
    client_final = truenas_pyscram.ClientFinalMessage(
        client_first=client_first, server_first=server_first,
        client_key=auth_data.client_key, stored_key=auth_data.stored_key,
        channel_binding=binding)
    return client_first, server_first, client_final


def test_verify_client_final_channel_binding_real_cert(auth_data):
    """End-to-end: a real tls-server-end-point binding verifies successfully."""
    binding = truenas_pyscram.compute_tls_server_end_point(_self_signed_cert_der())
    client_first, server_first, client_final = _channel_bound_client(
        auth_data, binding)

    # Matching binding + require_channel_binding -> no exception raised
    truenas_pyscram.verify_client_final_message(
        client_first=client_first, server_first=server_first,
        client_final=client_final, stored_key=auth_data.stored_key,
        channel_binding=binding, require_channel_binding=True)


def test_verify_client_final_channel_binding_mismatch(auth_data):
    """A different server channel binding must fail verification."""
    binding = truenas_pyscram.CryptoDatum(b"A" * 32)
    wrong = truenas_pyscram.CryptoDatum(b"B" * 32)
    client_first, server_first, client_final = _channel_bound_client(
        auth_data, binding)

    with pytest.raises(truenas_pyscram.ScramError, match="channel binding mismatch"):
        truenas_pyscram.verify_client_final_message(
            client_first=client_first, server_first=server_first,
            client_final=client_final, stored_key=auth_data.stored_key,
            channel_binding=wrong, require_channel_binding=True)


def test_verify_client_final_require_rejects_plain_client(auth_data):
    """require_channel_binding rejects a client that did not use binding."""
    client_first = truenas_pyscram.ClientFirstMessage(username="testuser")
    server_first = truenas_pyscram.ServerFirstMessage(
        client_first=client_first, salt=auth_data.salt,
        iterations=auth_data.iterations)
    client_final = truenas_pyscram.ClientFinalMessage(
        client_first=client_first, server_first=server_first,
        client_key=auth_data.client_key, stored_key=auth_data.stored_key)

    with pytest.raises(truenas_pyscram.ScramError, match="channel binding required"):
        truenas_pyscram.verify_client_final_message(
            client_first=client_first, server_first=server_first,
            client_final=client_final, stored_key=auth_data.stored_key,
            channel_binding=truenas_pyscram.CryptoDatum(b"A" * 32),
            require_channel_binding=True)


def test_verify_client_final_y_flag_downgrade_rejected(auth_data):
    """A 'y' gs2 flag against a CB-capable server is a downgrade and must fail."""
    client_first = truenas_pyscram.ClientFirstMessage(
        username="testuser", gs2_header="y")
    server_first = truenas_pyscram.ServerFirstMessage(
        client_first=client_first, salt=auth_data.salt,
        iterations=auth_data.iterations)
    client_final = truenas_pyscram.ClientFinalMessage(
        client_first=client_first, server_first=server_first,
        client_key=auth_data.client_key, stored_key=auth_data.stored_key)

    with pytest.raises(truenas_pyscram.ScramError, match="downgrade"):
        truenas_pyscram.verify_client_final_message(
            client_first=client_first, server_first=server_first,
            client_final=client_final, stored_key=auth_data.stored_key,
            channel_binding=truenas_pyscram.CryptoDatum(b"A" * 32))