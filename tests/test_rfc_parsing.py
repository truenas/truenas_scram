"""Tests for RFC string parsing functionality in SCRAM messages."""

import pytest
import truenas_pyscram as scram


def test_client_first_parse_basic():
    """Test parsing a basic client-first-message from RFC string."""
    msg1 = scram.ClientFirstMessage(username="testuser")
    rfc_str = str(msg1)

    msg2 = scram.ClientFirstMessage(rfc_string=rfc_str)

    assert str(msg1) == str(msg2)
    assert msg2.username == "testuser"
    assert msg2.api_key_id == 0


def test_client_first_parse_with_api_key():
    """Test parsing client-first-message with API key ID."""
    msg1 = scram.ClientFirstMessage(username="testuser", api_key_id=12345)
    rfc_str = str(msg1)
    api_user_str = 'testuser:12345'

    assert api_user_str in rfc_str

    msg2 = scram.ClientFirstMessage(rfc_string=rfc_str)

    assert str(msg1) == str(msg2)
    assert msg2.api_key_id == 12345
    assert msg2.username == "testuser"


def test_client_first_parse_with_gs2_header():
    """Test parsing client-first-message with GS2 header."""
    msg1 = scram.ClientFirstMessage(username="testuser", gs2_header="p=x-test-binding")
    rfc_str = str(msg1)

    msg2 = scram.ClientFirstMessage(rfc_string=rfc_str)

    assert str(msg1) == str(msg2)
    assert msg2.username == "testuser"
    assert msg2.gs2_header == "p=x-test-binding"


def test_client_first_no_params_error():
    """Test that ClientFirstMessage requires either username or rfc_string."""
    with pytest.raises(ValueError, match="Must specify either rfc_string or username"):
        scram.ClientFirstMessage()


def test_client_first_conflicting_params_error():
    """Test that username and rfc_string are mutually exclusive."""
    with pytest.raises(ValueError, match="Cannot specify both rfc_string and username"):
        scram.ClientFirstMessage(username="test", rfc_string="n,,n=test,r=xxx")


def test_client_first_rfc_string_gs2_header_exclusive():
    """rfc_string and gs2_header are mutually exclusive (gs2_header would be ignored)."""
    with pytest.raises(ValueError, match="Cannot specify both rfc_string and gs2_header"):
        scram.ClientFirstMessage(rfc_string="n,,n=test,r=xxx", gs2_header="p=tls-exporter")


def test_server_first_parse_basic():
    """Test parsing a basic server-first-message from RFC string."""
    client_first = scram.ClientFirstMessage(username="testuser")
    auth_data_for_salt = scram.generate_scram_auth_data()
    salt = auth_data_for_salt.salt

    msg1 = scram.ServerFirstMessage(
        client_first=client_first,
        salt=salt,
        iterations=100000
    )
    rfc_str = str(msg1)

    try:
        msg2 = scram.ServerFirstMessage(rfc_string=rfc_str)
    except Exception as exc:
        raise RuntimeError(f'Failed to decode ({rfc_str}): {exc}')

    assert str(msg1) == str(msg2)
    assert msg2.iterations == 100000


@pytest.mark.parametrize("iterations", [100000, 600000])
def test_server_first_parse_various_iterations(iterations):
    """Test parsing server-first-message with various iteration counts."""
    client_first = scram.ClientFirstMessage(username="testuser")
    auth_data_for_salt = scram.generate_scram_auth_data()
    salt = auth_data_for_salt.salt

    msg1 = scram.ServerFirstMessage(
        client_first=client_first,
        salt=salt,
        iterations=iterations
    )
    rfc_str = str(msg1)

    msg2 = scram.ServerFirstMessage(rfc_string=rfc_str)

    assert str(msg1) == str(msg2)
    assert msg2.iterations == iterations


def test_server_first_no_params_error():
    """Test that ServerFirstMessage requires either client_first or rfc_string."""
    with pytest.raises(ValueError, match="Must specify either rfc_string or client_first"):
        scram.ServerFirstMessage()


def test_server_first_conflicting_params_error():
    """Test that client_first and rfc_string are mutually exclusive."""
    client_first = scram.ClientFirstMessage(username="test")
    auth_data_for_salt = scram.generate_scram_auth_data()
    salt = auth_data_for_salt.salt

    with pytest.raises(ValueError, match="Cannot specify both rfc_string and client_first"):
        scram.ServerFirstMessage(
            client_first=client_first,
            salt=salt,
            iterations=200000,
            rfc_string="r=xxx,s=yyy,i=4096"
        )


@pytest.fixture
def client_server_first_messages():
    """Create client_first and server_first messages for testing."""
    client_first = scram.ClientFirstMessage(username="testuser")
    auth_data_for_salt = scram.generate_scram_auth_data()
    salt = auth_data_for_salt.salt
    server_first = scram.ServerFirstMessage(
        client_first=client_first,
        salt=salt,
        iterations=200000
    )
    auth_data = scram.generate_scram_auth_data(salt=salt, iterations=200000)
    return client_first, server_first, auth_data


def test_client_final_parse_basic(client_server_first_messages):
    """Test parsing a basic client-final-message from RFC string."""
    client_first, server_first, auth_data = client_server_first_messages

    msg1 = scram.ClientFinalMessage(
        client_first=client_first,
        server_first=server_first,
        client_key=auth_data.client_key,
        stored_key=auth_data.stored_key
    )
    rfc_str = str(msg1)

    msg2 = scram.ClientFinalMessage(rfc_string=rfc_str)

    assert str(msg1) == str(msg2)


def test_client_final_parse_with_channel_binding(client_server_first_messages):
    """Test parsing client-final-message with channel binding."""
    _, _, auth_data = client_server_first_messages

    # A channel-bound client must advertise a "p=" gs2 header (RFC 5802 6).
    client_first = scram.ClientFirstMessage(
        username="testuser",
        channel_binding_type=scram.CB_TLS_SERVER_END_POINT)
    server_first = scram.ServerFirstMessage(
        client_first=client_first, salt=auth_data.salt,
        iterations=auth_data.iterations)

    channel_binding = scram.CryptoDatum(b"test-channel-binding-data")

    msg1 = scram.ClientFinalMessage(
        client_first=client_first,
        server_first=server_first,
        client_key=auth_data.client_key,
        stored_key=auth_data.stored_key,
        channel_binding=channel_binding
    )
    rfc_str = str(msg1)

    msg2 = scram.ClientFinalMessage(rfc_string=rfc_str)

    assert str(msg1) == str(msg2)


def test_client_final_no_params_error():
    """Test that ClientFinalMessage requires parameters."""
    with pytest.raises(ValueError, match="Must specify either rfc_string or message parameters"):
        scram.ClientFinalMessage()


def test_client_final_conflicting_params_error(client_server_first_messages):
    """Test that message params and rfc_string are mutually exclusive."""
    client_first, server_first, auth_data = client_server_first_messages

    with pytest.raises(ValueError, match="Cannot specify both rfc_string and other parameters"):
        scram.ClientFinalMessage(
            client_first=client_first,
            server_first=server_first,
            client_key=auth_data.client_key,
            stored_key=auth_data.stored_key,
            rfc_string="c=biws,r=xxx,p=yyy"
        )


@pytest.fixture
def all_messages():
    """Create all messages needed for server final testing."""
    client_first = scram.ClientFirstMessage(username="testuser")
    auth_data_for_salt = scram.generate_scram_auth_data()
    salt = auth_data_for_salt.salt
    server_first = scram.ServerFirstMessage(
        client_first=client_first,
        salt=salt,
        iterations=200000
    )
    auth_data = scram.generate_scram_auth_data(salt=salt, iterations=200000)
    client_final = scram.ClientFinalMessage(
        client_first=client_first,
        server_first=server_first,
        client_key=auth_data.client_key,
        stored_key=auth_data.stored_key
    )
    return client_first, server_first, client_final, auth_data


def test_server_final_parse_basic(all_messages):
    """Test parsing a basic server-final-message from RFC string."""
    client_first, server_first, client_final, auth_data = all_messages

    msg1 = scram.ServerFinalMessage(
        client_first=client_first,
        server_first=server_first,
        client_final=client_final,
        stored_key=auth_data.stored_key,
        server_key=auth_data.server_key
    )
    rfc_str = str(msg1)

    msg2 = scram.ServerFinalMessage(rfc_string=rfc_str)

    assert str(msg1) == str(msg2)


def test_server_final_no_params_error():
    """Test that ServerFinalMessage requires parameters."""
    with pytest.raises(ValueError, match="Must specify either rfc_string or message parameters"):
        scram.ServerFinalMessage()


def test_server_final_conflicting_params_error(all_messages):
    """Test that message params and rfc_string are mutually exclusive."""
    client_first, server_first, client_final, auth_data = all_messages

    with pytest.raises(ValueError, match="Cannot specify both rfc_string and other parameters"):
        scram.ServerFinalMessage(
            client_first=client_first,
            server_first=server_first,
            client_final=client_final,
            stored_key=auth_data.stored_key,
            server_key=auth_data.server_key,
            rfc_string="v=xxx"
        )


def test_complete_auth_flow_roundtrip():
    """Test that a complete auth flow can be serialized and deserialized."""
    # Create initial client message
    client_first_1 = scram.ClientFirstMessage(username="alice", api_key_id=999)
    cf1_str = str(client_first_1)

    # Parse it back
    client_first_2 = scram.ClientFirstMessage(rfc_string=cf1_str)
    assert str(client_first_1) == str(client_first_2)

    # Create server response
    auth_data_for_salt = scram.generate_scram_auth_data()
    salt = auth_data_for_salt.salt
    server_first_1 = scram.ServerFirstMessage(
        client_first=client_first_2,
        salt=salt,
        iterations=200000
    )
    sf1_str = str(server_first_1)

    # Parse server response
    server_first_2 = scram.ServerFirstMessage(rfc_string=sf1_str)
    assert str(server_first_1) == str(server_first_2)

    # Create client final
    auth_data = scram.generate_scram_auth_data(salt=salt, iterations=200000)
    client_final_1 = scram.ClientFinalMessage(
        client_first=client_first_1,
        server_first=server_first_1,
        client_key=auth_data.client_key,
        stored_key=auth_data.stored_key
    )
    cf2_str = str(client_final_1)

    # Parse client final
    client_final_2 = scram.ClientFinalMessage(rfc_string=cf2_str)
    assert str(client_final_1) == str(client_final_2)

    # Create server final
    server_final_1 = scram.ServerFinalMessage(
        client_first=client_first_1,
        server_first=server_first_1,
        client_final=client_final_1,
        stored_key=auth_data.stored_key,
        server_key=auth_data.server_key
    )
    sf2_str = str(server_final_1)

    # Parse server final
    server_final_2 = scram.ServerFinalMessage(rfc_string=sf2_str)
    assert str(server_final_1) == str(server_final_2)


@pytest.mark.parametrize("username", [
    "simple",
    "user.with.dots",
    "user-with-dashes",
    "user_with_underscores",
    "user123",
    "123user",
])
def test_various_usernames_roundtrip(username):
    """Test that various username formats are preserved correctly."""
    msg1 = scram.ClientFirstMessage(username=username)
    rfc_str = str(msg1)

    msg2 = scram.ClientFirstMessage(rfc_string=rfc_str)

    assert str(msg1) == str(msg2)
    assert msg2.username == username


@pytest.mark.parametrize("username,api_key_id", [
    ("user1", 0),
    ("user2", 1),
    ("user3", 100),
    ("user4", 65535),
    ("user5", 2147483647),
])
def test_username_api_key_combinations(username, api_key_id):
    """Test various combinations of username and API key ID."""
    msg1 = scram.ClientFirstMessage(username=username, api_key_id=api_key_id)
    rfc_str = str(msg1)

    msg2 = scram.ClientFirstMessage(rfc_string=rfc_str)

    assert str(msg1) == str(msg2)
    assert msg2.username == username
    assert msg2.api_key_id == api_key_id


def test_parse_rejects_equals_in_username():
    """RFC 5802 Section 5.1: a server MUST fail on a username containing a '='
    that is not a valid =2C/=3D escape. This library rejects '=' in the parsed
    username outright (a raw ',' cannot appear: it terminates the attribute)."""
    bad_rfc = "n,,n=user=name,r=" + "A" * 43
    with pytest.raises(scram.ScramError, match="username must not contain"):
        scram.ClientFirstMessage(rfc_string=bad_rfc)


def _truncated(rfc_string, keep):
    """Drop all but the first `keep` comma-separated attributes of a message."""
    return ",".join(rfc_string.split(",")[:keep])


def _incomplete_messages():
    """Well-formed-but-incomplete messages: every attribute present parses, but
    the required set is not satisfied."""
    client_first = scram.ClientFirstMessage(username="testuser")
    auth_data = scram.generate_scram_auth_data()
    server_first = scram.ServerFirstMessage(
        client_first=client_first,
        salt=auth_data.salt,
        iterations=auth_data.iterations
    )
    client_final = scram.ClientFinalMessage(
        client_first=client_first, server_first=server_first,
        client_key=auth_data.client_key, stored_key=auth_data.stored_key
    )

    # client-first carries a "n,,"-prefixed gs2 header, so its attributes start
    # at index 1 of the comma split.
    return [
        (scram.ClientFirstMessage, _truncated(str(client_first), 3), "no nonce"),
        (scram.ServerFirstMessage, _truncated(str(server_first), 1), "nonce only"),
        (scram.ServerFirstMessage, _truncated(str(server_first), 2), "no iterations"),
        (scram.ClientFinalMessage, _truncated(str(client_final), 2), "no proof"),
    ]


@pytest.mark.parametrize(
    "msg_type,rfc_string,description",
    _incomplete_messages(),
    ids=lambda v: v if isinstance(v, str) and " " in v else None
)
def test_parse_rejects_missing_required_attributes(msg_type, rfc_string, description):
    """A message whose attributes all parse but whose required set is incomplete
    must be rejected.

    Regression test: the deserializers used to reach the completeness check with
    `ret` still holding the SCRAM_E_SUCCESS left by the last parsed attribute and
    jump to cleanup without reassigning it, so they returned SCRAM_E_SUCCESS while
    leaving *msg_out unwritten. A C caller following the documented
    `if (ret == SCRAM_E_SUCCESS)` contract then dereferenced an uninitialised
    pointer. Assert on the specific error so the accidental downstream failure
    the Python layer used to produce ("invalid input parameters", raised only
    because the NULL message reached the serializer) cannot pass for a fix.
    """
    with pytest.raises(scram.ScramError) as exc_info:
        msg_type(rfc_string=rfc_string)

    exc = exc_info.value
    assert "missing required attributes" in str(exc)
    assert exc.code == scram.SCRAM_E_PARSE_ERROR
