"""Test SCRAM client first message functionality."""

import base64

import truenas_pyscram


def test_client_first_message_creation():
    """Test that ClientFirstMessage can be created with username."""
    msg = truenas_pyscram.ClientFirstMessage("testuser")
    assert msg.username == "testuser"
    assert msg.api_key_id == 0
    assert msg.gs2_header is None
    assert isinstance(msg.nonce, truenas_pyscram.CryptoDatum)


def test_client_first_message_with_api_key():
    """Test ClientFirstMessage creation with API key ID."""
    msg = truenas_pyscram.ClientFirstMessage("testuser", api_key_id=12345)
    assert msg.username == "testuser"
    assert msg.api_key_id == 12345
    assert msg.gs2_header is None


def test_client_first_message_with_gs2_header():
    """Test ClientFirstMessage creation with GS2 header."""
    gs2_header = "n"  # Standard GS2 header for no channel binding
    msg = truenas_pyscram.ClientFirstMessage("testuser", gs2_header=gs2_header)
    assert msg.username == "testuser"
    assert msg.api_key_id == 0
    assert msg.gs2_header == gs2_header


def test_client_first_message_with_all_parameters():
    """Test ClientFirstMessage creation with all parameters."""
    msg = truenas_pyscram.ClientFirstMessage(
        "testuser",
        api_key_id=999,
        gs2_header="n"
    )
    assert msg.username == "testuser"
    assert msg.api_key_id == 999
    assert msg.gs2_header == "n"


def test_client_first_message_nonce_properties():
    """Test that the client nonce has expected properties."""
    msg = truenas_pyscram.ClientFirstMessage("testuser")

    # Nonce should be a CryptoDatum
    assert isinstance(msg.nonce, truenas_pyscram.CryptoDatum)

    # Nonce should have reasonable length (typically 32 bytes)
    assert len(msg.nonce) == 32

    # Nonce should support buffer protocol
    nonce_bytes = bytes(msg.nonce)
    assert isinstance(nonce_bytes, bytes)
    assert len(nonce_bytes) == 32


def test_client_first_message_nonce_randomness():
    """Test that different messages have different nonces."""
    msg1 = truenas_pyscram.ClientFirstMessage("testuser")
    msg2 = truenas_pyscram.ClientFirstMessage("testuser")

    # Nonces should be different (extremely unlikely to be same with crypto)
    assert msg1.nonce != msg2.nonce


def test_client_first_message_serialization():
    """Test that ClientFirstMessage can be serialized to string."""
    msg = truenas_pyscram.ClientFirstMessage("testuser")

    # Should be able to convert to string
    serialized = str(msg)
    assert isinstance(serialized, str)

    # Should contain expected RFC 5802 format elements
    assert "n=testuser" in serialized
    assert "r=" in serialized  # Should contain nonce


def test_client_first_message_serialization_with_api_key():
    """Test serialization with API key ID includes colon delimiter."""
    msg = truenas_pyscram.ClientFirstMessage("testuser", api_key_id=123)
    serialized = str(msg)

    # Should contain username with colon delimiter for API key
    assert "n=testuser:123" in serialized


def test_client_first_message_repr():
    """Test ClientFirstMessage repr format."""
    msg = truenas_pyscram.ClientFirstMessage("testuser", api_key_id=456)
    repr_str = repr(msg)

    assert "ClientFirstMessage" in repr_str
    assert "testuser" in repr_str
    assert "456" in repr_str


def test_client_first_message_type():
    """Test that ClientFirstMessage returns expected type."""
    msg = truenas_pyscram.ClientFirstMessage("testuser")
    assert type(msg).__name__ == "ClientFirstMessage"


def test_client_first_message_with_empty_username():
    """Test ClientFirstMessage with empty username."""
    # Empty username should still work (validation is handled by C library)
    msg = truenas_pyscram.ClientFirstMessage("")
    assert msg.username == ""
    assert isinstance(msg.nonce, truenas_pyscram.CryptoDatum)


def test_client_first_message_multiple_creation():
    """Test creating multiple ClientFirstMessage instances."""
    messages = [
        truenas_pyscram.ClientFirstMessage(f"user{i}", api_key_id=i)
        for i in range(5)
    ]

    # All should be valid instances
    for i, msg in enumerate(messages):
        assert msg.username == f"user{i}"
        assert msg.api_key_id == i
        assert isinstance(msg.nonce, truenas_pyscram.CryptoDatum)
        assert len(msg.nonce) == 32

    # All nonces should be unique
    nonces = [msg.nonce for msg in messages]
    assert len(set(nonces)) == 5


def test_client_first_rfc5802_format_no_gs2():
    """Test str() output matches actual serialization behavior."""
    msg = truenas_pyscram.ClientFirstMessage("alice")
    serialized = str(msg)

    # Current behavior: default GS2 header "n,," is added
    # Format: n,,n=username,r=nonce
    assert serialized.startswith("n,,")

    # Split on GS2 separator
    gs2_part, message_part = serialized.split(",,", 1)
    assert gs2_part == "n"

    # Parse message attributes
    parts = message_part.split(',')
    assert len(parts) == 2
    assert parts[0] == "n=alice"
    assert parts[1].startswith("r=")

    # Validate nonce is base64
    nonce_b64 = parts[1][2:]
    decoded_nonce = base64.b64decode(nonce_b64)
    assert len(decoded_nonce) == 32


def test_client_first_rfc5802_format_with_api_key():
    """Test RFC 5802 format with API key ID."""
    msg = truenas_pyscram.ClientFirstMessage("bob", api_key_id=456)
    serialized = str(msg)

    # Default GS2 header is added
    assert serialized.startswith("n,,")
    gs2_part, message_part = serialized.split(",,", 1)
    assert gs2_part == "n"

    parts = message_part.split(',')
    assert len(parts) == 2

    # Username should include API key with colon delimiter
    assert parts[0] == "n=bob:456"
    assert parts[1].startswith("r=")

    # Validate nonce
    nonce_b64 = parts[1][2:]
    decoded_nonce = base64.b64decode(nonce_b64)
    assert len(decoded_nonce) == 32


def test_client_first_rfc5802_gs2_header():
    """Test proper RFC 5802 GS2 header behavior."""
    msg = truenas_pyscram.ClientFirstMessage("charlie", gs2_header="n")
    serialized = str(msg)

    # Should now properly format: gs2-header + separator + attributes
    # Format: n,,n=username,r=nonce
    assert serialized.startswith("n,,")

    # Split on GS2 separator
    gs2_part, message_part = serialized.split(",,", 1)
    assert gs2_part == "n"

    # Message part should follow standard format
    parts = message_part.split(',')
    assert len(parts) == 2
    assert parts[0] == "n=charlie"
    assert parts[1].startswith("r=")

    # Validate nonce
    nonce_b64 = parts[1][2:]
    decoded_nonce = base64.b64decode(nonce_b64)
    assert len(decoded_nonce) == 32


def test_client_first_api_key_with_gs2_header():
    """Test API key handling with explicit GS2 header."""
    msg = truenas_pyscram.ClientFirstMessage("dave", api_key_id=789,
                                             gs2_header="n")
    serialized = str(msg)

    # Should properly format with GS2 separator
    assert serialized.startswith("n,,")
    gs2_part, message_part = serialized.split(",,", 1)
    assert gs2_part == "n"

    parts = message_part.split(',')
    assert len(parts) == 2
    assert parts[0] == "n=dave:789"
    assert parts[1].startswith("r=")

    # Validate nonce
    nonce_b64 = parts[1][2:]
    decoded_nonce = base64.b64decode(nonce_b64)
    assert len(decoded_nonce) == 32


def test_client_first_message_attributes_parsing():
    """Test that we can extract username and nonce from serialized form."""
    msg = truenas_pyscram.ClientFirstMessage("eve", api_key_id=999)
    serialized = str(msg)

    # For messages without explicit GS2 header, we get proper separator
    assert ",," in serialized
    gs2_header, bare_message = serialized.split(",,", 1)
    assert gs2_header == "n"

    # Parse attributes from bare message
    attributes = {}
    for attr in bare_message.split(','):
        if '=' in attr:
            key, value = attr.split('=', 1)
            attributes[key] = value

    # Validate extracted attributes
    assert 'n' in attributes
    assert 'r' in attributes
    assert attributes['n'] == "eve:999"

    # Nonce should be valid base64
    nonce_decoded = base64.b64decode(attributes['r'])
    assert len(nonce_decoded) == 32

    # Verify nonce matches the original
    original_nonce_bytes = bytes(msg.nonce)
    assert nonce_decoded == original_nonce_bytes
