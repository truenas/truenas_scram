"""Test nonce generation functionality."""

import truenas_pyscram


def test_generate_nonce_returns_crypto_datum():
    """Test that generate_nonce returns a CryptoDatum object."""
    nonce = truenas_pyscram.generate_nonce()
    assert isinstance(nonce, truenas_pyscram.CryptoDatum)


def test_generate_nonce_supports_buffer_protocol():
    """Test that CryptoDatum supports the buffer protocol."""
    nonce = truenas_pyscram.generate_nonce()
    # Test that we can convert to bytes via buffer protocol
    nonce_bytes = bytes(nonce)
    assert isinstance(nonce_bytes, bytes)
    assert len(nonce_bytes) == len(nonce)


def test_generate_nonce_length():
    """Test that generated nonce has correct length."""
    nonce = truenas_pyscram.generate_nonce()
    assert len(nonce) == 32


def test_generate_nonce_randomness():
    """Test that generated nonces are different."""
    nonce1 = truenas_pyscram.generate_nonce()
    nonce2 = truenas_pyscram.generate_nonce()
    assert nonce1 != nonce2


def test_generate_nonce_multiple_calls():
    """Test that multiple calls to generate_nonce work correctly."""
    nonces = [truenas_pyscram.generate_nonce() for _ in range(10)]

    # All should be the same length
    assert all(len(nonce) == 32 for nonce in nonces)

    # All should be CryptoDatum instances
    assert all(isinstance(nonce, truenas_pyscram.CryptoDatum) for nonce in nonces)

    # All should be unique (extremely unlikely to be the same with crypto randomness)
    assert len(set(nonces)) == 10


def test_crypto_datum_behaves_like_bytes():
    """Test that CryptoDatum objects behave like bytes."""
    nonce = truenas_pyscram.generate_nonce()

    # Should support indexing
    first_byte = nonce[0]
    assert isinstance(first_byte, int)
    assert 0 <= first_byte <= 255

    # Should support slicing
    first_half = nonce[:16]
    assert len(first_half) == 16
    assert isinstance(first_half, bytes)


def test_crypto_datum_clear():
    """Test that CryptoDatum clear method works correctly."""
    nonce = truenas_pyscram.generate_nonce()

    # Verify initial state
    assert len(nonce) == 32
    assert nonce[0] is not None

    # Clear the data
    result = nonce.clear()
    assert result is None  # Method should return None

    # Verify cleared state
    assert len(nonce) == 0

    # Indexing should raise IndexError
    import pytest
    with pytest.raises(IndexError):
        nonce[0]

    # Should be able to call clear multiple times safely
    nonce.clear()  # Should not crash
    assert len(nonce) == 0

    # Should still be hashable and comparable after clear
    empty_datum = truenas_pyscram.CryptoDatum(b"")
    assert len(empty_datum) == 0
    # Both should be empty and equal
    assert len(nonce) == len(empty_datum)
