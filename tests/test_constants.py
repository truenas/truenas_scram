"""Test SCRAM constants are properly exposed."""

import pytest
import truenas_pyscram


@pytest.mark.parametrize("const_name", [
    "SCRAM_E_SUCCESS",
    "SCRAM_E_INVALID_REQUEST",
    "SCRAM_E_MEMORY_ERROR",
    "SCRAM_E_CRYPTO_ERROR",
    "SCRAM_E_BASE64_ERROR",
    "SCRAM_E_PARSE_ERROR",
    "SCRAM_E_FORMAT_ERROR",
    "SCRAM_E_AUTH_FAILED",
])
def test_error_codes_exist(const_name):
    """Test that SCRAM error codes are available."""
    assert hasattr(truenas_pyscram, const_name)


@pytest.mark.parametrize("const_name,expected_value", [
    ("SCRAM_E_SUCCESS", 0),
    ("SCRAM_E_INVALID_REQUEST", -1),
    ("SCRAM_E_MEMORY_ERROR", -2),
    ("SCRAM_E_CRYPTO_ERROR", -3),
    ("SCRAM_E_BASE64_ERROR", -4),
    ("SCRAM_E_PARSE_ERROR", -5),
    ("SCRAM_E_FORMAT_ERROR", -6),
    ("SCRAM_E_AUTH_FAILED", -7),
])
def test_error_code_values(const_name, expected_value):
    """Test that error codes have expected values."""
    assert getattr(truenas_pyscram, const_name) == expected_value


@pytest.mark.parametrize("const_name", [
    "SCRAM_DEFAULT_ITERS",
    "SCRAM_MIN_ITERS",
    "SCRAM_MAX_ITERS",
    "SCRAM_MAX_USERNAME_LEN",
])
def test_limits_and_defaults_exist(const_name):
    """Test that SCRAM limits and defaults are available."""
    assert hasattr(truenas_pyscram, const_name)


@pytest.mark.parametrize("const_name,expected_value", [
    ("SCRAM_DEFAULT_ITERS", 500000),
    ("SCRAM_MIN_ITERS", 50000),
    ("SCRAM_MAX_ITERS", 5000000),
    ("SCRAM_MAX_USERNAME_LEN", 256),
])
def test_limits_and_defaults_values(const_name, expected_value):
    """Test that limits and defaults have expected values."""
    assert getattr(truenas_pyscram, const_name) == expected_value


@pytest.mark.parametrize("const_name", [
    "SCRAM_E_SUCCESS",
    "SCRAM_E_INVALID_REQUEST",
    "SCRAM_E_MEMORY_ERROR",
    "SCRAM_E_CRYPTO_ERROR",
    "SCRAM_E_BASE64_ERROR",
    "SCRAM_E_PARSE_ERROR",
    "SCRAM_E_FORMAT_ERROR",
    "SCRAM_E_AUTH_FAILED",
    "SCRAM_DEFAULT_ITERS",
    "SCRAM_MIN_ITERS",
    "SCRAM_MAX_ITERS",
    "SCRAM_MAX_USERNAME_LEN",
])
def test_constants_are_integers(const_name):
    """Test that all constants are integers."""
    value = getattr(truenas_pyscram, const_name)
    assert isinstance(value, int), f"{const_name} should be an integer"


def test_iteration_limits_make_sense():
    """Test that iteration limits are logically ordered."""
    assert truenas_pyscram.SCRAM_MIN_ITERS < truenas_pyscram.SCRAM_DEFAULT_ITERS
    assert truenas_pyscram.SCRAM_DEFAULT_ITERS < truenas_pyscram.SCRAM_MAX_ITERS
