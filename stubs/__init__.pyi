# SPDX-License-Identifier: LGPL-3.0-or-later
from typing import Union, final, overload

# Error codes
SCRAM_E_SUCCESS: int
SCRAM_E_INVALID_REQUEST: int
SCRAM_E_MEMORY_ERROR: int
SCRAM_E_CRYPTO_ERROR: int
SCRAM_E_BASE64_ERROR: int
SCRAM_E_PARSE_ERROR: int
SCRAM_E_FORMAT_ERROR: int
SCRAM_E_AUTH_FAILED: int

# Limits and defaults
SCRAM_DEFAULT_ITERS: int
SCRAM_MIN_ITERS: int
SCRAM_MAX_ITERS: int
SCRAM_MAX_USERNAME_LEN: int

# Channel-binding type names (RFC 5929)
CB_TLS_SERVER_END_POINT: str

# Error code to name mapping
errorcode: dict[int, str]

class ScramError(RuntimeError):
    code: int

@final
class CryptoDatum:
    def __init__(self, data: bytes, /) -> None: ...
    def clear(self) -> None: ...
    def __len__(self) -> int: ...
    @overload
    def __getitem__(self, index: int) -> int: ...
    @overload
    def __getitem__(self, index: slice) -> bytes: ...
    def __eq__(self, other: object) -> bool: ...
    def __ne__(self, other: object) -> bool: ...
    def __hash__(self) -> int: ...
    def __buffer__(self, flags: int, /) -> memoryview: ...

@final
class ScramAuthData:
    """Returned by generate_scram_auth_data(); cannot be instantiated directly."""
    @property
    def salt(self) -> CryptoDatum: ...
    @property
    def iterations(self) -> int: ...
    @property
    def salted_password(self) -> CryptoDatum: ...
    @property
    def client_key(self) -> CryptoDatum: ...
    @property
    def stored_key(self) -> CryptoDatum: ...
    @property
    def server_key(self) -> CryptoDatum: ...

@final
class ClientFirstMessage:
    def __init__(
        self,
        *,
        username: str | None = ...,
        api_key_id: int = ...,
        gs2_header: str | None = ...,
        rfc_string: str | None = ...,
        channel_binding_type: str | None = ...,
    ) -> None: ...
    @property
    def username(self) -> str: ...
    @property
    def api_key_id(self) -> int: ...
    @property
    def nonce(self) -> CryptoDatum: ...
    @property
    def gs2_header(self) -> str | None: ...
    def __str__(self) -> str: ...

@final
class ServerFirstMessage:
    def __init__(
        self,
        *,
        client_first: ClientFirstMessage | None = ...,
        salt: CryptoDatum | None = ...,
        iterations: int = ...,
        rfc_string: str | None = ...,
    ) -> None: ...
    @property
    def salt(self) -> CryptoDatum: ...
    @property
    def iterations(self) -> int: ...
    @property
    def nonce(self) -> CryptoDatum: ...
    def __str__(self) -> str: ...

@final
class ClientFinalMessage:
    def __init__(
        self,
        *,
        client_first: ClientFirstMessage | None = ...,
        server_first: ServerFirstMessage | None = ...,
        client_key: CryptoDatum | None = ...,
        stored_key: CryptoDatum | None = ...,
        channel_binding: CryptoDatum | None = ...,
        rfc_string: str | None = ...,
    ) -> None: ...
    @property
    def nonce(self) -> CryptoDatum: ...
    @property
    def client_proof(self) -> CryptoDatum: ...
    @property
    def gs2_header(self) -> str | None: ...
    @property
    def channel_binding(self) -> CryptoDatum | None: ...
    def __str__(self) -> str: ...

@final
class ServerFinalMessage:
    def __init__(
        self,
        *,
        client_first: ClientFirstMessage | None = ...,
        server_first: ServerFirstMessage | None = ...,
        client_final: ClientFinalMessage | None = ...,
        stored_key: CryptoDatum | None = ...,
        server_key: CryptoDatum | None = ...,
        rfc_string: str | None = ...,
    ) -> None: ...
    @property
    def signature(self) -> CryptoDatum: ...
    def __str__(self) -> str: ...

def generate_nonce() -> CryptoDatum: ...
def generate_scram_auth_data(
    *,
    salted_password: CryptoDatum | None = ...,
    salt: CryptoDatum | None = ...,
    iterations: int = ...,
) -> ScramAuthData: ...
def verify_client_final_message(
    client_first: ClientFirstMessage,
    server_first: ServerFirstMessage,
    client_final: ClientFinalMessage,
    stored_key: CryptoDatum,
    channel_binding: CryptoDatum | None = ...,
    require_channel_binding: bool = ...,
) -> None: ...
def verify_server_signature(
    client_first: ClientFirstMessage,
    server_first: ServerFirstMessage,
    client_final: ClientFinalMessage,
    server_final: ServerFinalMessage,
    server_key: CryptoDatum,
) -> None: ...
def compute_tls_server_end_point(cert_der: bytes) -> CryptoDatum: ...
