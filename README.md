# TrueNAS SCRAM Authentication Library

A Python C extension implementing SCRAM (Salted Challenge Response Authentication Mechanism) authentication as specified in RFC 5802. This library provides both C and Python APIs for secure password-based authentication.

## Features

- Complete RFC 5802 SCRAM-SHA-512 implementation
- Python C extension for high performance
- Support for channel binding (tls-unique, tls-exporter)
- Comprehensive message validation and verification
- Server-side and client-side authentication functions
- Cryptographically secure nonce generation
- Configurable iteration counts (50,000 - 5,000,000)

## Installation

```bash
pip install -e .
```

## SCRAM Authentication Flow

The SCRAM authentication process involves a four-message exchange between client and server:

```
Client                                Server
  |                                     |
  | 1. ClientFirstMessage               |
  |------------------------------------>|
  |    n=username,r=client_nonce        |
  |                                     |
  |              2. ServerFirstMessage  |
  |<------------------------------------|
  |    r=combined_nonce,s=salt,i=iters  |
  |                                     |
  | 3. ClientFinalMessage               |
  |------------------------------------>|
  |    c=channel_binding,r=nonce,p=proof|
  |                                     |
  |               4. ServerFinalMessage |
  |<------------------------------------|
  |    v=server_signature               |
```

### Implementation Methods

#### 1. Client First Message
```python
client_first = truenas_pyscram.ClientFirstMessage("username")
# Generates: n,,n=username,r=<client_nonce>
```

#### 2. Server First Message
```python
auth_data = truenas_pyscram.generate_scram_auth_data()
server_first = truenas_pyscram.ServerFirstMessage(
    client_first, auth_data.salt, auth_data.iterations)
# Generates: r=<combined_nonce>,s=<salt_b64>,i=<iterations>
```

#### 3. Client Final Message
```python
client_final = truenas_pyscram.ClientFinalMessage(
    client_first, server_first, auth_data.client_key, auth_data.stored_key)
# Generates: c=<channel_binding_b64>,r=<nonce>,p=<client_proof_b64>
```

#### 4. Server Final Message
```python
server_final = truenas_pyscram.ServerFinalMessage(
    client_first, server_first, client_final,
    auth_data.stored_key, auth_data.server_key)
# Generates: v=<server_signature_b64>
```

### Verification Functions

#### Server-Side Verification
```python
# Server verifies client authentication
truenas_pyscram.verify_client_final_message(
    client_first, server_first, client_final, stored_key)
```

#### Client-Side Verification (Optional but Recommended)
```python
# Client verifies server authenticity
truenas_pyscram.verify_server_signature(
    client_first, server_first, client_final, server_final, server_key)
```

## Complete Example

```python
import truenas_pyscram

# Generate authentication data (normally stored securely)
auth_data = truenas_pyscram.generate_scram_auth_data()

# 1. Client creates first message
client_first = truenas_pyscram.ClientFirstMessage("alice")

# 2. Server creates first response
server_first = truenas_pyscram.ServerFirstMessage(
    client_first, auth_data.salt, auth_data.iterations)

# 3. Client creates final message (with password-derived keys)
client_final = truenas_pyscram.ClientFinalMessage(
    client_first, server_first, auth_data.client_key, auth_data.stored_key)

# 4. Server verifies client and creates final response
truenas_pyscram.verify_client_final_message(
    client_first, server_first, client_final, auth_data.stored_key)

server_final = truenas_pyscram.ServerFinalMessage(
    client_first, server_first, client_final,
    auth_data.stored_key, auth_data.server_key)

# 5. Client verifies server (optional but recommended)
truenas_pyscram.verify_server_signature(
    client_first, server_first, client_final, server_final,
    auth_data.server_key)

print("Authentication successful!")
```

## Channel Binding

For enhanced security over TLS connections, SCRAM supports channel binding:

```python
# Client with channel binding
client_first = truenas_pyscram.ClientFirstMessage(
    "alice", gs2_header="p=tls-unique")

# Channel binding data from TLS connection
channel_binding = truenas_pyscram.CryptoDatum(tls_channel_binding_data)

client_final = truenas_pyscram.ClientFinalMessage(
    client_first, server_first, auth_data.client_key,
    auth_data.stored_key, channel_binding)
```

## API Reference

### Core Classes

#### `ClientFirstMessage(username, api_key_id=0, gs2_header="")`
Creates the initial client message with username and nonce.

**Properties:**
- `nonce`: Client-generated random nonce (CryptoDatum)

#### `ServerFirstMessage(client_first, salt, iterations)`
Creates server response with combined nonce, salt, and iteration count.

**Properties:**
- `salt`: PBKDF2 salt (CryptoDatum)
- `nonce`: Combined client+server nonce (CryptoDatum)
- `iterations`: PBKDF2 iteration count (int)

#### `ClientFinalMessage(client_first, server_first, client_key, stored_key, channel_binding=None)`
Creates client proof message.

**Properties:**
- `nonce`: Combined nonce (CryptoDatum)
- `client_proof`: Authentication proof (CryptoDatum)
- `gs2_header`: GS2 header string
- `channel_binding`: Channel binding data (CryptoDatum or None)

#### `ServerFinalMessage(client_first, server_first, client_final, stored_key, server_key)`
Creates server verification signature.

**Properties:**
- `signature`: Server signature for client verification (CryptoDatum)

### Utility Functions

#### `generate_nonce() -> CryptoDatum`
Generates cryptographically secure 32-byte nonce.

#### `generate_scram_auth_data(salted_password=None, salt=None, iterations=0) -> ScramAuthData`
Generates complete SCRAM authentication data including all derived keys.

#### `verify_client_final_message(client_first, server_first, client_final, stored_key)`
Server-side verification of client authentication proof.

#### `verify_server_signature(client_first, server_first, client_final, server_final, server_key)`
Client-side verification of server authenticity (optional but recommended).

### Constants

- `SCRAM_DEFAULT_ITERS`: 500,000 (default iteration count)
- `SCRAM_MIN_ITERS`: 50,000 (minimum allowed iterations)
- `SCRAM_MAX_ITERS`: 5,000,000 (maximum allowed iterations)
- `SCRAM_MAX_USERNAME_LEN`: 256 (maximum username length)

## Security Considerations

1. **Iteration Count**: Use at least 500,000 iterations for new deployments
2. **Salt Storage**: Generate unique salts for each user and store securely
3. **Key Storage**: Store only the `stored_key` and `server_key`, never plaintext passwords
4. **Channel Binding**: Use with TLS for enhanced security
5. **Nonce Uniqueness**: Ensure client nonces are never reused
6. **Server Verification**: Always verify server signatures to prevent impersonation

## Testing

Run the test suite:

```bash
pytest tests/ -v
```

The library includes comprehensive tests covering:
- All message types and properties
- Error handling and validation
- Channel binding scenarios
- Complete authentication flows
- Verification functions
- Edge cases and security scenarios

## License

This project is licensed under the LGPL-3.0-or-later license.

## References

### Core SCRAM RFCs
- [RFC 5802: Salted Challenge Response Authentication Mechanism (SCRAM) SASL and GSS-API Mechanisms](https://tools.ietf.org/html/rfc5802) (2010)
- [RFC 7677: SCRAM-SHA-256 and SCRAM-SHA-256-PLUS Simple Authentication and Security Layer (SASL) Mechanisms](https://tools.ietf.org/html/rfc7677) (2015)
- [RFC 7804: Salted Challenge Response HTTP Authentication Mechanism](https://tools.ietf.org/html/rfc7804) (2016)

### Channel Binding RFCs
- [RFC 5929: Channel Bindings for TLS](https://tools.ietf.org/html/rfc5929) (2010)
- [RFC 9266: Channel Bindings for TLS 1.3](https://tools.ietf.org/html/rfc9266) (2022)

### Supporting RFCs
- [RFC 4648: The Base16, Base32, and Base64 Data Encodings](https://tools.ietf.org/html/rfc4648) (2006)
- [RFC 5056: On the Use of Channel Bindings to Secure Channels](https://tools.ietf.org/html/rfc5056) (2007)
- [RFC 5801: Using Generic Security Service Application Program Interface (GSS-API) Mechanisms in Simple Authentication and Security Layer (SASL)](https://tools.ietf.org/html/rfc5801) (2010)

### Recent Developments (2020-2024)
- **SCRAM-bis Document**: Updated implementation guidance for modern security practices
- **SCRAM-SHA-512**: Enhanced hash function support (Internet-Draft)
- **SCRAM-SHA3-512**: Post-quantum resistant hash function support (Internet-Draft)
- **Two-Factor Authentication Extensions**: SCRAM extensions for 2FA support (Internet-Draft)
- **Quick Reauthentication Extensions**: Optimized reauthentication mechanisms (Internet-Draft)