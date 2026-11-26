# OAuth 2.0 support in APIShield v1

Supported flow (ONE):
- Client credentials, with a least-privilege test client.

NOT supported in v1:
- Authorization Code (with or without PKCE): needs a browser and a user.
- Implicit flow: deprecated.
- Resource Owner Password Credentials: deprecated, and it handles real passwords.
- Device code flow.
- Refresh tokens: a client credentials token is renewed by asking again.
- Token introspection, dynamic client registration, mutual TLS, DPoP.

Rules:
- The token endpoint must be inside the approved scan scope and use HTTPS.
- Test clients only, with the smallest scopes possible.
- Tokens and secrets live in memory only and are masked everywhere.
