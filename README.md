# OAuth2ACF
The OAuth2ACF is a web server for OAuth2 authentication using the Authorization Code Flow, It enables iOS, Android, and desktop applications to complete OAuth2 authentication.
# ICChat push authorization

When all `OAUTH2ACF_PUSH_*` settings from `.env.example` are present, the
service also exposes:

- `POST /v1/push/token`: validates each Google/Microsoft access token, stores
  the accompanying refresh token encrypted, rotates an opaque device session,
  and returns a ten-minute Ed25519 JWT for `icchat-fcm`.
- `DELETE /v1/push/session`: validates the opaque device session and deletes
  it together with every encrypted provider connection owned by that session.
- `GET /internal/v1/provider-connections`: lists the account mappings available
  to the push monitor. Requires the broker key.
- `POST /internal/v1/provider-token`: refreshes one provider access token for
  the push monitor. Requires the broker key.

Generate the signing key and broker secret with:

```bash
openssl genpkey -algorithm Ed25519 -out push-signing-private.pem
openssl pkey -in push-signing-private.pem -pubout -out account-public.pem
openssl rand -hex 32 > push-broker-key
```

The private key stays with OAuth2ACF. `account-public.pem` is mounted read-only
in `icchat-fcm`. Provider refresh tokens are encrypted with
`OAUTH2ACF_TOKEN_KEY`; changing that value without a coordinated migration makes
existing connections unreadable.

The mobile App calls the token endpoint only over HTTPS and stores the opaque
session in platform secure storage. When its final push registration is
removed, it calls the session endpoint so background watches stop being
renewed. OAuth client IDs, consent-screen publication, provider scopes and
redirect URIs still have to be configured in Google Cloud and Microsoft Entra;
those are deployment credentials rather than source code.
