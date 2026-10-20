# OAuth2ACF
The OAuth2ACF is a web server for OAuth2 authentication using the Authorization Code Flow, It enables iOS, Android, and desktop applications to complete OAuth2 authentication.

## Docker Compose 部署

Debian 安装、OAuth provider 配置、密钥生成、反向代理、ICChat/icchat-fcm
对接、备份恢复和故障排查见
[Docker Compose 安装与配置手册](docs/DOCKER_COMPOSE_DEPLOYMENT.md)。

```bash
cp .env.example .env
mkdir -p secrets
cp oauth-clients.example.json secrets/oauth-clients.json
openssl rand -hex 32 > secrets/legacy-jwt-key
openssl rand -base64 48 > secrets/token-encryption-key
openssl genpkey -algorithm Ed25519 -out secrets/push-signing-private.pem
openssl pkey -in secrets/push-signing-private.pem -pubout -out account-public.pem
openssl rand -hex 32 > secrets/push-broker-key
chmod 600 secrets/*
# 填写 .env 和 secrets/oauth-clients.json 后：
docker compose up --build -d
```

Compose 将 SQLite 持久化到命名卷 `oauth2acf-data`，只把 HTTP 发布到宿主机
`127.0.0.1:9090`。生产环境必须放在 HTTPS 反向代理后面。

# ICChat push authorization

When all `OAUTH2ACF_PUSH_*` settings from `.env.example` are present, the
service also exposes:

- `POST /v1/push/token`: validates each Google/Microsoft access token or a
  self-hosted TLS IMAP login, stores the accompanying secret encrypted, rotates
  an opaque device session, and returns a ten-minute Ed25519 JWT for
  `icchat-fcm`.
- `DELETE /v1/push/session`: validates the opaque device session and deletes
  it together with every encrypted provider connection owned by that session.
- `GET /internal/v1/provider-connections`: lists the account mappings available
  to the push monitor. Requires the broker key.
- `POST /internal/v1/provider-token`: refreshes one provider access token for
  the push monitor. Requires the broker key.
- `GET /internal/v1/imap-connections`: lists dynamic IMAP monitor settings but
  never returns passwords. Requires the broker key.
- `POST /internal/v1/imap-password`: returns one decrypted IMAP password to
  `icchat-fcm` over the private HTTPS broker channel. Requires the broker key.

Generate the signing key and broker secret with:

```bash
openssl genpkey -algorithm Ed25519 -out push-signing-private.pem
openssl pkey -in push-signing-private.pem -pubout -out account-public.pem
openssl rand -hex 32 > push-broker-key
```

The private key stays with OAuth2ACF. `account-public.pem` is mounted read-only
in `icchat-fcm`. Provider refresh tokens and self-hosted IMAP passwords are
encrypted with the key supplied by `OAUTH2ACF_TOKEN_KEY_FILE` (or the compatible
direct-value `OAUTH2ACF_TOKEN_KEY` setting); changing that key without a
coordinated migration makes existing connections unreadable. The broker
endpoints must be reachable only by `icchat-fcm`; access logs must not record
request bodies.

The mobile App calls the token endpoint only over HTTPS and stores the opaque
session in platform secure storage. When its final push registration is
removed, it calls the session endpoint so background watches stop being
renewed. OAuth client IDs, consent-screen publication, provider scopes and
redirect URIs still have to be configured in Google Cloud and Microsoft Entra;
those are deployment credentials rather than source code.

Self-hosted server monitoring is accepted only for password-based IMAP over
implicit TLS or STARTTLS. OAuth2ACF verifies the login and read-only access to
the selected mailbox before storing it. Plaintext IMAP and JMAP accounts remain
on the App's local listener and are not uploaded for remote monitoring.
