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

Self-hosted server monitoring supports password-based IMAP over TLS/STARTTLS
and JMAP over HTTPS. OAuth2ACF verifies mailbox access before storing encrypted
credentials. Plaintext connections and OIDC/XOAUTH2 remain on the App's local
listener and are not uploaded for remote monitoring.

## 自建 IMAP / JMAP 推送账号

`POST /v1/push/token` 的 `accounts` 支持 `provider: "selfhosted"`。
每项必须恰好包含一个 `imap` 或 `jmap` 证明，不发送本地 sh1 句柄、accessToken
或 refreshToken。IMAP 使用现有 TLS/STARTTLS 密码验证；JMAP 示例：

```json
{
  "accounts": [{
    "accountId": "selfHosted:user@example.com",
    "provider": "selfhosted",
    "jmap": {
      "email": "user@example.com",
      "sessionUrl": "https://mail.example.com/.well-known/jmap",
      "username": "user@example.com",
      "password": "app-specific-password"
    }
  }]
}
```

JMAP 验证同源 HTTPS Session 和 Email/get 权限，空 ids 不读取邮件内容。
实际连接解析并固定公网 IP，拒绝私网地址、跨 origin 跳转和环境代理。
密码经现有加密密钥加密保存，配置散列使用 HMAC 指纹；请保留当前加密密钥。
`InitDB` 自动创建带会话外键的 `jmap_connections`，无需清空旧数据库。

broker key 保护的内部接口新增：

- `GET /internal/v1/jmap-connections`：仅返回主体、账号、sessionUrl、username、revision。
- `POST /internal/v1/jmap-password`：请求 `{ "subject": "...", "accountId": "..." }`，返回密码。

上述内部接口仅开放给 icchat-fcm。账号移除、IMAP/JMAP 协议切换或会话撤销时，
旧协议的加密凭据会在事务内移除。当前不支持自建账号 OIDC/XOAUTH2 的后台凭据续期。
部署先升级账户服务，再升级推送服务，最后升级 App。
